import logging
import threading
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy import inspect, select, text
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException

from .auth.browser import router as browser_router
from .auth.sessions import BrowserSessions, SessionUnavailable
from .config import Settings
from .db import factory, make_engine
from .models import (
    Actor,
    AgentSettings,
    ArtifactBuild,
    AtomicTest,
    CustomTestSubmission,
    ExecutionBinding,
    FilePlan,
    Run,
)
from .routes.agent_packages import router as packages_router
from .routes.agent_settings import router as agent_settings_router
from .routes.api import router
from .routes.artifacts import router as artifacts_router
from .routes.catalog import router as catalog_router
from .routes.catalog_deployments import router as catalog_deployments_router
from .routes.custom_tests import router as custom_tests_router
from .routes.execution_access import router as execution_access_router
from .routes.profile_sync import router as profile_sync_router
from .routes.run_batches import router as run_batches_router
from .routes.users import router as users_router

logger = logging.getLogger("atomic.api")


def require_execution_database(app):
    """Refuse historical fixture stores, including immutable fabricated run evidence."""
    required = {
        model.__tablename__
        for model in [
            Actor,
            AgentSettings,
            AtomicTest,
            Run,
            FilePlan,
            ArtifactBuild,
            ExecutionBinding,
            CustomTestSubmission,
        ]
    }
    if not required <= set(inspect(app.state.engine).get_table_names()):
        raise RuntimeError("Apply database migrations before starting the control plane")
    with app.state.sessions() as db:
        if (
            db.scalar(select(Actor.id).where(Actor.simulated.is_(True)).limit(1))
            or db.scalar(select(AtomicTest.guid).where(AtomicTest.simulated.is_(True)).limit(1))
            or db.scalar(select(Run.id).where(Run.snapshot["simulated"].as_boolean().is_(True)).limit(1))
        ):
            raise RuntimeError("Historical fixture databases cannot be opened as an execution deployment")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()

    @asynccontextmanager
    async def lifespan(app):
        await run_in_threadpool(require_execution_database, app)
        from .jobs.preparation import worker

        stop = threading.Event()

        def tick():
            app.state.preparation_worker_tick = time.time()

        tick()
        task = threading.Thread(target=worker, args=(app.state.sessions, settings, stop, tick), daemon=True)
        app.state.preparation_worker = task
        if settings.artifact_worker_enabled:
            task.start()
        try:
            yield
        finally:
            stop.set()
            if task.ident:
                task.join(timeout=6)

    app = FastAPI(title="Atomic Control", version="0.1.0", lifespan=lifespan)
    app.state.settings = settings
    app.state.oidc_pending = {}
    app.state.execution_access_lock = threading.RLock()
    app.state.execution_access_previews = {}
    app.state.engine = make_engine(settings.database_url)
    app.state.sessions = factory(app.state.engine)
    app.state.browser_sessions = BrowserSessions(app.state.sessions, settings)

    @app.exception_handler(HTTPException)
    def http_error(request, exc):
        # SQLite audit writes can wait for another request's transaction. Run in
        # the worker pool so its dependency cleanup can release that transaction.
        if exc.status_code in {401, 403, 409}:
            from .services.common import audit

            with app.state.sessions() as db, db.begin():
                audit(
                    db,
                    getattr(request.state, "identity", "anonymous"),
                    "authorization.denied",
                    request.url.path,
                    status=exc.status_code,
                )
        detail = (
            exc.detail if isinstance(exc.detail, dict) else {"code": "http_error", "message": str(exc.detail)}
        )
        return JSONResponse({"error": detail}, status_code=exc.status_code)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        return JSONResponse(
            {
                "error": {
                    "code": "validation_error",
                    "message": "Invalid request",
                    "fields": [list(e["loc"]) for e in exc.errors()],
                }
            },
            status_code=422,
        )

    @app.middleware("http")
    async def security(request: Request, call_next):
        start = time.monotonic()
        if request.method in {"POST", "PUT", "PATCH", "DELETE"} and request.headers.get("origin"):
            from urllib.parse import urlparse

            origin = urlparse(request.headers["origin"])
            if origin.netloc != request.headers.get("host"):
                return JSONResponse(
                    {"error": {"code": "cross_origin", "message": "Cross-origin mutation refused"}},
                    status_code=403,
                )
        length = request.headers.get("content-length", "0")
        body_limit = (
            24_000_000
            if request.url.path.endswith(("/artifact/prepare", "/review"))
            or request.url.path == "/api/v1/catalog/custom-tests"
            else 6_000_000
            if request.url.path == "/api/v1/catalog/uploads"
            else 200_000
        )
        if not length.isdigit() or int(length) > body_limit:
            return JSONResponse(
                {"error": {"code": "body_too_large", "message": "Request exceeds size limit"}},
                status_code=413,
            )
        # Bound actual streamed bytes too; Content-Length may be absent for chunked uploads.
        if request.method in {"POST", "PUT", "PATCH"}:
            chunks = bytearray()
            async for chunk in request.stream():
                if len(chunks) + len(chunk) > body_limit:
                    return JSONResponse(
                        {"error": {"code": "body_too_large", "message": "Request exceeds size limit"}},
                        status_code=413,
                    )
                chunks.extend(chunk)
            request._body = bytes(chunks)
        # Resolve/refresh before route dependencies acquire their database write lock.
        clear_session = False
        if (
            request.url.path.startswith("/api/v1/")
            and request.cookies.get("atomic_session")
            and not request.headers.get("authorization")
        ):
            try:
                request.state.browser_session = await run_in_threadpool(
                    app.state.browser_sessions.resolve, request.cookies["atomic_session"]
                )
                clear_session = request.state.browser_session is None
            except SessionUnavailable:
                request.state.browser_session_unavailable = True
        response = await call_next(request)
        if clear_session:
            response.delete_cookie("atomic_session")
        response.headers.update(
            {"X-Content-Type-Options": "nosniff", "Cache-Control": "no-store", "X-Frame-Options": "DENY"}
        )
        logger.info(
            "http_request method=%s status=%s elapsed_ms=%d",
            request.method,
            response.status_code,
            (time.monotonic() - start) * 1000,
        )
        return response

    @app.get("/health")
    def health():
        return {"status": "ok", "mode": settings.mode}

    @app.get("/ready")
    def ready():
        task = getattr(app.state, "preparation_worker", None)
        if (
            settings.artifact_worker_enabled
            and task
            and (not task.is_alive() or time.time() - app.state.preparation_worker_tick > 45)
        ):
            return JSONResponse({"status": "not_ready", "component": "test_preparation"}, status_code=503)
        with app.state.engine.connect() as connection:
            connection.execute(text("SELECT version_num FROM alembic_version"))
        return {"status": "ready"}

    app.include_router(router)
    app.include_router(artifacts_router)
    app.include_router(packages_router)
    app.include_router(agent_settings_router)
    app.include_router(catalog_router)
    app.include_router(custom_tests_router)
    app.include_router(execution_access_router)
    app.include_router(profile_sync_router)
    app.include_router(catalog_deployments_router)
    app.include_router(run_batches_router)
    app.include_router(users_router)
    app.include_router(browser_router)
    return app


app = create_app()
