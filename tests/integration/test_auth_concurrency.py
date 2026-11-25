import asyncio

import httpx
import pytest
from sqlalchemy import func, select

from apps.api.app.config import Settings
from apps.api.app.main import create_app
from apps.api.app.models import Audit, Base


@pytest.mark.asyncio
async def test_parallel_signed_out_dashboard_requests_are_denied_and_audited(tmp_path):
    app = create_app(Settings(database_url=f"sqlite:///{tmp_path}/auth.db", dev_auth=False))
    Base.metadata.create_all(app.state.engine)
    paths = ["me", "tests", "actors", "runs", "audit", "approvals"]
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://control.test"
    ) as http:
        responses = await asyncio.wait_for(
            asyncio.gather(*(http.get("/api/v1/" + path) for path in paths)), timeout=5
        )
    assert all(response.status_code == 401 for response in responses)
    with app.state.sessions() as db:
        assert db.scalar(select(func.count()).select_from(Audit)) == len(paths)
