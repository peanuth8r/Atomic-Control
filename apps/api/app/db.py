from collections.abc import Generator

from fastapi import Request
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import Session, sessionmaker


def make_engine(url: str):
    engine = create_engine(
        url, connect_args={"check_same_thread": False, "timeout": 30} if url.startswith("sqlite") else {}
    )
    if url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def configure(connection, _):
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA journal_mode=WAL")

    return engine


def session(request: Request) -> Generator[Session]:
    with request.app.state.sessions() as db:
        if db.bind.dialect.name == "sqlite":
            # Serialize write decisions across API processes, not just threads.
            db.execute(text("BEGIN IMMEDIATE"))
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise


def factory(engine):
    return sessionmaker(engine, expire_on_commit=False)
