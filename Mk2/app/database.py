"""
app.database
─────────────
SQLAlchemy engine, session factory, and bootstrap helpers.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.models import Base


# Module-level state (populated by ``init_db``)
_engine = None
_SessionLocal: sessionmaker | None = None


def init_db(database_url: str) -> None:
    """
    Create the engine, bind it to the session factory,
    and issue CREATE TABLE for any missing tables.
    """
    global _engine, _SessionLocal

    _engine = create_engine(
        database_url,
        echo=False,
        connect_args={"check_same_thread": False},  # SQLite only
    )
    _SessionLocal = sessionmaker(bind=_engine, expire_on_commit=False)

    # Create all tables that don't already exist
    Base.metadata.create_all(bind=_engine)


@contextmanager
def get_db() -> Generator[Session, None, None]:
    """
    Provide a transactional database session.

    Usage::

        with get_db() as session:
            user = session.query(User).first()
    """
    if _SessionLocal is None:
        raise RuntimeError("Database not initialised — call init_db() first.")

    session = _SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
