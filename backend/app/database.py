"""SQLAlchemy engine, session, болон declarative base."""
from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_settings

settings = get_settings()

_connect_args = {}
if settings.database_url.startswith("sqlite"):
    # SQLite-ийг олон thread-ээс ашиглахад шаардлагатай.
    _connect_args = {"check_same_thread": False}

engine = create_engine(
    settings.database_url,
    connect_args=_connect_args,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    """Бүх ORM моделийн declarative base."""


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency: session нээж, хүсэлт дуусахад хаана."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Бүх хүснэгтийг үүсгэнэ (sqlite migration-ийн хялбар хувилбар)."""
    # models модулийг import хийснээр Base.metadata-д бүртгэгдэнэ.
    from app import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
