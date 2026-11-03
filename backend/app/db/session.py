"""数据库会话管理，兼容 SQLite（开发）与 MySQL（生产）。"""

from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings

_is_sqlite = settings.DATABASE_URL.startswith("sqlite")

engine_kwargs: dict = {"echo": settings.DB_ECHO, "future": True}
if _is_sqlite:
    # SQLite 需要允许多线程访问，且关闭同线程检查
    engine_kwargs["connect_args"] = {"check_same_thread": False}
else:
    engine_kwargs.update(
        pool_size=settings.DB_POOL_SIZE,
        max_overflow=settings.DB_MAX_OVERFLOW,
        pool_pre_ping=True,
        pool_recycle=3600,
    )

engine = create_engine(settings.DATABASE_URL, **engine_kwargs)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def get_db() -> Generator[Session, None, None]:
    """FastAPI 依赖注入用的会话生成器。"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """建表并写入初始数据（角色/权限/默认管理员/内置 YARA 规则）。"""
    from app.db.base import Base
    from app.db import models  # noqa: F401  确保模型注册到 metadata
    from app.db.init_data import seed_all

    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        seed_all(db)
