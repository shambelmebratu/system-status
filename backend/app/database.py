from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import get_settings


_url = get_settings().database_url
# Pool headroom for long-polling requests (they use short sessions, but several can overlap). SQLite (tests) has no such pool.
_pool = {} if _url.startswith("sqlite") else {"pool_size": 10, "max_overflow": 20}
engine = create_engine(_url, pool_pre_ping=True, pool_recycle=1800, **_pool)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def get_db() -> Generator[Session, None, None]:
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
