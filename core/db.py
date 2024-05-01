from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, func
from sqlalchemy.orm import sessionmaker, Session, declarative_base, DeclarativeBase
from core.config import settings
from typing import Any, AsyncIterator
import contextlib
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

# Create the engine
engine = create_engine(
    settings.postgres_dsn
)


# from https://medium.com/@tclaitken/setting-up-a-fastapi-app-with-async-sqlalchemy-2-0-pydantic-v2-e6c540be4308
class DatabaseSessionManager:
    def __init__(self, host: str, engine_kwargs: dict[str, Any] = {}):
        self._engine = create_async_engine(host, **engine_kwargs)
        self._sessionmaker = async_sessionmaker(autocommit=False,
                                                 bind=self._engine)

    async def close(self):
        if self._engine is None:
            raise Exception("DatabaseSessionmanager is not initialized")
        await self._engine.dispose()

    @contextlib.asynccontextmanager
    async def connect(self) -> AsyncIterator[AsyncConnection]:
        if self._engine is None:
            raise Exception("DatabaseSessionManager is not initialized")

        async with self._engine.begin() as connection:
            try:
                yield connection
            except Exception:
                await connection.rollback()
                raise

    @contextlib.asynccontextmanager
    async def session(self) -> AsyncIterator[AsyncSession]:
        if self._sessionmaker is None:
            raise Exception("DatabaseSessionManager is not initialized")

        session = self._sessionmaker()
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


sessionmanager = DatabaseSessionManager(settings.postgres_dsn,
                                        {"echo": settings.echo_sql})


async def get_db_session():
    async with sessionmanager.session() as session:
        yield session


# Create a session factory
# SessionLocal = sessionmaker(bind=engine)

Base = declarative_base()




def init_db(db: Session) -> None:
    """
    """
