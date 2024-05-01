from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from core.config import settings

from core.db import Base
# Import your models here. For example:
# from .models import User, Item
from models import *



async def main():
    engine = create_async_engine(settings.postgres_dsn)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())