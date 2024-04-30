# from routers import auth
from typing import Union, Annotated
from fastapi import FastAPI, Query, Path, Depends
from fastapi.middleware.cors import CORSMiddleware
from api.main import api_router
from core.config import settings
from core.logger import main_logger
from core.db import sessionmanager
from contextlib import asynccontextmanager

origins = [
    "http://localhost:3000"
]


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Function that handles startup and shutdown events.
    To understand more, read https://fastapi.tiangolo.com/advanced/events/
    """
    yield
    if sessionmanager._engine is not None:
        # Close the DB connection
        await sessionmanager.close()


app = FastAPI(title=settings.app_name, lifespan=lifespan)
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

main_logger.debug("Application Startup in main")
