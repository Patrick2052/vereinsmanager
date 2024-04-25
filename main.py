# from routers import auth
from typing import Union, Annotated
from fastapi import FastAPI, Query, Path, Depends
from fastapi.security import OAuth2PasswordBearer
from api.main import api_router
from core.config import settings
from core.logger import main_logger


app = FastAPI(title=settings.app_name)
app.include_router(api_router)

main_logger.debug("Application Startup in main")