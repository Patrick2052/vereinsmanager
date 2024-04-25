from fastapi import APIRouter
from api.routers import auth
from core.config import settings

api_router = APIRouter()
api_router.include_router(auth.router, prefix="/auth")


@api_router.get("/status")
def app_status():
    return {
        "App Name": settings.app_name
    }