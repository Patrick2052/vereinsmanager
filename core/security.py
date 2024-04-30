from datetime import datetime, timedelta, timezone
from typing import Any

from jose import jwt
from passlib.context import CryptContext

from core.config import settings
# import models as mo

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


ALGORITHM = settings.hash_algorithm


def create_access_token(subject: str | Any, expires_delta: timedelta) -> str:
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode = {
                "exp": expire,
                "sub": str(subject),
                "type": "access"
                }
    encoded_jwt = jwt.encode(to_encode,
                             settings.secret_key,
                             algorithm=ALGORITHM)
    return encoded_jwt


def create_refresh_token(subject: str,
                         expires_delta: timedelta = timedelta(days=7)):

    expire = datetime.now() + expires_delta

    data = {
        "sub": subject,
        "type": "refresh"
    }

    to_encode = data.copy()
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode,
                             settings.secret_key,
                             algorithm=ALGORITHM)
    return encoded_jwt


def decode_token(token: str):
    return jwt.decode(token, settings.secret_key)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


# def authenticate_user(user_id: str) -> mo.User | None:
