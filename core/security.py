from datetime import datetime, timedelta, timezone
from typing import Any

from jose import jwt
from passlib.context import CryptContext
from uuid import uuid4
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from core.db import get_db_session
import models as mo
from sqlalchemy.future import select

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


ALGORITHM = settings.hash_algorithm


def create_access_token(subject: str | Any, expires_delta: timedelta) -> str:
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode = {
                "exp": expire,
                "sub": str(subject),
                "type": "access",
                "jti": str(uuid4())
                }
    encoded_jwt = jwt.encode(to_encode,
                             settings.secret_key,
                             algorithm=ALGORITHM)
    return encoded_jwt


async def create_refresh_token(session: AsyncSession, subject: str,
                               expires_delta: timedelta = timedelta(days=7)):
    """
    subject is the user id
    """
    # revoke previous refresh tokens for the user
    res = await session.execute(select(mo.RefreshToken).where(mo.RefreshToken.user_id == subject, mo.RefreshToken.revoked == False))
    access_tokens = res.scalars().all()
    for token in access_tokens:
        token.revoked = True
    await session.commit()

    expire = datetime.now() + expires_delta

    data = {
        "sub": subject,
        "type": "refresh",
        "jti": str(uuid4())
    }

    session.add(mo.RefreshToken(
        token_id=data["jti"],
        user_id=data["sub"],
        expires_at=expire
    ))
    await session.commit()

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
