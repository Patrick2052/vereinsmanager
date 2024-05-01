from datetime import datetime, timedelta, timezone
from typing import Any

from jose import jwt
from passlib.context import CryptContext
from uuid import uuid4
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from core.db import get_db_session
from core.email import send_email_confirmation
import models as mo
from sqlalchemy.ext.asyncio import AsyncSession
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


def check_password_strength(password: str) -> bool:
    "check if password is good enough"

    return True


def create_email_verification_token(email: str,
                                    user_id: str,
                                    expires_delta: timedelta) -> dict:
    """

    returns a dict

    {
        "encoded_token": "...",
        "jti": "<token_id>",
        "expires": timestamp
    }
    """

    expire = datetime.now(timezone.utc) + expires_delta

    jti = str(uuid4())

    to_encode = {
                "exp": expire,
                "email": email,
                "user_id": user_id,
                "type": "email_verification",
                "jti": jti
                }

    encoded_jwt = jwt.encode(to_encode,
                             settings.secret_key,
                             algorithm=ALGORITHM)

    return {
            "encoded_token": encoded_jwt,
            "jti": jti,
            "expires": expire
            }


def create_password_reset_token(email: str,
                                user_id: str,
                                expires_delta: timedelta = timedelta(minutes=15)) -> dict:
    """

    returns a dict

    {
        "encoded_token": "...",
        "jti": "<token_id>",
        "expires": timestamp
    }
    """

    expire = datetime.now(timezone.utc) + expires_delta

    jti = str(uuid4())

    to_encode = {
                "exp": expire,
                "email": email,
                "user_id": user_id,
                "type": "password_reset",
                "jti": jti
                }

    encoded_jwt = jwt.encode(to_encode,
                             settings.secret_key,
                             algorithm=ALGORITHM)

    return {
            "encoded_token": encoded_jwt,
            "jti": jti,
            "expires": expire
            }


async def send_email_verification_email(
        db: AsyncSession,
        user_id: str,
        email: str = None
        ):
    """
    creates a email verification token and stores it in the db
    then sends a email to the user
    """

    user = await db.get(mo.User, user_id)
    if user is None:
        raise ValueError("User does not exist")
    user_email = user.email

    email_verification_token_info = create_email_verification_token(user_email, user_id, expires_delta=timedelta(hours=24))
    user.email_confirmation_token_jti = email_verification_token_info["jti"]

    await db.commit()

    send_email_confirmation(user_email, email_verification_token_info["encoded_token"])

    return
