from core.config import settings
from fastapi.security import OAuth2PasswordBearer
from core.db import SessionLocal
from typing import Annotated
from fastapi import Depends, HTTPException, status
from collections.abc import Generator
from jose import JWTError
from pydantic import ValidationError
from jose import JWTError, jwt
from core import security
from schemas.token import TokenPayload
import models as mo

reusable_oauth2 = OAuth2PasswordBearer(
    tokenUrl=f"/auth/access-token"
)


TokenDep = Annotated[str, Depends(reusable_oauth2)]


async def get_db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


SessionDep = Annotated[SessionLocal, Depends(get_db)]


def get_current_user(session: SessionDep, token: TokenDep):
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[security.ALGORITHM]
        )
        token_data = TokenPayload(**payload)
    except (JWTError, ValidationError):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Could not validate credentials",
        )
    user = session.query(mo.User, token_data.sub)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return user