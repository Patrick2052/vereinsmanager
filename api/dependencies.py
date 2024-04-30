from collections.abc import Generator
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

import models as mo
import schemas
from schemas.token import TokenPayload
from core import security
from core.config import settings
from core.db import get_db_session

reusable_oauth2 = OAuth2PasswordBearer(
    tokenUrl="/auth/access-token"
)


TokenDep = Annotated[str, Depends(reusable_oauth2)]

# def auth_token(token = Depends(reusable_oauth2)):
#     try:
#         payload = security.decode_token(token)
#         token_data = TokenPayload(**payload)
#     except (JWTError, ValidationError):
#         raise HTTPException(
#             status_code=status.HTTP_403_FORBIDDEN,
#             detail="Could not validate credentials",
#         )

#     if token_data["type"] == "refresh":
#         raise HTTPException(
#             status_code=status.HTTP_403_FORBIDDEN,
#             detail="Refresh token not valid"
#         )


# async def get_db():
#     session = SessionLocal()
#     try:
#         yield session
#     finally:
#         session.close()


SessionDep = Annotated[AsyncSession, Depends(get_db_session)]


def get_current_user(session: SessionDep, token: TokenDep) -> schemas.User:
    try:
        payload = security.decode_token(token)
        token_data = TokenPayload(**payload)

        if token_data.type != "access":
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail="Invalid access token")

    except (JWTError, ValidationError):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Could not validate credentials",
        )

    user = session.query(mo.User).where(mo.User.id == token_data.sub).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    user_data = schemas.User(**user.__dict__)

    if user_data.disabled is True:
        raise HTTPException(status_code=400, detail="Inactive user")
    return user_data


def has_agb(user: schemas.User = Depends(get_current_user)) -> bool:
    if not user.agb_read_and_accepted:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="agb not accepted")
    else:
        return True
