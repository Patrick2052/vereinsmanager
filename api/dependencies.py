from collections.abc import Generator
from typing import Annotated

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2AuthorizationCodeBearer
from jose import JWTError, jwt
from pydantic import ValidationError, BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

import models as mo
import schemas
from schemas.token import TokenPayload, RefreshTokenPayload
from core import security
from core.config import settings
from core.db import get_db_session


TOKEN_URL = "/auth/access-token"

# only looks for the bearer authorization header for jwts
bearer_only_oauth2 = OAuth2PasswordBearer(
    tokenUrl=TOKEN_URL
)


# takes the tokens from cookies or authorization bearer header
optional_oauth2_password_bearer = OAuth2PasswordBearer(
    tokenUrl=TOKEN_URL,
    auto_error=False,
)


TokenDep = Annotated[str, Depends(bearer_only_oauth2)]


SessionDep = Annotated[AsyncSession, Depends(get_db_session)]


async def get_current_user(session: SessionDep, token: TokenDep) -> schemas.User:
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

    result = await session.execute(select(mo.User).where(mo.User.id == token_data.sub))
    user = result.scalars().first()

    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    user_data = schemas.User(**user.__dict__)

    if user_data.disabled is True:
        raise HTTPException(status_code=400, detail="Inactive user")
    return user_data


async def refresh_token(request: Request, db: SessionDep) -> RefreshTokenPayload:
    """
    refresh token is only avaliable in a http only cookie

    raises 403 when refresh token is revoked in db
    raises 403 when refresh token is expired
    raises 403 if refresh token is not provided
    raises 403 when token is not a refresh token (type: refresh)
    """

    # look into cookeis
    cookie_refresh_token = request.cookies.get(settings.jwt_refresh_token_cookie_name)

    if cookie_refresh_token is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="No Token")

    try:
        payload = security.decode_token(cookie_refresh_token)
    except JWTError:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Invalid Token")

    try:
        token_data = RefreshTokenPayload(**payload)
    except ValidationError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token structure")

    if token_data.type != "refresh":
        print("token is not refresh")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Invalid Token")

    res = await db.execute(select(mo.RefreshToken).where(mo.RefreshToken.token_id == token_data.jti,
                                                         mo.RefreshToken.revoked == True))
    revoked_token = res.scalars().first()
    if revoked_token is not None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Refresh token is revoked")

    return token_data
