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
import schemas
import models as mo

reusable_oauth2 = OAuth2PasswordBearer(
    tokenUrl="/auth/access-token"
)


TokenDep = Annotated[str, Depends(reusable_oauth2)]


async def get_db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


SessionDep = Annotated[SessionLocal, Depends(get_db)]


def get_current_user(session: SessionDep, token: TokenDep) -> schemas.User:
    try:
        # payload = jwt.decode(
        #     token, settings.secret_key, algorithms=[security.ALGORITHM]
        # )
        payload = security.decode_token(token)
        print(payload)
        token_data = TokenPayload(**payload)
        print(token_data)
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