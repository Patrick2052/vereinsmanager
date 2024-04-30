from fastapi import APIRouter
from typing import Annotated
from fastapi.security import OAuth2PasswordRequestForm
from fastapi import Depends, HTTPException, status
from api.dependencies import reusable_oauth2, SessionDep, get_current_user, has_agb
from sqlalchemy.orm import Session
from core.security import create_access_token, decode_token, verify_password, create_refresh_token
import datetime
import models as mo
import schemas
from jose.exceptions import JWTError
from core.config import settings
from sqlalchemy.future import select

import schemas.token

router = APIRouter(tags=["auth"])


@router.post("/access-token")
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: SessionDep):  # noqa

    # check username / email
    
    res = await db.execute(select(mo.User).where(mo.User.email == form_data.username))
    user = res.scalars().first()

    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Username or password false")  # noqa

    # verify password
    if not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Username or password false")  # noqa

    print(user)

    access_token = create_access_token(user.id, settings.jwt_session_lifetime)
    refresh_token = create_refresh_token(user.id, settings.jwt_refresh_lifetime)

    return {"access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer"}


@router.post("/refresh-token")
def get_access_token_via_refresh_token(token: Annotated[str, Depends(reusable_oauth2)]):

    try:
        payload = decode_token(token)
    except JWTError:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Invalid Token")

    token_data = schemas.token.TokenPayload(**payload)

    if token_data.type != "refresh":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Invalid Token")

    access_token = create_access_token(token_data.sub, settings.jwt_session_lifetime)

    return {
        "access_token": access_token
    }





# @router.get("/test-secure")
# async def test_secure(token: Annotated[str, Depends(reusable_oauth2)],
#                       current_user: schemas.User = Depends(get_current_user)):
#     return {"user_data": current_user, "token_raw": token, "token_data": decode_token(token)}


# @router.get("/test-secure-agb")
# async def test_secure_agb(token: Annotated[str, Depends(reusable_oauth2)],
#                           current_user: schemas.User = Depends(get_current_user),
#                           has_agb=Depends(has_agb)):

#     return {"user_data": current_user, "token_raw": token,
#             "token_data": decode_token(token)}


@router.get("/me")
async def get_current_user_info(current_user: schemas.User = Depends(get_current_user)):
    return {
        "user_data": schemas.PublicUserData(**current_user.model_dump())
    }
