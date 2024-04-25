from fastapi import APIRouter
from typing import Annotated
from fastapi.security import OAuth2PasswordRequestForm
from fastapi import Depends, HTTPException, status
from api.dependencies import reusable_oauth2, get_db, get_current_user, has_agb
from sqlalchemy.orm import Session
from core.security import create_access_token, decode_token, verify_password
import datetime
import models as mo
import schemas

router = APIRouter()


@router.post("/access-token")
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: Session = Depends(get_db)):


    # check username / email
    user = db.query(mo.User).where(mo.User.email == form_data.username).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Username or password false")

    # verify password
    if not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Username or password false")

    print(user)

    access_token = create_access_token(user.id, datetime.timedelta(minutes=30))

    return {"access_token": access_token, "token_type": "bearer"}
    # print("token")
    # print(form_data.__dict__)

    # user = get_user(fake_users, form_data.username)
    # if not user:
    #     raise HTTPException(
    #         status_code=status.HTTP_400_BAD_REQUEST,
    #         detail="Incorrect username or password"
    #     )
    # print(user)

    # hashed_password = f"fakehash_{form_data.password}"
    # if not hashed_password == user.hashed_password:
    #     raise HTTPException(
    #         status_code=status.HTTP_400_BAD_REQUEST,
    #         detail="Incorrect Username or Password"
    #     )

    # return {
    #     "access_token": user.username, "token_type": "bearer"
    # }


@router.get("/test-secure")
async def test_secure(token: Annotated[str, Depends(reusable_oauth2)], current_user: schemas.User = Depends(get_current_user)):
    return {"user_data": current_user, "token_raw": token, "token_data": decode_token(token)}


@router.get("/test-secure-agb")
async def test_secure(token: Annotated[str, Depends(reusable_oauth2)], current_user: schemas.User = Depends(get_current_user), has_agb = Depends(has_agb)):
    return {"user_data": current_user, "token_raw": token, "token_data": decode_token(token)}
