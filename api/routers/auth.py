from fastapi import APIRouter
from typing import Annotated
from fastapi.security import OAuth2PasswordRequestForm
from fastapi import Depends, HTTPException

router = APIRouter()


@router.get("/auth/access-token")
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
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