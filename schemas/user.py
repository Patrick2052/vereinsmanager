from pydantic import BaseModel, EmailStr, HttpUrl
from datetime import datetime
from typing import Annotated


class UserCreate(BaseModel):
    username: str
    email: str
    password: str


class User(BaseModel):
    id: str
    username: str
    first_name: str | None = None
    last_name: str | None = None
    email: EmailStr
    email_verified: bool
    email_confirmation_token_jti: str | None = None
    agb_read_and_accepted: bool | None = None
    datenschutz_read_and_accepted: bool | None = None
    profile_pic_url: HttpUrl | None = None
    disabled: bool | None = None
    created: datetime | None = None
    hashed_password: str

    class Config:
        orm_mode = True


class RegisterUser(BaseModel):
    username: str | None
    first_name: str | None
    last_name: str | None
    email: EmailStr
    agb: bool
    datenschutz: bool
    password: str


class PublicUserData(BaseModel):
    id: str
    username: str
    first_name: str | None = None
    last_name: str | None = None
    email: EmailStr
    agb_read_and_accepted: bool | None = None
    datenschutz_read_and_accepted: bool | None = None
    profile_pic_url: HttpUrl | None = None
    openpowerlifting_url: HttpUrl | None = None
    # disabled: bool | None = None
    created: datetime | None = None
    # hashed_password: str

    class Config:
        orm_mode = True
