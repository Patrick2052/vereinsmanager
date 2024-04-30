from pydantic import BaseModel, EmailStr, HttpUrl
from datetime import datetime


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
    agb_read_and_accepted: bool | None = None
    datenschutz_read_and_accepted: bool | None = None
    profile_pic_url: HttpUrl | None = None
    disabled: bool | None = None
    created: datetime | None = None
    hashed_password: str

    class Config:
        orm_mode = True


class PublicUserData(BaseModel):
    id: str
    username: str
    first_name: str | None = None
    last_name: str | None = None
    email: EmailStr
    agb_read_and_accepted: bool | None = None
    datenschutz_read_and_accepted: bool | None = None
    profile_pic_url: HttpUrl | None = None
    disabled: bool | None = None
    created: datetime | None = None
    # hashed_password: str

    class Config:
        orm_mode = True