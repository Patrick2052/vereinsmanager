from pydantic import BaseModel, EmailStr
from typing import Literal


class TokenPayload(BaseModel):
    sub: str | None = None
    # user_id: str
    exp: int
    type: str


class RefreshTokenPayload(TokenPayload):
    jti: str


class EmailVerificationTokenPayload(BaseModel):
    exp: int
    type: Literal["email_verification"]
    email: EmailStr
    user_id: str
    jti: str


class PasswordResetTokenPayload(BaseModel):
    exp: int
    type: Literal["password_reset"]
    email: EmailStr
    user_id: str
    jti: str
