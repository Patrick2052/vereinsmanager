from sqlalchemy import Column, String, Boolean, DateTime, func, ForeignKey
from sqlalchemy.orm import Session
from sqlalchemy.dialects.postgresql import UUID
import uuid
from core.db import Base
# from internal.auth import get_password_hash, verify_password
from sqlalchemy.ext.asyncio import AsyncAttrs


class User(Base, AsyncAttrs):
    __tablename__ = 'users'

    id = Column(String, primary_key=True, default=str(uuid.uuid4()))
    username = Column(String)
    first_name = Column(String)
    last_name = Column(String, nullable=True)
    email = Column(String, unique=True)
    agb_read_and_accepted = Column(Boolean, default=False)
    datenschutz_read_and_accepted = Column(Boolean, default=False)
    profile_pic_url = Column(String, nullable=True)

    disabled = Column(Boolean, default=False)
    created = Column(DateTime, default=func.now())

    hashed_password = Column(String, nullable=False)

    # def set_password(self, pw: str) -> None:
    #     """
    #     sets the password in this user model put doesn't
    #     update the database automatically
    #     """
    #     self.hashed_password = get_password_hash(pw)

    # def verify_password(self, plain_password: str) -> bool:
    #     return verify_password(plain_password, self.hashed_password)


class RefreshToken(Base, AsyncAttrs):
    __tablename__ = "auth_refresh_tokens"

    token_id = Column(UUID, primary_key=True)
    user_id = Column(String, ForeignKey('users.id'), nullable=False)
    revoked = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True))
