from typing import Any
from sqlalchemy.orm import Session
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
import schemas
from core.security import get_password_hash
import models as mo
from pydantic import EmailStr


def create_user(db: Session, user_create: schemas.UserCreate):
    user_data = schemas.User.model_validate(user_create, update={
        "hashed_password": get_password_hash(user_create.password) 
    })

    db.add(mo.User(
      username=user_data.username,
      email=user_data.email,
      hashed_password=user_data.hashed_password
    ))
    db.commit()


async def get_user_by_email(db: AsyncSession, email: EmailStr) -> mo.User | None:
    res = await db.execute(select(mo.User).where(mo.User.email == email))
    user = res.scalars().first()
    return user


async def get_user_by_id(db: AsyncSession, id: str) -> mo.User | None:
    res = await db.execute(select(mo.User).where(mo.User.id == id))
    user = res.scalars().first()
    return user


# def create_user(*, session: Session, user_create: UserCreate) -> User:
#     db_obj = User.model_validate(
#         user_create, update={"hashed_password": get_password_hash(user_create.password)}
#     )
#     session.add(db_obj)
#     session.commit()
#     session.refresh(db_obj)
#     return db_obj


# def update_user(*, session: Session, db_user: User, user_in: UserUpdate) -> Any:
#     user_data = user_in.model_dump(exclude_unset=True)
#     extra_data = {}
#     if "password" in user_data:
#         password = user_data["password"]
#         hashed_password = get_password_hash(password)
#         extra_data["hashed_password"] = hashed_password
#     db_user.sqlmodel_update(user_data, update=extra_data)
#     session.add(db_user)
#     session.commit()
#     session.refresh(db_user)
#     return db_user


# def get_user_by_email(*, session: Session, email: str) -> User | None:
#     statement = select(User).where(User.email == email)
#     session_user = session.exec(statement).first()
#     return session_user


# def authenticate(*, session: Session, email: str, password: str) -> User | None:
#     db_user = get_user_by_email(session=session, email=email)
#     if not db_user:
#         return None
#     if not verify_password(password, db_user.hashed_password):
#         return None
#     return db_user


# def create_item(*, session: Session, item_in: ItemCreate, owner_id: int) -> Item:
#     db_item = Item.model_validate(item_in, update={"owner_id": owner_id})
#     session.add(db_item)
#     session.commit()
#     session.refresh(db_item)
#     return db_item
