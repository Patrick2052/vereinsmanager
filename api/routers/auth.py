from datetime import timedelta, datetime
from typing import Annotated
from fastapi.responses import HTMLResponse
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from sqlalchemy.future import select
from jose.exceptions import JWTError
from pydantic import EmailStr, ValidationError
import models as mo
import schemas
from core.config import settings
from core.logger import main_logger
import crud

from fastapi import (
    APIRouter,
    Response,
    Form,
    Request,
    Depends,
    HTTPException,
    status,
)

from schemas.token import (
    TokenPayload,
    EmailVerificationTokenPayload,
    PasswordResetTokenPayload,
)
from core.email import (
    send_basic_email,
    send_email_confirmation,
    send_password_recovery,
)
from core.security import (
    create_access_token,
    decode_token,
    verify_password,
    create_refresh_token,
    check_password_strength,
    create_email_verification_token,
    create_password_reset_token,
)
from api.dependencies import (
    bearer_only_oauth2,
    SessionDep,
    get_current_user,
    refresh_token,
)

import schemas.token


router = APIRouter(tags=["auth"])


@router.post("/access-token")
async def login_for_access_token(response: Response, form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: SessionDep, request: Request):  # noqa

    # check username / email
    res = await db.execute(select(mo.User).where(mo.User.email == form_data.username))
    user = res.scalars().first()

    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Username or password false")  # noqa

    user_email = user.email

    # verify password
    if not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Username or password false")  # noqa

    access_token = create_access_token(user.id,
                                       settings.jwt_session_lifetime)

    refresh_token = await create_refresh_token(db, user.id,
                                               settings.jwt_refresh_lifetime)

    # TODO: samesite?
    response.set_cookie(key=settings.jwt_refresh_token_cookie_name,
                        value=refresh_token,
                        httponly=True,
                        secure=settings.jwt_refresh_token_secure,
                        samesite="strict"
                        )

    client_ip = request.client.host
    user_agent = request.headers.get("User-Agent")

    # send warning email to user
    text = f"""
    Vereinsmanager - new login to your account from IP: {client_ip}, User-Agent: {user_agent}

    at {str(datetime.datetime.now())}

    ### If it was you who logged in you can ignore this email ### 
    """
    try:
        send_basic_email(body=text, receiver_email=user_email, subject="vereinsmanager - new login")
    except Exception as e:
        main_logger.exception(f"Sending Email on login to {user_email} failed",
                              exc_info=e)

    return {"access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer"}


@router.post("/refresh-token")
def get_access_token_via_refresh_token(refresh_token: Annotated[TokenPayload, Depends(refresh_token)]):

    access_token = create_access_token(refresh_token.sub,
                                       settings.jwt_session_lifetime)

    return {
        "access_token": access_token
    }


@router.post("/register-new-user")
async def register_new_user(
                      db: SessionDep,
                      response: Response,
                      password: Annotated[str, Form()],
                      email: Annotated[EmailStr, Form()],
                      datenschutz: Annotated[bool, Form()],
                      agb: Annotated[bool, Form()],
                      username: Annotated[str | None, Form()] = None,
                      first_name: Annotated[str | None, Form()] = None,
                      last_name: Annotated[str | None, Form()] = None,
                      ):

    if not datenschutz:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Datenschutz muss akzeptiert werden!")

    if not agb:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Agb müssen akzeptiert werden!")

    if not check_password_strength(password):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Password is not strong enough!")

    # check for email duplicate
    res = await db.execute(select(mo.User).where(mo.User.email == email))
    user = res.scalars().first()
    if user is not None:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            detail="User with this email already exists!")

    new_user = mo.User(
        username=username,
        first_name=first_name,
        last_name=last_name,
        email=email,
        agb_read_and_accepted=agb,
        datenschutz_read_and_accepted=datenschutz,
    )
    new_user.set_password(password)
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    user_id = new_user.id
    user_email = new_user.email

    send_email_verification_email(db, user_email, user_id)

    access_token = create_access_token(user_id,
                                       settings.jwt_session_lifetime)

    refresh_token = await create_refresh_token(db, user_id,
                                               settings.jwt_refresh_lifetime)

    response.set_cookie(key=settings.jwt_refresh_token_cookie_name,
                        value=refresh_token,
                        httponly=True,
                        secure=settings.jwt_refresh_token_secure,
                        samesite="strict"
                        )

    return {
        "status": "registered",
        "access_token": access_token,
        "refresh_token": refresh_token
    }


@router.get("/confirm-email")
async def confirm_email(db: SessionDep, token: str):
    """The endpoint hit by the link in the confirmation email"""

    try:
        payload = decode_token(token)
    except JWTError:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Invalid or expired Token")

    try:
        token_data = EmailVerificationTokenPayload(**payload)
    except ValidationError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token structure")

    if token_data.type != "email_verification":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token")

    user = await db.get(mo.User, token_data.user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if user.email_verified is True:
        return "email is already verified"

    user_email_token_jti = user.email_confirmation_token_jti
    if user_email_token_jti != token_data.jti:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="This isn't the newest token")

    user.email_verified = True
    await db.commit()

    return "email verfied - you can close this window now"


@router.put("/confirm-email")
async def trigger_email_confirmation(db: SessionDep,
                                     current_user=Depends(get_current_user)):
    """
    function to manually trigger a new email confirmation
    email to be sent to the user
    """

    await send_email_verification_email(db, user_id=current_user.id)

    return "email sent"


@router.get("/me")
async def get_current_user_info(current_user: schemas.User = Depends(get_current_user)):
    return {
        "user_data": schemas.PublicUserData(**current_user.model_dump())
    }


@router.get("/password-recovery")
def recovery_page(token: str):

    page = f"""
    <h1>PW Reset</h1>

    <form action="http://localhost:8000/auth/reset-password" method="POST">
        <input type="password" name="new_password" id="new_password">
        <input type="hidden" name="token" id="token" value="{token}">
        <input type="submit"/>
    </form>
    """

    return HTMLResponse(
        page
    )


@router.post("/password-recovery")
async def recover_password(email: str, db: SessionDep):

    user = await crud.get_user_by_email(db, email)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="User not found")

    user_email = user.email
    user_id = user.id

    pw_reset_token_info = create_password_reset_token(user_email,
                                                      user_id,
                                                      expires_delta=timedelta(minutes=15))

    db.add(mo.PasswordResetToken(
        token_id=pw_reset_token_info["jti"],
        user_id=user_id,
        revoked=False,
        expires_at=pw_reset_token_info["expires"]
    ))
    await db.commit()

    send_password_recovery(user_email, pw_reset_token_info["encoded_token"])

    return "email sent"


@router.post("/reset-password")
async def reset_password(db: SessionDep,
                         request: Request,
                         new_password=Form(...),
                         token=Form(...)):

    if not check_password_strength(new_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password is too weak")

    try:
        payload = decode_token(token)
    except JWTError:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Invalid or expired Token")

    try:
        token_data = PasswordResetTokenPayload(**payload)
    except ValidationError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token structure")

    if token_data.type != "password_reset":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token")

    res = await db.execute(select(mo.PasswordResetToken).where(mo.PasswordResetToken.token_id == token_data.jti))
    token = res.scalars().first()
    if token is not None:
        if token.revoked is True:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail="Invalid Token")

    user = await db.get(mo.User, token_data.user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    user.set_password(new_password)
    token.revoked = True
    await db.commit()

    return "new password set"
