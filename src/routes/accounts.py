from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import BaseSecurityError
from schemas import TokenRefreshResponseSchema, TokenRefreshRequestSchema
from schemas.accounts import UserCreate, UserLoginRequestSchema
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password, verify_password
from security.utils import generate_secure_token

router = APIRouter()


@router.post("/register/", status_code=status.HTTP_201_CREATED)
def register_user(user_data: UserCreate, db: Session = Depends(get_db)):
    try:
        existing_user = db.execute(select(UserModel).filter(UserModel.email == user_data.email)).scalar_one_or_none()
        if existing_user:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                                detail=f"A user with this email {user_data.email} already exists.")

        hashed_password = hash_password(user_data.password)

        new_user = UserModel(email=user_data.email, password=hashed_password, group=UserGroupEnum.USER)
        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        activation_token = ActivationTokenModel(user_id=new_user.id, token=generate_secure_token())
        db.add(activation_token)
        db.commit()

        return {"id": new_user.id, "email": new_user.email}

    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="An error occurred during user creation.")


@router.post("/activate/", status_code=status.HTTP_200_OK)
def activate_user(email: str, token: str, db: Session = Depends(get_db)):
    try:
        activation_token = db.execute(
            select(ActivationTokenModel).filter(ActivationTokenModel.token == token)
        ).scalar_one_or_none()

        if not activation_token or activation_token.user.email != email:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail="Invalid or expired activation token.")

        user = activation_token.user
        if user.is_active:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail="User account is already active.")

        user.is_active = True
        db.delete(activation_token)
        db.commit()

        return {"message": "User account activated successfully."}

    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="An error occurred during account activation.")


@router.post("/password-reset/request/", status_code=status.HTTP_200_OK)
def request_password_reset(email: str, db: Session = Depends(get_db)):
    try:
        user = db.execute(select(UserModel).filter(UserModel.email == email)).scalar_one_or_none()

        if user and user.is_active:
            db.execute(delete(PasswordResetTokenModel).filter(PasswordResetTokenModel.user_id == user.id))
            reset_token = PasswordResetTokenModel(user_id=user.id, token=generate_secure_token(),
                                                  expires_at=datetime.now(timezone.utc))
            db.add(reset_token)
            db.commit()

        return {"message": "If you are registered, you will receive an email with instructions."}

    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="An error occurred during password reset request.")


@router.post(
    "/reset-password/complete/",
    status_code=status.HTTP_200_OK
)
def complete_password_reset(
        email: str,
        token: str,
        password: str,
        db: Session = Depends(get_db)
):
    try:
        reset_token = db.execute(
            select(PasswordResetTokenModel).filter(PasswordResetTokenModel.token == token)
        ).scalar_one_or_none()

        user = db.execute(select(UserModel).filter(UserModel.email == email)).scalar_one_or_none()
        stmt = select(PasswordResetTokenModel).filter_by(user_id=user.id)
        result = db.execute(stmt)
        token_record = result.scalars().first()
        expires_at = cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)

        if not reset_token or reset_token.user.email != email or expires_at < datetime.now(timezone.utc):
            if reset_token:
                db.delete(reset_token)
                db.commit()
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail="Invalid email or token.")

        user = reset_token.user
        if not user or not user.is_active:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail="Invalid email or token.")

        user.password = hash_password(password)
        db.delete(reset_token)
        db.commit()

        return {"message": "Password reset successfully."}

    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="An error occurred while resetting the password.")


@router.post("/login/", status_code=status.HTTP_200_OK)
def login_user(
        login_data: UserLoginRequestSchema,
        db: Session = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    try:
        user = db.execute(select(UserModel).filter(UserModel.email == login_data.email)).scalar_one_or_none()
        if not user or not verify_password(login_data.password, user.password):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password.")

        if not user.is_active:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account is not activated.")

        access_token = jwt_manager.create_access_token(user_id=user.id)
        refresh_token = jwt_manager.create_refresh_token(user_id=user.id)

        refresh_token_entry = RefreshTokenModel(user_id=user.id, token=refresh_token,
                                                created_at=datetime.now(timezone.utc))
        db.add(refresh_token_entry)
        db.commit()

        return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}

    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="An error occurred while processing the request.")


@router.post(
    "/api/v1/accounts/refresh/",
    response_model=TokenRefreshResponseSchema
)
def refresh_access_token(
        request: TokenRefreshRequestSchema,
        db: Session = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    try:
        payload = jwt_manager.decode_refresh_token(request.refresh_token)
        user_id = payload.get("sub")

        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid refresh token."
            )

        token_entry = db.query(RefreshTokenModel).filter_by(token=request.refresh_token).first()
        if not token_entry:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token not found."
            )

        user = db.query(UserModel).filter_by(id=user_id).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found."
            )

        new_access_token = jwt_manager.create_access_token(user_id=user.id)

        return {"access_token": new_access_token}
    except HTTPException as e:
        raise e
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired."
        )
