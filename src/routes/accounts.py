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
from schemas.accounts import UserCreate
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password
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

        activation_token = generate_secure_token()

        return {"id": new_user.id, "email": new_user.email}

    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="An error occurred during user creation.")
