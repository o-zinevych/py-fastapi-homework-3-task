from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from passlib.context import CryptContext
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
    RefreshTokenModel,
)
from exceptions import BaseSecurityError
from schemas import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    MessageResponseSchema,
    UserActivationRequestSchema,
)
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


async def get_user_by_email(email: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(UserModel).where(UserModel.email == email))
    user = result.scalar_one_or_none()
    return user


@router.post(
    "/register/", status_code=201, response_model=UserRegistrationResponseSchema
)
async def register_user(
    user_data: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)
):
    email = cast(str, user_data.email)
    db_user = await get_user_by_email(email, db)
    if db_user:
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {user_data.email} already exists.",
        )
    try:
        group_result = await db.execute(
            select(UserGroupModel).where(UserGroupModel.name == user_data.group)
        )
        group = group_result.scalar_one_or_none()

        new_user = UserModel(email=email, group=group)
        new_user.password = user_data.password

        activation_token = ActivationTokenModel(user_id=new_user.id)
        new_user.activation_token = activation_token

        db.add(new_user)
        await db.commit()
        await db.refresh(new_user)
        return new_user
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=500, detail="An error occurred during user creation."
        )


@router.post("/activate/", response_model=MessageResponseSchema)
async def activate_user(
    activation_data: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)
):
    email = cast(str, activation_data.email)
    db_user = await get_user_by_email(email, db)
    if db_user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    result = await db.execute(
        select(ActivationTokenModel).where(
            ActivationTokenModel.token == activation_data.token
        )
    )
    db_token = result.scalar_one_or_none()
    if db_token:
        expires_at = cast(datetime, db_token.expires_at).replace(tzinfo=timezone.utc)
    if (
        not db_token
        or db_token.user != db_user
        or expires_at < datetime.now(timezone.utc)
    ):
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )

    db_user.is_active = True
    db.add(db_user)
    await db.delete(db_token)
    await db.commit()
    return {"message": "User account activated successfully."}
