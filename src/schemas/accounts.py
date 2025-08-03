from pydantic import BaseModel, EmailStr, field_validator, ConfigDict

from database import accounts_validators, UserGroupEnum


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str
    group: UserGroupEnum = UserGroupEnum.USER

    @field_validator("email")
    @classmethod
    def validate_user_email(cls, user_email: str) -> str:
        return accounts_validators.validate_email(user_email)

    @field_validator("password")
    @classmethod
    def validate_user_password_strength(cls, user_password: str) -> str:
        return accounts_validators.validate_password_strength(user_password)


class UserRegistrationResponseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    email: EmailStr
