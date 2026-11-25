import unicodedata

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


class _Strict(BaseModel):
    # extra="forbid": a client cannot smuggle `role`, `is_active`, `email_verified`... (mass assignment).
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)


class RegisterIn(_Strict):
    email: EmailStr = Field(max_length=320)
    # 12..128: long passphrases allowed, upper bound stops multi-MB inputs reaching Argon2.
    password: str = Field(min_length=12, max_length=128)
    display_name: str = Field(min_length=1, max_length=50)

    @field_validator("display_name")
    @classmethod
    def _clean_name(cls, v: str) -> str:
        v = unicodedata.normalize("NFKC", v).strip()
        if not v or any(unicodedata.category(c).startswith("C") for c in v):
            raise ValueError("display name must be printable text")
        return v

    @field_validator("password")
    @classmethod
    def _not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("password must not be blank")
        return v


class LoginIn(_Strict):
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=1, max_length=128)
