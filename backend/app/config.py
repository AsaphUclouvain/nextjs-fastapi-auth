"""Typed settings, loaded from environment variables / .env.

Everything security-relevant is explicit here so it can be reviewed in one place.
"""

from functools import lru_cache
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_env: Literal["development", "test", "production"] = "development"
    database_url: str = "sqlite:///./app.db"
    redis_url: str = "redis://localhost:6379/0"
    redis_prefix: str = "auth"

    # Access tokens: short-lived HS256 JWTs. 32+ random bytes, e.g. `python -c "import secrets;print(secrets.token_urlsafe(48))"`.
    jwt_secret: str = Field(min_length=32)
    jwt_issuer: str = "authapp-api"
    jwt_audience: str = "authapp-web"
    access_token_ttl_s: int = Field(default=600, ge=60, le=3600)

    # Refresh tokens: opaque, rotated on every use, stored hashed in Redis.
    refresh_token_ttl_s: int = Field(default=14 * 24 * 3600, ge=300)  # idle timeout
    session_absolute_ttl_s: int = Field(default=30 * 24 * 3600, ge=300)  # hard cap per login
    refresh_reuse_grace_s: int = Field(default=10, ge=0, le=60)  # tolerated concurrent re-presentation

    # The single origin the browser talks to (Next.js). Used for Origin checks and OAuth redirect URIs.
    public_origin: str = "http://localhost:3000"
    cookie_secure: bool = True
    # Only enable when the API is reachable *only* through a proxy you control that sets X-Forwarded-For.
    trust_forwarded_for: bool = False

    google_client_id: str = ""
    google_client_secret: str = ""
    github_client_id: str = ""
    github_client_secret: str = ""
    oauth_state_ttl_s: int = Field(default=600, ge=60, le=1800)

    # Rate limits as "<count>/<window seconds>".
    rl_login_ip: str = "30/60"
    rl_login_email: str = "10/900"
    rl_register_ip: str = "10/3600"
    rl_refresh_ip: str = "120/60"
    rl_oauth_ip: str = "30/60"

    @field_validator("public_origin")
    @classmethod
    def _origin_shape(cls, v: str) -> str:
        parts = urlsplit(v)
        if parts.scheme not in ("http", "https") or not parts.netloc or parts.path not in ("", "/") or parts.query:
            raise ValueError("PUBLIC_ORIGIN must look like https://host[:port] with no path")
        return f"{parts.scheme}://{parts.netloc}"

    @field_validator("rl_login_ip", "rl_login_email", "rl_register_ip", "rl_refresh_ip", "rl_oauth_ip")
    @classmethod
    def _rl_shape(cls, v: str) -> str:
        count, _, window = v.partition("/")
        if not (count.isdigit() and window.isdigit() and int(count) > 0 and int(window) > 0):
            raise ValueError("rate limit must be '<count>/<seconds>'")
        return v

    @model_validator(mode="after")
    def _production_guards(self) -> "Settings":
        if self.app_env == "production":
            if not self.cookie_secure or not self.public_origin.startswith("https://"):
                raise ValueError("production requires COOKIE_SECURE=true and an https PUBLIC_ORIGIN")
        if self.session_absolute_ttl_s < self.access_token_ttl_s:
            raise ValueError("SESSION_ABSOLUTE_TTL_S must be >= ACCESS_TOKEN_TTL_S")
        return self

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
