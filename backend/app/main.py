import logging
import time
from collections.abc import Callable

import httpx
import jwt
import redis
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.orm import sessionmaker

from .config import Settings, get_settings
from .db import make_engine
from .oauth.providers import GitHubProvider, GoogleProvider, JWKSClient
from .oauth.state import OAuthStateStore
from .routers import auth, dashboard, oauth
from .security.headers import install_security_headers
from .security.ratelimit import RateLimiter
from .security.tokens import TokenService


def create_app(
    settings: Settings | None = None,
    *,
    redis_client: redis.Redis | None = None,
    http_client: httpx.Client | None = None,
    google_jwks: JWKSClient | None = None,
    clock: Callable[[], float] = time.time,
) -> FastAPI:
    settings = settings or get_settings()
    logging.basicConfig(level=logging.INFO)
    app = FastAPI(
        title="authapp API",
        docs_url=None if settings.is_production else "/api/docs",
        redoc_url=None,
        openapi_url=None if settings.is_production else "/api/openapi.json",
    )
    app.state.settings = settings
    engine = make_engine(settings.database_url)
    app.state.engine = engine
    app.state.SessionLocal = sessionmaker(engine, expire_on_commit=False)
    r = redis_client or redis.Redis.from_url(settings.redis_url, decode_responses=True)
    app.state.redis = r
    app.state.tokens = TokenService(settings, r, clock)
    app.state.ratelimiter = RateLimiter(r, settings.redis_prefix, clock)
    app.state.oauth_states = OAuthStateStore(r, settings.redis_prefix, settings.oauth_state_ttl_s)
    # No redirects followed, explicit timeouts: a slow provider cannot pin workers forever.
    http = http_client or httpx.Client(timeout=httpx.Timeout(10.0), follow_redirects=False)
    jwks = google_jwks or jwt.PyJWKClient(GoogleProvider.JWKS_URL, cache_keys=True, lifespan=3600, timeout=10)
    app.state.providers = {
        "google": GoogleProvider(settings, http, jwks),
        "github": GitHubProvider(settings, http),
    }

    @app.exception_handler(RequestValidationError)
    async def _validation_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
        # FastAPI's default 422 echoes the submitted values back (`input`) - that would include
        # the password. Return only where and what, never the value.
        errors = [{"loc": [str(p) for p in e.get("loc", ())], "msg": e.get("msg", "invalid")} for e in exc.errors()]
        return JSONResponse({"detail": "validation_error", "errors": errors}, status_code=422)

    install_security_headers(app, settings)
    app.include_router(auth.router)
    app.include_router(oauth.router)
    app.include_router(dashboard.router)

    @app.get("/api/health")
    def health() -> dict:
        return {"ok": True}

    return app


def app_factory() -> FastAPI:  # `uvicorn app.main:app_factory --factory`
    return create_app()
