"""Test harness.

Every test runs twice: against fakeredis (with real Lua via lupa) and against a real
redis-server if TEST_REDIS_URL is set (e.g. redis://localhost:6379/15 - that DB is flushed!).
Outbound HTTP to Google/GitHub is replaced by httpx.MockTransport; Google's JWKS by a local RSA key.
"""

import base64
import hashlib
import os
import time
from dataclasses import dataclass, field
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import fakeredis
import httpx
import jwt
import pytest
import redis
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app.config import Settings
from app.db import Base
from app.main import create_app

ORIGIN = "http://localhost:3000"
GOOGLE_CLIENT_ID = "test-client.apps.googleusercontent.com"
PASSWORD = "correct horse battery staple"


class FakeClock:
    def __init__(self) -> None:
        self.t = float(int(time.time()))

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


class FakeJWKS:
    def __init__(self, key, kid="test-kid"):
        self.key, self.kid = key, kid

    def get_signing_key_from_jwt(self, token):
        header = jwt.get_unverified_header(token)
        if header.get("kid") != self.kid:
            raise jwt.PyJWKClientError("unknown kid")
        return SimpleNamespace(key=self.key.public_key())


@dataclass
class FakeProviders:
    """Scriptable Google + GitHub endpoints. Records requests for assertions."""
    google_key: rsa.RSAPrivateKey
    google_id_token: str | None = None
    google_status: int = 200
    github_token_response: dict = field(default_factory=lambda: {"access_token": "gho_test", "token_type": "bearer"})
    github_user: dict = field(default_factory=lambda: {"id": 1001, "login": "octo", "name": "Octo Cat"})
    github_emails: list = field(default_factory=lambda: [{"email": "octo@example.com", "primary": True, "verified": True}])
    requests: list = field(default_factory=list)

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        url = str(request.url)
        if url == "https://oauth2.googleapis.com/token":
            return httpx.Response(self.google_status, json={"id_token": self.google_id_token, "access_token": "ya29"})
        if url == "https://github.com/login/oauth/access_token":
            return httpx.Response(200, json=self.github_token_response)
        if url == "https://api.github.com/user":
            return httpx.Response(200, json=self.github_user)
        if url == "https://api.github.com/user/emails":
            return httpx.Response(200, json=self.github_emails)
        return httpx.Response(404)

    def form_of(self, url: str) -> dict:
        req = next(r for r in reversed(self.requests) if str(r.url) == url)
        return {k: v[0] for k, v in parse_qs(req.content.decode()).items()}

    def make_id_token(self, *, nonce: str, sub="google-sub-1", email="gina@example.com", email_verified=True,
                      aud=GOOGLE_CLIENT_ID, iss="https://accounts.google.com", exp_in=3600, key=None,
                      kid="test-kid", alg="RS256", extra=None) -> str:
        now = int(time.time())
        claims = {"iss": iss, "aud": aud, "sub": sub, "email": email, "email_verified": email_verified,
                  "name": "Gina", "nonce": nonce, "iat": now, "exp": now + exp_in, **(extra or {})}
        return jwt.encode(claims, key or self.google_key, algorithm=alg, headers={"kid": kid})


_GOOGLE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(params=["fakeredis", "redis-server"])
def redis_client(request):
    if request.param == "fakeredis":
        client = fakeredis.FakeRedis(decode_responses=True)
    else:
        url = os.environ.get("TEST_REDIS_URL")
        if not url:
            pytest.skip("TEST_REDIS_URL not set")
        client = redis.Redis.from_url(url, decode_responses=True)
    client.flushdb()
    yield client
    client.flushdb()


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        _env_file=None, app_env="test", database_url=f"sqlite:///{tmp_path}/test.db",
        jwt_secret="t" * 48, public_origin=ORIGIN, cookie_secure=True,
        google_client_id=GOOGLE_CLIENT_ID, google_client_secret="g-secret",
        github_client_id="gh-client", github_client_secret="gh-secret",
        access_token_ttl_s=600, refresh_token_ttl_s=3600, session_absolute_ttl_s=7200,
        refresh_reuse_grace_s=10,
    )


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def providers() -> FakeProviders:
    return FakeProviders(google_key=_GOOGLE_KEY)


@pytest.fixture
def app(settings, redis_client, clock, providers):
    application = create_app(settings, redis_client=redis_client, clock=clock,
                             http_client=httpx.Client(transport=httpx.MockTransport(providers.handler)),
                             google_jwks=FakeJWKS(_GOOGLE_KEY))
    Base.metadata.create_all(application.state.engine)
    return application


def new_client(app) -> TestClient:
    # https base URL so the Secure cookies are stored and sent back by the test cookie jar.
    return TestClient(app, base_url="https://testserver", follow_redirects=False)


@pytest.fixture
def client(app) -> TestClient:
    return new_client(app)


# ---- helpers ------------------------------------------------------------------------------
def csrf(client: TestClient) -> str:
    return client.get("/api/auth/csrf").json()["csrfToken"]


def post(client: TestClient, url: str, json=None, *, token: str | None = None, origin: str | None = ORIGIN):
    headers = {}
    if origin:
        headers["Origin"] = origin
    headers["X-CSRF-Token"] = token if token is not None else csrf(client)
    return client.post(url, json=json, headers=headers)


def register(client: TestClient, email="alice@example.com", password=PASSWORD, name="Alice"):
    return post(client, "/api/auth/register", {"email": email, "password": password, "display_name": name})


def login(client: TestClient, email="alice@example.com", password=PASSWORD):
    return post(client, "/api/auth/login", {"email": email, "password": password})


def cookie(client: TestClient, name: str) -> str | None:
    for c in client.cookies.jar:
        if c.name == name:
            return c.value
    return None


def set_cookie(client: TestClient, name: str, value: str, path: str = "/") -> None:
    # replace any existing value regardless of path
    for c in list(client.cookies.jar):
        if c.name == name:
            client.cookies.jar.clear(c.domain, c.path, c.name)
    client.cookies.set(name, value, domain="testserver.local", path=path)


def pkce_challenge(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


def oauth_start(client: TestClient, provider: str, next_path: str | None = "/dashboard") -> dict:
    url = f"/api/auth/oauth/{provider}/start" + (f"?next={next_path}" if next_path is not None else "")
    r = client.get(url)
    assert r.status_code == 302, r.text
    q = {k: v[0] for k, v in parse_qs(urlsplit(r.headers["location"]).query).items()}
    q["_location"] = r.headers["location"]
    return q
