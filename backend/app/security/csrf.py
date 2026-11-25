"""CSRF defence for every state-changing request.

Two independent checks (OWASP CSRF cheat sheet: "defence in depth"):
1. Origin (or Referer) must equal PUBLIC_ORIGIN exactly.
2. Double-submit token: the X-CSRF-Token header must equal the HttpOnly __Host-csrf cookie.
   JavaScript gets the value from GET /api/auth/csrf (same-origin only: there is no CORS, so a
   foreign site cannot read that response). The token is rotated at every login.
SameSite=Strict on the auth cookies is a third, browser-side layer.
"""

import hmac
import re
import secrets
from urllib.parse import urlsplit

from fastapi import HTTPException, Request, status

from ..config import Settings
from .cookies import cookie_names

_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)  # 43 chars


def is_well_formed(token: str | None) -> bool:
    return bool(token and _TOKEN_RE.match(token))


def _origin_of(url: str) -> str | None:
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    return f"{parts.scheme}://{parts.netloc}" if parts.scheme and parts.netloc else None


def verify_csrf(request: Request) -> None:
    settings: Settings = request.app.state.settings
    origin = request.headers.get("origin")
    if origin is None and (referer := request.headers.get("referer")):
        origin = _origin_of(referer)
    if origin != settings.public_origin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "bad_origin")
    cookie = request.cookies.get(cookie_names(settings).csrf)
    header = request.headers.get("x-csrf-token")
    if not (is_well_formed(cookie) and header and hmac.compare_digest(cookie.encode(), header.encode())):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "csrf_failed")
