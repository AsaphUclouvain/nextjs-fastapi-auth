"""Authorization-code flow with PKCE (S256), state bound to the browser, OIDC nonce for Google.

Start:    random state, PKCE verifier, nonce and a binding secret. Server keeps everything in Redis
          under sha256(state); the browser gets the binding secret in an HttpOnly cookie.
Callback: state is consumed atomically (single use), the binding cookie must match (so an
          attacker cannot make a victim finish the attacker's login = login CSRF), the provider
          must match (distinct redirect URIs per provider also defend against mix-up attacks),
          then the code is exchanged together with the PKCE verifier.
"""

import hmac
import logging
import secrets
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import Principal, current_principal
from ..oauth.providers import OAuthError
from ..oauth.state import OAuthTransaction, pkce_pair, sha256_hex
from ..security import cookies
from ..security.csrf import verify_csrf
from ..security.ratelimit import client_ip, enforce
from ..security.redirects import safe_next
from ..services import resolve_oauth_user
from .auth import start_session

log = logging.getLogger("auth.oauth")
router = APIRouter(prefix="/api/auth/oauth", tags=["oauth"])

# Only these fixed codes are ever put in the URL; nothing provider-supplied is reflected.
ERROR_CODES = {
    "oauth_denied", "oauth_state_invalid", "token_exchange_failed", "invalid_id_token",
    "profile_fetch_failed", "provider_unreachable", "email_unverified", "account_exists",
    "identity_linked_elsewhere", "provider_already_linked", "account_disabled", "oauth_failed",
}


def _provider(request: Request, name: str):
    provider = request.app.state.providers.get(name)
    if provider is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown_provider")
    if not provider.configured:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "provider_not_configured")
    return provider


def _redirect_uri(request: Request, provider: str) -> str:
    # Built from configuration, never from the Host header (host-header injection).
    return f"{request.app.state.settings.public_origin}/api/auth/oauth/{provider}/callback"


def _begin(request: Request, provider_name: str, *, next_path: str, mode: str, link_user_id: str | None):
    provider = _provider(request, provider_name)
    enforce(request, "oauth_ip", client_ip(request), request.app.state.settings.rl_oauth_ip)
    state, nonce, binding = secrets.token_urlsafe(32), secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    verifier, challenge = pkce_pair()
    request.app.state.oauth_states.save(state, OAuthTransaction(
        provider=provider_name, code_verifier=verifier, nonce=nonce, next_path=safe_next(next_path),
        mode=mode, link_user_id=link_user_id, binding_hash=sha256_hex(binding)))
    url = provider.authorization_url(state=state, code_challenge=challenge, nonce=nonce,
                                     redirect_uri=_redirect_uri(request, provider_name))
    return url, binding


@router.get("/{provider}/start")
def start(provider: str, request: Request, next: str | None = None) -> RedirectResponse:
    url, binding = _begin(request, provider, next_path=next or "", mode="login", link_user_id=None)
    resp = RedirectResponse(url, status_code=status.HTTP_302_FOUND)
    cookies.set_oauth_bind_cookie(resp, request.app.state.settings, binding)
    return resp


@router.post("/{provider}/link", dependencies=[Depends(verify_csrf)])
def link(provider: str, request: Request, principal: Principal = Depends(current_principal)):
    """Linking needs an authenticated, CSRF-checked POST, so a third party cannot attach *their*
    provider identity to a victim's account (which would give them a way in)."""
    url, binding = _begin(request, provider, next_path="/dashboard", mode="link", link_user_id=principal.user.id)
    resp = JSONResponse({"authorizationUrl": url})
    cookies.set_oauth_bind_cookie(resp, request.app.state.settings, binding)
    return resp


def _fail(request: Request, code: str) -> RedirectResponse:
    code = code if code in ERROR_CODES else "oauth_failed"
    resp = RedirectResponse("/login?" + urlencode({"error": code}), status_code=status.HTTP_302_FOUND)
    cookies.clear_oauth_bind_cookie(resp, request.app.state.settings)
    return resp


@router.get("/{provider}/callback")
def callback(provider: str, request: Request, db: Session = Depends(get_db),
             code: str | None = None, state: str | None = None, error: str | None = None,
             iss: str | None = None) -> RedirectResponse:
    s = request.app.state.settings
    prov = request.app.state.providers.get(provider)
    if prov is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown_provider")

    tx = request.app.state.oauth_states.pop(state)  # consumed even if anything below fails
    binding = request.cookies.get(cookies.cookie_names(s).oauth_bind)
    if (tx is None or tx.provider != provider or not binding
            or not hmac.compare_digest(tx.binding_hash, sha256_hex(binding))):
        log.warning("oauth state rejected provider=%s", provider)
        return _fail(request, "oauth_state_invalid")
    if error:
        return _fail(request, "oauth_denied")
    if iss is not None and prov.auth_response_iss is not None and iss != prov.auth_response_iss:
        return _fail(request, "oauth_state_invalid")  # RFC 9207 mix-up defence
    if not code or len(code) > 2048:
        return _fail(request, "oauth_state_invalid")

    try:
        ident = prov.exchange(code=code, code_verifier=tx.code_verifier,
                              redirect_uri=_redirect_uri(request, provider), nonce=tx.nonce)
        user = resolve_oauth_user(db, ident, link_user_id=tx.link_user_id if tx.mode == "link" else None)
    except OAuthError as exc:
        log.info("oauth login failed provider=%s code=%s", provider, exc.code)
        return _fail(request, exc.code)

    if tx.mode == "link":
        resp = RedirectResponse(tx.next_path, status_code=status.HTTP_302_FOUND)
        cookies.clear_oauth_bind_cookie(resp, s)
        return resp  # linking does not change the current login
    resp = RedirectResponse(tx.next_path, status_code=status.HTTP_302_FOUND)
    start_session(request, resp, user)
    cookies.clear_oauth_bind_cookie(resp, s)
    return resp
