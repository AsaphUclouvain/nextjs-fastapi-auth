import logging

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import Principal, current_principal
from ..models import User
from ..permissions import permissions_for
from ..schemas import LoginIn, RegisterIn
from ..security import cookies
from ..security.csrf import is_well_formed, new_csrf_token, verify_csrf
from ..security.passwords import hash_password, verify_password
from ..security.ratelimit import client_ip, enforce
from ..security.tokens import AuthError, IssuedTokens, TokenService
from ..services import user_by_email

log = logging.getLogger("auth")
router = APIRouter(prefix="/api/auth", tags=["auth"])


def user_view(user: User) -> dict:
    return {
        "id": user.id, "email": user.email, "displayName": user.display_name, "role": user.role,
        "permissions": sorted(permissions_for(user.role)),
        "linkedProviders": sorted(a.provider for a in user.oauth_accounts),
        "hasPassword": user.password_hash is not None,
    }


def revoke_presented_session(request: Request) -> None:
    """Revoke whatever login the browser currently presents (only if we can prove it is ours)."""
    s, tokens = request.app.state.settings, request.app.state.tokens
    names = cookies.cookie_names(s)
    fid = tokens.refresh_token_known(request.cookies.get(names.refresh))
    if fid is None and (access := request.cookies.get(names.access)):
        try:  # signature-checked; an expired access token may still identify the login to end
            fid = tokens.decode_access(access, check_exp=False)["sid"]
        except AuthError:
            fid = None
    if fid:
        tokens.revoke_family(fid)


def start_session(request: Request, response: Response, user: User) -> str:
    """Fresh family + fresh CSRF token on every login (session-fixation defence)."""
    s = request.app.state.settings
    revoke_presented_session(request)
    issued: IssuedTokens = request.app.state.tokens.create_session(user.id)
    cookies.set_access_cookie(response, s, issued.access_token)
    assert issued.refresh_token
    cookies.set_refresh_cookie(response, s, issued.refresh_token, issued.refresh_max_age)
    csrf = new_csrf_token()
    cookies.set_csrf_cookie(response, s, csrf)
    return csrf


@router.get("/csrf")
def get_csrf(request: Request, response: Response) -> dict:
    s = request.app.state.settings
    token = request.cookies.get(cookies.cookie_names(s).csrf)
    if not is_well_formed(token):
        token = new_csrf_token()
        cookies.set_csrf_cookie(response, s, token)
    return {"csrfToken": token}


@router.post("/register", status_code=status.HTTP_201_CREATED, dependencies=[Depends(verify_csrf)])
def register(body: RegisterIn, request: Request, response: Response, db: Session = Depends(get_db)) -> dict:
    enforce(request, "register_ip", client_ip(request), request.app.state.settings.rl_register_ip)
    email = body.email.strip().lower()
    # Known limitation: this reveals that an address is registered. Hiding it needs an e-mail
    # verification flow ("check your inbox" for both cases), which is out of scope here.
    if user_by_email(db, email) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "email_taken")
    user = User(email=email, display_name=body.display_name, password_hash=hash_password(body.password))
    db.add(user)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "email_taken") from exc
    db.refresh(user)
    csrf = start_session(request, response, user)
    return {"user": user_view(user), "csrfToken": csrf}


@router.post("/login", dependencies=[Depends(verify_csrf)])
def login(body: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)) -> dict:
    s = request.app.state.settings
    email = body.email.strip().lower()
    enforce(request, "login_ip", client_ip(request), s.rl_login_ip)
    enforce(request, "login_email", email, s.rl_login_email)  # slows targeted guessing on one account
    user = user_by_email(db, email)
    ok, new_hash = verify_password(user.password_hash if user and user.is_active else None, body.password)
    if not ok or user is None:
        log.info("login failed")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid_credentials")  # same answer for every cause
    if new_hash:
        user.password_hash = new_hash
        db.commit()
    csrf = start_session(request, response, user)
    return {"user": user_view(user), "csrfToken": csrf}


@router.post("/refresh", dependencies=[Depends(verify_csrf)], response_model=None)
def refresh(request: Request, response: Response, db: Session = Depends(get_db)) -> dict | JSONResponse:
    s = request.app.state.settings
    tokens: TokenService = request.app.state.tokens
    enforce(request, "refresh_ip", client_ip(request), s.rl_refresh_ip)
    result = tokens.rotate(request.cookies.get(cookies.cookie_names(s).refresh))
    if result.tokens is None:
        code = {"reuse": "refresh_reuse_detected", "expired": "session_expired"}.get(result.status, "invalid_refresh")
        return _auth_failure(s, code)
    user = db.get(User, result.user_id)
    if user is None or not user.is_active:
        tokens.revoke_family(result.tokens.family_id)
        return _auth_failure(s, "invalid_refresh")
    cookies.set_access_cookie(response, s, result.tokens.access_token)
    if result.tokens.refresh_token:  # "grace": a parallel request already rotated; keep its cookie
        cookies.set_refresh_cookie(response, s, result.tokens.refresh_token, result.tokens.refresh_max_age)
    return {"ok": True, "accessExpiresAt": result.tokens.access_expires_at, "rotated": result.status == "rotated"}


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(verify_csrf)])
def logout(request: Request, response: Response) -> Response:
    revoke_presented_session(request)
    cookies.clear_auth_cookies(response, request.app.state.settings)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.post("/logout-all", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(verify_csrf)])
def logout_all(request: Request, response: Response, principal: Principal = Depends(current_principal)) -> Response:
    request.app.state.tokens.revoke_all(principal.user.id)
    cookies.clear_auth_cookies(response, request.app.state.settings)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


def _auth_failure(settings, code: str) -> JSONResponse:
    # A returned response (rather than a raised HTTPException) keeps the cookie-clearing headers.
    resp = JSONResponse({"detail": code}, status_code=status.HTTP_401_UNAUTHORIZED)
    cookies.clear_auth_cookies(resp, settings)
    return resp
