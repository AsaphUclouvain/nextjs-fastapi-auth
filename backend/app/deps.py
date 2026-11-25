from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from .db import get_db
from .models import User
from .permissions import permissions_for
from .security.cookies import cookie_names
from .security.tokens import AuthError, TokenService


@dataclass(frozen=True)
class Principal:
    user: User
    family_id: str
    permissions: frozenset[str]


def get_tokens(request: Request) -> TokenService:
    return request.app.state.tokens


def current_principal(request: Request, db: Session = Depends(get_db)) -> Principal:
    token = request.cookies.get(cookie_names(request.app.state.settings).access)
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "not_authenticated")
    try:
        claims = request.app.state.tokens.verify_access(token)
    except AuthError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, exc.code) from exc
    user = db.get(User, claims["sub"])
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid_token")
    return Principal(user, claims["sid"], permissions_for(user.role))


def require_permission(permission: str):
    def _dep(principal: Principal = Depends(current_principal)) -> Principal:
        if permission not in principal.permissions:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "forbidden")
        return principal

    return _dep
