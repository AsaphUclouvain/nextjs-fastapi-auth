"""Sample data. Each endpoint states the permission it needs; the frontend only mirrors this."""

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import Principal, current_principal, require_permission
from ..models import User
from .auth import user_view

router = APIRouter(prefix="/api", tags=["dashboard"])


@router.get("/dashboard/guest")
def guest_dashboard() -> dict:
    return {
        "title": "Public overview",
        "cards": [
            {"label": "Open tasks (demo)", "value": 42},
            {"label": "Uptime this month (demo)", "value": "99.95%"},
            {"label": "Docs pages", "value": 18},
        ],
        "cta": "Sign in to see your own tasks.",
    }


@router.get("/me")
def me(principal: Principal = Depends(current_principal)) -> dict:
    return user_view(principal.user)


@router.get("/dashboard")
def user_dashboard(principal: Principal = Depends(require_permission("dashboard:read"))) -> dict:
    name = principal.user.display_name
    return {
        "title": f"Welcome back, {name}",  # rendered as text by React, never as HTML
        "tasks": [
            {"id": 1, "title": "Review pull request #12", "done": False},
            {"id": 2, "title": "Write auth tests", "done": True},
            {"id": 3, "title": "Rotate OAuth client secret", "done": False},
        ],
    }


@router.get("/admin/reports")
def admin_reports(_: Principal = Depends(require_permission("reports:read")),
                  db: Session = Depends(get_db)) -> dict:
    total = db.scalar(select(func.count()).select_from(User)) or 0
    admins = db.scalar(select(func.count()).select_from(User).where(User.role == "admin")) or 0
    return {"users": total, "admins": admins}


@router.get("/admin/users")
def admin_users(_: Principal = Depends(require_permission("users:read")),
                db: Session = Depends(get_db)) -> dict:
    users = db.scalars(select(User).order_by(User.created_at).limit(100)).all()
    return {"users": [{"id": u.id, "email": u.email, "role": u.role, "active": u.is_active} for u in users]}
