import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine

from app.db import Base
from app.models import User
from app.permissions import permissions_for
from app.security.redirects import safe_next

from .conftest import login, new_client, register


def make_admin(app, email="alice@example.com"):
    with app.state.SessionLocal() as db:
        db.query(User).filter_by(email=email).one().role = "admin"
        db.commit()


def test_guest_dashboard_is_public(client):
    r = client.get("/api/dashboard/guest")
    assert r.status_code == 200 and r.json()["cards"]


def test_user_dashboard_requires_auth(client):
    assert client.get("/api/dashboard").status_code == 401
    assert client.get("/api/me").json()["detail"] == "not_authenticated"
    register(client)
    assert client.get("/api/dashboard").status_code == 200


def test_user_cannot_reach_admin_endpoints(client):
    register(client)
    assert client.get("/api/admin/reports").status_code == 403
    assert client.get("/api/admin/users").status_code == 403


def test_role_change_applies_immediately_without_new_token(client, app):
    register(client)
    assert client.get("/api/admin/users").status_code == 403
    make_admin(app)
    r = client.get("/api/admin/users")  # same access token: roles are read from the DB
    assert r.status_code == 200 and r.json()["users"][0]["email"] == "alice@example.com"
    assert client.get("/api/admin/reports").json() == {"users": 1, "admins": 1}


def test_unknown_role_has_no_permissions():
    assert permissions_for("superuser") == frozenset()
    assert "users:read" not in permissions_for("user")


@pytest.mark.parametrize("value,expected", [
    ("/dashboard", "/dashboard"), ("/a/b?c=d#e", "/a/b?c=d#e"), (None, "/dashboard"), ("", "/dashboard"),
    ("//evil.com", "/dashboard"), ("/\\evil.com", "/dashboard"), ("https://evil.com", "/dashboard"),
    ("javascript:alert(1)", "/dashboard"), ("/ok\r\nSet-Cookie: a=b", "/dashboard"), ("/\tevil", "/dashboard"),
    ("dashboard", "/dashboard"), ("/" + "a" * 600, "/dashboard"),
])
def test_safe_next(value, expected):
    assert safe_next(value) == expected


def test_migrations_match_models(tmp_path):
    url = f"sqlite:///{tmp_path}/mig.db"
    cfg = Config("alembic.ini")
    cfg.attributes["url"] = url
    command.upgrade(cfg, "head")
    engine = create_engine(url)
    with engine.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    assert diff == []
    command.downgrade(cfg, "base")


def test_production_settings_guard():
    from app.config import Settings
    with pytest.raises(ValueError):
        Settings(_env_file=None, app_env="production", jwt_secret="x" * 48, cookie_secure=False)
    with pytest.raises(ValueError):
        Settings(_env_file=None, jwt_secret="short")
    with pytest.raises(ValueError):
        Settings(_env_file=None, jwt_secret="x" * 48, public_origin="https://app.example/path")


def test_trust_forwarded_for_off_by_default(client, app):
    """A spoofed X-Forwarded-For must not let an attacker dodge the per-IP limit."""
    codes = []
    for i in range(11):
        c = new_client(app)
        c.headers["X-Forwarded-For"] = f"10.0.0.{i}"
        codes.append(register(c, email=f"x{i}@example.com").status_code)
    assert codes[-1] == 429


def test_login_after_register_in_new_browser(client, app):
    register(client)
    other = new_client(app)
    assert login(other).status_code == 200
    assert other.get("/api/dashboard").status_code == 200
