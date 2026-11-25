from urllib.parse import parse_qs, urlsplit

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from app.models import OAuthAccount, User

from .conftest import (GOOGLE_CLIENT_ID, cookie, new_client, oauth_start, pkce_challenge, post, register,
                       set_cookie)


def callback(client, provider, state, code="auth-code-123", **extra):
    params = {"code": code, "state": state, **extra}
    return client.get(f"/api/auth/oauth/{provider}/callback", params=params)


def error_of(resp) -> str | None:
    assert resp.status_code == 302
    loc = resp.headers["location"]
    return parse_qs(urlsplit(loc).query).get("error", [None])[0] if loc.startswith("/login") else None


def users(app):
    with app.state.SessionLocal() as db:
        return db.query(User).all(), db.query(OAuthAccount).all()


# ---- Google -------------------------------------------------------------------------------
def test_google_start_uses_pkce_s256_state_nonce(client):
    q = oauth_start(client, "google")
    assert q["_location"].startswith("https://accounts.google.com/o/oauth2/v2/auth?")
    assert q["code_challenge_method"] == "S256" and len(q["code_challenge"]) == 43
    assert len(q["state"]) >= 43 and len(q["nonce"]) >= 43
    assert q["redirect_uri"] == "http://localhost:3000/api/auth/oauth/google/callback"
    assert q["scope"] == "openid email profile" and q["client_id"] == GOOGLE_CLIENT_ID
    assert cookie(client, "__Host-oauth_bind")


def test_google_happy_path_creates_user_and_session(client, providers, app):
    q = oauth_start(client, "google", next_path="/dashboard?tab=1")
    providers.google_id_token = providers.make_id_token(nonce=q["nonce"])
    r = callback(client, "google", q["state"])
    assert r.status_code == 302 and r.headers["location"] == "/dashboard?tab=1"
    form = providers.form_of("https://oauth2.googleapis.com/token")
    assert pkce_challenge(form["code_verifier"]) == q["code_challenge"]  # verifier matches challenge
    assert form["redirect_uri"] == q["redirect_uri"]
    me = client.get("/api/me").json()
    assert me["email"] == "gina@example.com" and me["linkedProviders"] == ["google"] and me["hasPassword"] is False
    assert cookie(client, "__Host-oauth_bind") is None  # cleared
    # second login with the same Google subject -> same user, no duplicate
    q2 = oauth_start(client, "google")
    providers.google_id_token = providers.make_id_token(nonce=q2["nonce"], email="gina.new@example.com")
    callback(client, "google", q2["state"])
    all_users, accounts = users(app)
    assert len(all_users) == 1 and len(accounts) == 1


@pytest.mark.parametrize("override", [
    {"aud": "someone-elses-client"},
    {"iss": "https://evil.example"},
    {"exp_in": -120},
    {"key": rsa.generate_private_key(public_exponent=65537, key_size=2048)},  # bad signature
    {"kid": "unknown-kid"},
    {"extra": {"azp": "another-client"}},
])
def test_google_id_token_validation(client, providers, override, app):
    q = oauth_start(client, "google")
    providers.google_id_token = providers.make_id_token(nonce=q["nonce"], **override)
    assert error_of(callback(client, "google", q["state"])) == "invalid_id_token"
    assert users(app)[0] == [] and cookie(client, "__Host-access") is None


def test_google_nonce_mismatch(client, providers):
    q = oauth_start(client, "google")
    providers.google_id_token = providers.make_id_token(nonce="attacker-chosen-nonce")
    assert error_of(callback(client, "google", q["state"])) == "invalid_id_token"


def test_google_hs256_key_confusion_rejected(client, providers):
    import jwt as pyjwt
    q = oauth_start(client, "google")
    providers.google_id_token = pyjwt.encode(
        {"iss": "https://accounts.google.com", "aud": GOOGLE_CLIENT_ID, "sub": "x", "nonce": q["nonce"],
         "iat": 1, "exp": 9999999999}, "g-secret", algorithm="HS256", headers={"kid": "test-kid"})
    assert error_of(callback(client, "google", q["state"])) == "invalid_id_token"


def test_google_unverified_email_not_accepted(client, providers):
    q = oauth_start(client, "google")
    providers.google_id_token = providers.make_id_token(nonce=q["nonce"], email_verified=False)
    assert error_of(callback(client, "google", q["state"])) == "email_unverified"


def test_google_token_endpoint_error(client, providers):
    q = oauth_start(client, "google")
    providers.google_status = 400
    assert error_of(callback(client, "google", q["state"])) == "token_exchange_failed"


def test_auth_response_iss_mismatch_rejected(client, providers):
    q = oauth_start(client, "google")
    providers.google_id_token = providers.make_id_token(nonce=q["nonce"])
    assert error_of(callback(client, "google", q["state"], iss="https://evil.example")) == "oauth_state_invalid"


# ---- state / binding ----------------------------------------------------------------------
def test_state_bound_to_browser_login_csrf(client, providers, app):
    """Attacker starts a flow, then lures the victim to the callback with the attacker's code+state."""
    q = oauth_start(client, "google")  # attacker's browser
    providers.google_id_token = providers.make_id_token(nonce=q["nonce"], sub="attacker")
    victim = new_client(app)
    assert error_of(callback(victim, "google", q["state"])) == "oauth_state_invalid"
    assert cookie(victim, "__Host-access") is None


def test_state_is_single_use(client, providers):
    q = oauth_start(client, "google")
    providers.google_id_token = providers.make_id_token(nonce=q["nonce"])
    bind = cookie(client, "__Host-oauth_bind")
    assert error_of(callback(client, "google", q["state"])) is None
    set_cookie(client, "__Host-oauth_bind", bind)
    assert error_of(callback(client, "google", q["state"])) == "oauth_state_invalid"


def test_state_for_other_provider_rejected(client, providers):
    q = oauth_start(client, "github")
    assert error_of(callback(client, "google", q["state"])) == "oauth_state_invalid"


def test_missing_or_garbage_state(client):
    oauth_start(client, "google")
    assert error_of(client.get("/api/auth/oauth/google/callback?code=x")) == "oauth_state_invalid"
    assert error_of(callback(client, "google", "x" * 300)) == "oauth_state_invalid"


def test_provider_error_param_not_reflected(client):
    q = oauth_start(client, "google")
    r = client.get("/api/auth/oauth/google/callback", params={"state": q["state"], "error": "<script>alert(1)</script>"})
    assert error_of(r) == "oauth_denied" and "script" not in r.headers["location"]


@pytest.mark.parametrize("evil", ["//evil.example", "https://evil.example", "/\\evil.example", "/\r\nSet-Cookie:x=y",
                                  "javascript:alert(1)"])
def test_open_redirect_blocked(client, providers, evil):
    r = client.get("/api/auth/oauth/google/start", params={"next": evil})
    q = {k: v[0] for k, v in parse_qs(urlsplit(r.headers["location"]).query).items()}
    providers.google_id_token = providers.make_id_token(nonce=q["nonce"])
    resp = callback(client, "google", q["state"])
    assert resp.headers["location"] == "/dashboard"


def test_unknown_provider(client):
    assert client.get("/api/auth/oauth/facebook/start").status_code == 404


def test_unconfigured_provider(app, client):
    app.state.settings.github_client_secret = ""
    assert client.get("/api/auth/oauth/github/start").status_code == 503


# ---- account linking policy -----------------------------------------------------------------
def test_no_auto_link_to_existing_password_account(client, providers, app):
    """Pre-account-takeover: someone registered the victim's address with a password first."""
    register(client, email="gina@example.com")
    victim = new_client(app)
    q = oauth_start(victim, "google")
    providers.google_id_token = providers.make_id_token(nonce=q["nonce"], email="gina@example.com")
    assert error_of(callback(victim, "google", q["state"])) == "account_exists"
    assert users(app)[1] == []


def test_explicit_link_while_signed_in(client, providers, app):
    register(client, email="alice@example.com")
    r = post(client, "/api/auth/oauth/github/link")
    assert r.status_code == 200
    q = {k: v[0] for k, v in parse_qs(urlsplit(r.json()["authorizationUrl"]).query).items()}
    providers.github_emails = [{"email": "other@example.com", "primary": True, "verified": True}]
    resp = callback(client, "github", q["state"])
    assert resp.headers["location"] == "/dashboard"
    assert client.get("/api/me").json()["linkedProviders"] == ["github"]
    # and now GitHub alone signs in to the same account
    fresh = new_client(app)
    q2 = oauth_start(fresh, "github")
    callback(fresh, "github", q2["state"])
    assert fresh.get("/api/me").json()["email"] == "alice@example.com"


def test_link_requires_auth_and_csrf(client):
    assert post(client, "/api/auth/oauth/github/link").status_code == 401
    register(client)
    r = client.post("/api/auth/oauth/github/link", headers={"Origin": "http://localhost:3000"})
    assert r.status_code == 403


def test_cannot_link_identity_owned_by_someone_else(client, providers, app):
    owner = new_client(app)
    q = oauth_start(owner, "github")
    callback(owner, "github", q["state"])  # octo (id 1001) now owns that GitHub identity
    register(client, email="mallory@example.com")
    r = post(client, "/api/auth/oauth/github/link")
    q2 = {k: v[0] for k, v in parse_qs(urlsplit(r.json()["authorizationUrl"]).query).items()}
    assert error_of(callback(client, "github", q2["state"])) == "identity_linked_elsewhere"


# ---- GitHub -------------------------------------------------------------------------------
def test_github_happy_path_uses_numeric_id(client, providers, app):
    q = oauth_start(client, "github")
    assert q["code_challenge_method"] == "S256" and q["scope"] == "read:user user:email"
    r = callback(client, "github", q["state"])
    assert r.headers["location"] == "/dashboard"
    form = providers.form_of("https://github.com/login/oauth/access_token")
    assert pkce_challenge(form["code_verifier"]) == q["code_challenge"]
    _, accounts = users(app)
    assert accounts[0].subject == "1001"
    # user renames their GitHub login: still the same account
    providers.github_user = {"id": 1001, "login": "renamed"}
    other = new_client(app)
    q2 = oauth_start(other, "github")
    callback(other, "github", q2["state"])
    assert other.get("/api/me").json()["email"] == "octo@example.com"
    assert len(users(app)[0]) == 1


def test_github_requires_verified_primary_email(client, providers):
    providers.github_emails = [{"email": "octo@example.com", "primary": True, "verified": False},
                               {"email": "alt@example.com", "primary": False, "verified": True}]
    q = oauth_start(client, "github")
    assert error_of(callback(client, "github", q["state"])) == "email_unverified"


def test_github_error_in_200_response(client, providers):
    providers.github_token_response = {"error": "bad_verification_code"}
    q = oauth_start(client, "github")
    assert error_of(callback(client, "github", q["state"])) == "token_exchange_failed"


def test_github_bad_profile(client, providers):
    providers.github_user = {"id": "1001", "login": "string-id"}
    q = oauth_start(client, "github")
    assert error_of(callback(client, "github", q["state"])) == "profile_fetch_failed"
