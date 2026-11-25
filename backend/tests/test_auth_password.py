from app.security.passwords import hash_password, verify_password

from .conftest import PASSWORD, ORIGIN, cookie, csrf, login, new_client, post, register


def test_register_sets_session_and_returns_user(client):
    r = register(client)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["user"]["email"] == "alice@example.com"
    assert body["user"]["role"] == "user"
    assert "password" not in r.text and "hash" not in r.text.lower().replace("haspassword", "")
    assert cookie(client, "__Host-access") and cookie(client, "__Secure-refresh")
    assert client.get("/api/me").json()["email"] == "alice@example.com"


def test_cookie_flags(client):
    r = register(client)
    raw = r.headers.get_list("set-cookie")
    access = next(c for c in raw if c.startswith("__Host-access="))
    refresh = next(c for c in raw if c.startswith("__Secure-refresh="))
    for c in (access, refresh):
        low = c.lower()
        assert "httponly" in low and "secure" in low and "samesite=strict" in low
    assert "path=/;" in access.lower() or access.lower().endswith("path=/")
    assert "path=/api/auth" in refresh.lower()
    assert "domain=" not in access.lower()


def test_email_is_normalised_and_unique(client):
    assert register(client, email="Bob@Example.COM").status_code == 201
    other = new_client(client.app)
    r = register(other, email="bob@example.com")
    assert r.status_code == 409 and r.json()["detail"] == "email_taken"


def test_weak_or_invalid_input_rejected_without_echo(client):
    r = register(client, password="short")
    assert r.status_code == 422
    assert "short" not in r.text  # the submitted password is never echoed back
    assert register(client, email="not-an-email").status_code == 422
    assert register(client, password="x" * 129).status_code == 422
    assert register(client, name="bad\u0000name").status_code == 422
    assert register(client, password=" " * 12).status_code == 422


def test_mass_assignment_of_role_is_rejected(client):
    r = post(client, "/api/auth/register", {"email": "eve@example.com", "password": PASSWORD,
                                            "display_name": "Eve", "role": "admin"})
    assert r.status_code == 422


def test_login_success_and_generic_failures(client):
    register(client)
    anon = new_client(client.app)
    wrong = login(anon, password="wrong password!!")
    unknown = login(anon, email="nobody@example.com")
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json() == {"detail": "invalid_credentials"}
    ok = login(anon, email="ALICE@example.com")
    assert ok.status_code == 200
    assert anon.get("/api/me").status_code == 200


def test_oauth_only_account_cannot_password_login(client, app):
    from app.models import User
    with app.state.SessionLocal() as db:
        db.add(User(email="oauth@example.com", display_name="O", password_hash=None, email_verified=True))
        db.commit()
    assert login(client, email="oauth@example.com", password="anything-at-all").status_code == 401


def test_disabled_user_cannot_login_and_tokens_stop_working(client, app):
    from app.models import User
    register(client)
    with app.state.SessionLocal() as db:
        u = db.query(User).one()
        u.is_active = False
        db.commit()
    assert client.get("/api/me").status_code == 401
    assert login(new_client(app)).status_code == 401


def test_password_hashing():
    h = hash_password(PASSWORD)
    assert h.startswith("$argon2id$") and PASSWORD not in h
    assert verify_password(h, PASSWORD) == (True, None)
    assert verify_password(h, PASSWORD + "x")[0] is False
    assert verify_password("not-a-hash", PASSWORD)[0] is False
    assert verify_password(None, PASSWORD)[0] is False


def test_rehash_when_parameters_change():
    from argon2 import PasswordHasher
    weak = PasswordHasher(time_cost=1, memory_cost=8192).hash(PASSWORD)
    ok, new = verify_password(weak, PASSWORD)
    assert ok and new and new != weak


# ---- CSRF ---------------------------------------------------------------------------------
def test_csrf_missing_token(client):
    r = client.post("/api/auth/login", json={"email": "a@example.com", "password": "x"}, headers={"Origin": ORIGIN})
    assert r.status_code == 403 and r.json()["detail"] == "csrf_failed"


def test_csrf_wrong_token(client):
    csrf(client)
    r = post(client, "/api/auth/login", {"email": "a@example.com", "password": "x"}, token="A" * 43)
    assert r.status_code == 403


def test_csrf_foreign_or_missing_origin(client):
    t = csrf(client)
    assert post(client, "/api/auth/login", {"email": "a@x.io", "password": "x"}, token=t,
                origin="https://evil.example").json()["detail"] == "bad_origin"
    assert post(client, "/api/auth/login", {"email": "a@x.io", "password": "x"}, token=t,
                origin=None).status_code == 403
    # look-alike origin
    assert post(client, "/api/auth/login", {"email": "a@x.io", "password": "x"}, token=t,
                origin="http://localhost:3000.evil.example").status_code == 403


def test_csrf_token_rotates_on_login(client):
    before = csrf(client)
    r = register(client)
    after = r.json()["csrfToken"]
    assert after != before and cookie(client, "__Host-csrf") == after
    # old token no longer accepted
    assert post(client, "/api/auth/logout", token=before).status_code == 403


# ---- rate limiting ------------------------------------------------------------------------
def test_login_rate_limited_per_email(client, clock):
    register(client)
    anon = new_client(client.app)
    codes = [login(anon, password=f"wrong-password-{i}").status_code for i in range(10)]
    assert set(codes) == {401}
    r = login(anon)  # 11th attempt, even with the right password
    assert r.status_code == 429 and int(r.headers["Retry-After"]) >= 1
    clock.advance(901)
    assert login(anon).status_code == 200


def test_register_rate_limited_per_ip(client):
    codes = [register(new_client(client.app), email=f"u{i}@example.com").status_code for i in range(11)]
    assert codes[:10] == [201] * 10 and codes[10] == 429


# ---- headers ------------------------------------------------------------------------------
def test_security_headers(client):
    r = client.get("/api/dashboard/guest")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["referrer-policy"] == "no-referrer"
    assert "default-src 'none'" in r.headers["content-security-policy"]
    assert r.headers["cache-control"] == "no-store"
    assert "access-control-allow-origin" not in r.headers
