import threading
import time

import jwt

from .conftest import cookie, login, new_client, post, register, set_cookie


def refresh(client):
    return post(client, "/api/auth/refresh")


def test_refresh_rotates_and_old_token_is_detected_as_reuse(client, clock):
    register(client)
    rt1 = cookie(client, "__Secure-refresh")
    r = refresh(client)
    assert r.status_code == 200 and r.json()["rotated"] is True
    rt2 = cookie(client, "__Secure-refresh")
    assert rt2 and rt2 != rt1

    clock.advance(11)  # outside the grace window
    attacker = new_client(client.app)
    set_cookie(attacker, "__Secure-refresh", rt1, path="/api/auth")
    r = refresh(attacker)
    assert r.status_code == 401 and r.json()["detail"] == "refresh_reuse_detected"
    # The whole family is dead: the legitimate holder of rt2 and their access token too.
    assert client.get("/api/me").json()["detail"] == "session_revoked"
    assert refresh(client).status_code == 401


def test_reuse_within_grace_gets_access_only_and_does_not_revoke(client):
    register(client)
    rt1 = cookie(client, "__Secure-refresh")
    assert refresh(client).status_code == 200
    rt2 = cookie(client, "__Secure-refresh")

    other_tab = new_client(client.app)  # same browser, request was already in flight with rt1
    set_cookie(other_tab, "__Secure-refresh", rt1, path="/api/auth")
    r = refresh(other_tab)
    assert r.status_code == 200 and r.json()["rotated"] is False
    assert not any(h.startswith("__Secure-refresh=") for h in r.headers.get_list("set-cookie"))
    # family still alive, rt2 still the current token
    assert refresh(client).status_code == 200
    assert cookie(client, "__Secure-refresh") != rt2


def test_grace_only_covers_the_immediate_predecessor(client):
    register(client)
    rt1 = cookie(client, "__Secure-refresh")
    refresh(client)
    refresh(client)  # rt2 -> rt3 within the grace window
    replay = new_client(client.app)
    set_cookie(replay, "__Secure-refresh", rt1, path="/api/auth")
    assert refresh(replay).json()["detail"] == "refresh_reuse_detected"


def test_concurrent_refresh_exactly_one_rotation(app, client):
    """Many parallel refreshes with the same token: the Lua script serialises them."""
    register(client)
    token = cookie(client, "__Secure-refresh")
    tokens = app.state.tokens
    results, barrier = [], threading.Barrier(20)

    def worker():
        barrier.wait()
        results.append(tokens.rotate(token).status)

    threads = [threading.Thread(target=worker) for _ in range(20)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert results.count("rotated") == 1
    assert results.count("grace") == 19


def test_access_token_expiry_then_refresh(client, clock):
    register(client)
    clock.advance(601)
    r = client.get("/api/me")
    assert r.status_code == 401 and r.json()["detail"] == "token_expired"
    assert refresh(client).status_code == 200
    assert client.get("/api/me").status_code == 200


def test_refresh_idle_timeout_and_absolute_lifetime(client, clock, redis_client):
    register(client)
    # keep refreshing every 50 min: idle timeout (60 min) never hits, absolute (120 min) does
    for _ in range(2):
        clock.advance(3000)
        assert refresh(client).status_code == 200
    clock.advance(1300)  # now past 2h since login
    r = refresh(client)
    assert r.status_code == 401 and r.json()["detail"] == "session_expired"


def test_refresh_cookie_only_sent_to_auth_paths(client):
    register(client)
    seen = {}

    @client.app.get("/api/echo-cookies")
    def _echo(request: __import__("fastapi").Request):
        seen.update(request.cookies)
        return {}

    client.get("/api/echo-cookies")
    assert "__Host-access" in seen and "__Secure-refresh" not in seen


def test_tampered_or_forged_access_tokens(client, settings, app):
    register(client)
    good = cookie(client, "__Host-access")
    claims = jwt.decode(good, options={"verify_signature": False})

    def try_token(tok):
        set_cookie(client, "__Host-access", tok)
        return client.get("/api/me")

    head, body, sig = good.split(".")
    flipped = sig[:-2] + ("AA" if sig[-2:] != "AA" else "BB")
    assert try_token(f"{head}.{body}.{flipped}").status_code == 401
    # alg=none
    none_tok = jwt.encode({**claims, "sub": "someone-else"}, key=None, algorithm="none")
    assert try_token(none_tok).status_code == 401
    # right shape, wrong key
    assert try_token(jwt.encode(claims, "x" * 48, algorithm="HS256")).status_code == 401
    # valid signature but wrong audience / type
    assert try_token(jwt.encode({**claims, "aud": "other"}, settings.jwt_secret, algorithm="HS256")).status_code == 401
    assert try_token(jwt.encode({**claims, "typ": "refresh"}, settings.jwt_secret, algorithm="HS256")).status_code == 401
    # valid signature, someone else's sub but our sid -> sid/sub mismatch
    assert try_token(jwt.encode({**claims, "sub": "another-user"}, settings.jwt_secret, algorithm="HS256")).json()["detail"] == "session_revoked"
    assert try_token(good).status_code == 200


def test_malformed_refresh_tokens(client):
    register(client)
    for bad in ["", "abc", "0" * 32 + "." + "A" * 43, "x" * 500, "../../etc"]:
        c = new_client(client.app)
        set_cookie(c, "__Secure-refresh", bad, path="/api/auth")
        assert refresh(c).status_code == 401


def test_logout_revokes_server_side(client):
    register(client)
    stolen_access = cookie(client, "__Host-access")
    stolen_refresh = cookie(client, "__Secure-refresh")
    assert post(client, "/api/auth/logout").status_code == 204
    thief = new_client(client.app)
    set_cookie(thief, "__Host-access", stolen_access)
    set_cookie(thief, "__Secure-refresh", stolen_refresh, path="/api/auth")
    assert thief.get("/api/me").json()["detail"] == "session_revoked"
    assert refresh(thief).status_code == 401


def test_logout_all_revokes_every_device(client):
    register(client)
    laptop = new_client(client.app)
    login(laptop)
    assert laptop.get("/api/me").status_code == 200
    assert post(client, "/api/auth/logout-all").status_code == 204
    assert laptop.get("/api/me").status_code == 401
    assert refresh(laptop).status_code == 401


def test_login_creates_new_family_and_revokes_presented_one(client):
    """Session fixation: whatever session the browser had is replaced, never adopted."""
    register(client)
    fixed_access = cookie(client, "__Host-access")
    login(client)
    new_access = cookie(client, "__Host-access")
    sid_old = jwt.decode(fixed_access, options={"verify_signature": False})["sid"]
    sid_new = jwt.decode(new_access, options={"verify_signature": False})["sid"]
    assert sid_old != sid_new
    planted = new_client(client.app)
    set_cookie(planted, "__Host-access", fixed_access)
    assert planted.get("/api/me").status_code == 401


def test_refresh_requires_csrf(client):
    register(client)
    r = client.post("/api/auth/refresh", headers={"Origin": "http://localhost:3000"})
    assert r.status_code == 403


def test_redis_never_holds_plain_refresh_tokens(client, redis_client):
    register(client)
    rt = cookie(client, "__Secure-refresh")
    secret_part = rt.split(".")[1]
    for key in redis_client.keys("*"):
        assert secret_part not in key
        if redis_client.type(key) == "hash":
            assert all(secret_part not in v for v in redis_client.hgetall(key).values())
