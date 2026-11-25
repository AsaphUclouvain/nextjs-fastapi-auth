"""Access tokens (short-lived JWT) + refresh tokens (opaque, rotating, Redis-backed).

Redis layout (all keys of one login share the hash tag {fid}, so the Lua script is cluster-safe):

  auth:fam:{fid}            HASH  user_id, current (sha256 of the live refresh token), created_at, abs_exp
                            TTL = absolute session lifetime. Deleting it revokes the whole login:
                            every refresh token of the family *and* every access token (sid claim).
  auth:rt:{fid}:<sha256>    HASH  user_id, state=active|rotated, rotated_at, next
                            TTL = refresh idle timeout. Rotated entries are kept until they expire
                            so a replay of an old token is recognised as reuse.
  auth:user:<uid>:fams      SET   family ids of the user (for "log out everywhere").

Refresh token wire format: "<fid>.<43 random url-safe chars>" (256 bits of secret). Only its SHA-256
is stored, so a Redis dump does not yield usable tokens.
"""

import hashlib
import logging
import re
import secrets
import uuid
from collections.abc import Callable
from dataclasses import dataclass

import jwt
from redis import Redis

from ..config import Settings

log = logging.getLogger("auth.tokens")

_REFRESH_RE = re.compile(r"^([0-9a-f]{32})\.([A-Za-z0-9_-]{43})$")

# Atomic rotation. KEYS: presented-token key, family key, new-token key.
# ARGV: presented hash, new hash, now, grace seconds, refresh ttl.
# Returns {status, user_id}: rotated | grace | reuse | expired | invalid.
ROTATE_LUA = """
local fam_user = redis.call('HGET', KEYS[2], 'user_id')
if not fam_user then return {'invalid', ''} end
local now = tonumber(ARGV[3])
local abs_exp = tonumber(redis.call('HGET', KEYS[2], 'abs_exp'))
if now >= abs_exp then
  redis.call('DEL', KEYS[2])
  return {'expired', fam_user}
end
local state = redis.call('HGET', KEYS[1], 'state')
if not state then return {'invalid', fam_user} end
local current = redis.call('HGET', KEYS[2], 'current')
if state == 'active' and current == ARGV[1] then
  local ttl = math.min(tonumber(ARGV[5]), abs_exp - now)
  redis.call('HSET', KEYS[1], 'state', 'rotated', 'rotated_at', ARGV[3], 'next', ARGV[2])
  redis.call('HSET', KEYS[3], 'user_id', fam_user, 'state', 'active')
  redis.call('EXPIRE', KEYS[3], ttl)
  redis.call('HSET', KEYS[2], 'current', ARGV[2])
  return {'rotated', fam_user}
end
if state == 'rotated' then
  local rotated_at = tonumber(redis.call('HGET', KEYS[1], 'rotated_at'))
  local nxt = redis.call('HGET', KEYS[1], 'next')
  -- Only the *immediate* predecessor, only briefly, and only while its successor is still live.
  if (now - rotated_at) <= tonumber(ARGV[4]) and nxt == current then
    return {'grace', fam_user}
  end
end
-- A rotated token outside the grace window (or any inconsistency): assume theft, kill the family.
redis.call('DEL', KEYS[2])
return {'reuse', fam_user}
"""


class AuthError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class IssuedTokens:
    family_id: str
    user_id: str
    access_token: str
    access_expires_at: int
    refresh_token: str | None  # None when only a new access token was issued (grace path)
    refresh_max_age: int


@dataclass(frozen=True)
class RotationResult:
    status: str  # rotated | grace | reuse | expired | invalid
    user_id: str | None
    family_id: str | None
    tokens: IssuedTokens | None


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def parse_refresh(token: str | None) -> str | None:
    """Return the family id if the token is well formed, else None."""
    if not token or len(token) > 100:
        return None
    m = _REFRESH_RE.match(token)
    return m.group(1) if m else None


class TokenService:
    def __init__(self, settings: Settings, redis: Redis, clock: Callable[[], float]):
        self.s, self.redis, self.clock = settings, redis, clock
        self.p = settings.redis_prefix
        self._rotate = redis.register_script(ROTATE_LUA)

    # ---- keys -----------------------------------------------------------------------------
    def k_fam(self, fid: str) -> str:
        return f"{self.p}:fam:{{{fid}}}"

    def k_rt(self, fid: str, token_hash: str) -> str:
        return f"{self.p}:rt:{{{fid}}}:{token_hash}"

    def k_user(self, uid: str) -> str:
        return f"{self.p}:user:{uid}:fams"

    # ---- issuing --------------------------------------------------------------------------
    def _now(self) -> int:
        return int(self.clock())

    def mint_access(self, user_id: str, fid: str, now: int | None = None) -> tuple[str, int]:
        now = self._now() if now is None else now
        exp = now + self.s.access_token_ttl_s
        payload = {
            "iss": self.s.jwt_issuer, "aud": self.s.jwt_audience, "sub": user_id, "sid": fid,
            "typ": "access", "jti": uuid.uuid4().hex, "iat": now, "nbf": now, "exp": exp,
        }
        # Deliberately no role/permissions in the token: they are read from the DB per request,
        # so a role change or account disable takes effect immediately, not after token expiry.
        return jwt.encode(payload, self.s.jwt_secret, algorithm="HS256"), exp

    def create_session(self, user_id: str) -> IssuedTokens:
        """New login => brand-new family (never reuse anything the client sent: no session fixation)."""
        fid, now = uuid.uuid4().hex, self._now()
        refresh = f"{fid}.{secrets.token_urlsafe(32)}"
        h = _sha256(refresh)
        abs_exp = now + self.s.session_absolute_ttl_s
        rt_ttl = min(self.s.refresh_token_ttl_s, self.s.session_absolute_ttl_s)
        pipe = self.redis.pipeline(transaction=True)
        pipe.hset(self.k_fam(fid), mapping={"user_id": user_id, "current": h, "created_at": now, "abs_exp": abs_exp})
        pipe.expireat(self.k_fam(fid), abs_exp)
        pipe.hset(self.k_rt(fid, h), mapping={"user_id": user_id, "state": "active"})
        pipe.expire(self.k_rt(fid, h), rt_ttl)
        pipe.sadd(self.k_user(user_id), fid)
        pipe.expire(self.k_user(user_id), self.s.session_absolute_ttl_s)
        pipe.execute()
        access, exp = self.mint_access(user_id, fid, now)
        return IssuedTokens(fid, user_id, access, exp, refresh, rt_ttl)

    # ---- verification ---------------------------------------------------------------------
    def decode_access(self, token: str, *, check_exp: bool = True) -> dict:
        try:
            claims = jwt.decode(
                token, self.s.jwt_secret, algorithms=["HS256"],  # pinned: no "none", no RS/HS confusion
                audience=self.s.jwt_audience, issuer=self.s.jwt_issuer,
                options={"require": ["iss", "aud", "sub", "sid", "typ", "jti", "iat", "nbf", "exp"],
                         "verify_exp": False, "verify_nbf": False, "verify_iat": False},
            )
        except jwt.PyJWTError as exc:
            raise AuthError("invalid_token") from exc
        if claims.get("typ") != "access" or not isinstance(claims.get("sid"), str):
            raise AuthError("invalid_token")
        now = self._now()
        # Time checks against the injectable clock (PyJWT always uses wall time).
        if not all(isinstance(claims[c], int) for c in ("iat", "nbf", "exp")) or claims["nbf"] > now + 5:
            raise AuthError("invalid_token")
        if check_exp and claims["exp"] <= now:
            raise AuthError("token_expired")
        return claims

    def verify_access(self, token: str) -> dict:
        claims = self.decode_access(token)
        # Stateful check: the login (family) must still exist => logout/revocation is immediate.
        owner = self.redis.hget(self.k_fam(claims["sid"]), "user_id")
        if owner is None or owner != claims["sub"]:
            raise AuthError("session_revoked")
        return claims

    # ---- rotation -------------------------------------------------------------------------
    def rotate(self, presented: str | None) -> RotationResult:
        fid = parse_refresh(presented)
        if fid is None:
            return RotationResult("invalid", None, None, None)
        assert presented is not None
        now = self._now()
        old_h = _sha256(presented)
        new_refresh = f"{fid}.{secrets.token_urlsafe(32)}"
        new_h = _sha256(new_refresh)
        status, uid = self._rotate(
            keys=[self.k_rt(fid, old_h), self.k_fam(fid), self.k_rt(fid, new_h)],
            args=[old_h, new_h, now, self.s.refresh_reuse_grace_s, self.s.refresh_token_ttl_s],
        )
        status = status.decode() if isinstance(status, bytes) else status
        uid = (uid.decode() if isinstance(uid, bytes) else uid) or None
        if status == "reuse":
            log.warning("refresh token reuse detected; family revoked fid=%s user=%s", fid, uid)
            if uid:
                self.redis.srem(self.k_user(uid), fid)
            return RotationResult("reuse", uid, fid, None)
        if status in ("rotated", "grace") and uid:
            access, exp = self.mint_access(uid, fid, now)
            abs_exp = int(self.redis.hget(self.k_fam(fid), "abs_exp") or now)
            max_age = max(1, min(self.s.refresh_token_ttl_s, abs_exp - now))
            refresh = new_refresh if status == "rotated" else None
            return RotationResult(status, uid, fid, IssuedTokens(fid, uid, access, exp, refresh, max_age))
        if status == "expired" and uid:
            self.redis.srem(self.k_user(uid), fid)
        return RotationResult(status, uid, fid, None)

    def refresh_token_known(self, presented: str | None) -> str | None:
        """Family id if this refresh token was ever issued by us and is not expired."""
        fid = parse_refresh(presented)
        if fid and presented and self.redis.exists(self.k_rt(fid, _sha256(presented))):
            return fid
        return None

    # ---- revocation -----------------------------------------------------------------------
    def revoke_family(self, fid: str) -> None:
        uid = self.redis.hget(self.k_fam(fid), "user_id")
        self.redis.delete(self.k_fam(fid))
        if uid:
            self.redis.srem(self.k_user(uid), fid)

    def revoke_all(self, user_id: str) -> int:
        fids = self.redis.smembers(self.k_user(user_id))
        pipe = self.redis.pipeline(transaction=False)
        for fid in fids:
            pipe.delete(self.k_fam(fid))
        pipe.delete(self.k_user(user_id))
        pipe.execute()
        return len(fids)
