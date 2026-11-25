"""Server-side OAuth transaction store (Redis, single use, short TTL).

The browser only ever sees `state` (in the URL) and a random binding value (HttpOnly cookie).
The PKCE verifier, OIDC nonce, post-login target and link-mode user id never leave the server.
"""

import base64
import hashlib
import json
import secrets
from dataclasses import asdict, dataclass

from redis import Redis


@dataclass
class OAuthTransaction:
    provider: str
    code_verifier: str
    nonce: str
    next_path: str
    mode: str  # "login" | "link"
    link_user_id: str | None
    binding_hash: str


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)  # 86 chars, within RFC 7636's 43..128
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


class OAuthStateStore:
    def __init__(self, redis: Redis, prefix: str, ttl: int):
        self.redis, self.prefix, self.ttl = redis, prefix, ttl

    def _key(self, state: str) -> str:
        return f"{self.prefix}:oauth:{sha256_hex(state)}"

    def save(self, state: str, tx: OAuthTransaction) -> None:
        self.redis.set(self._key(state), json.dumps(asdict(tx)), ex=self.ttl, nx=True)

    def pop(self, state: str | None) -> OAuthTransaction | None:
        if not state or len(state) > 200:
            return None
        raw = self.redis.getdel(self._key(state))  # atomic get+delete: a state can be consumed once
        return OAuthTransaction(**json.loads(raw)) if raw else None
