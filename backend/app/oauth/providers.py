"""Google (OpenID Connect) and GitHub (plain OAuth 2.0) providers.

Google: the identity comes from the ID token, verified locally: RS256 signature against Google's
JWKS, `iss`, `aud` == our client id, `azp`, `exp`/`iat`, and the `nonce` we generated.
GitHub: not OIDC, so there is no ID token. The identity is the numeric `id` from GET /user,
called with the access token we just received over TLS from GitHub's token endpoint, and the
e-mail comes from GET /user/emails, keeping only an address GitHub marks verified and primary.
The `login` (username) is mutable and recyclable, so it is never used as the key.
"""

import hmac
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlencode

import httpx
import jwt

from ..config import Settings


class OAuthError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class OAuthIdentity:
    provider: str
    subject: str
    email: str | None
    email_verified: bool
    name: str | None


class JWKSClient(Protocol):
    def get_signing_key_from_jwt(self, token: str) -> Any: ...


def _json(resp: httpx.Response, code: str) -> dict:
    if resp.status_code != 200:
        raise OAuthError(code)
    try:
        data = resp.json()
    except ValueError as exc:
        raise OAuthError(code) from exc
    if not isinstance(data, dict):
        raise OAuthError(code)
    return data


class GoogleProvider:
    name = "google"
    AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
    TOKEN_URL = "https://oauth2.googleapis.com/token"
    JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs"
    ISSUERS = ("https://accounts.google.com", "accounts.google.com")
    uses_nonce = True
    # RFC 9207: if the provider returns `iss` on the redirect, it must be this.
    auth_response_iss = "https://accounts.google.com"

    def __init__(self, settings: Settings, http: httpx.Client, jwks: JWKSClient):
        self.s, self.http, self.jwks = settings, http, jwks

    @property
    def configured(self) -> bool:
        return bool(self.s.google_client_id and self.s.google_client_secret)

    def authorization_url(self, *, state: str, code_challenge: str, nonce: str, redirect_uri: str) -> str:
        return self.AUTH_URL + "?" + urlencode({
            "client_id": self.s.google_client_id, "redirect_uri": redirect_uri, "response_type": "code",
            "scope": "openid email profile", "state": state, "nonce": nonce,
            "code_challenge": code_challenge, "code_challenge_method": "S256", "prompt": "select_account",
        })

    def exchange(self, *, code: str, code_verifier: str, redirect_uri: str, nonce: str) -> OAuthIdentity:
        try:
            resp = self.http.post(self.TOKEN_URL, data={
                "grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri,
                "client_id": self.s.google_client_id, "client_secret": self.s.google_client_secret,
                "code_verifier": code_verifier,
            }, headers={"Accept": "application/json"})
        except httpx.HTTPError as exc:
            raise OAuthError("provider_unreachable") from exc
        id_token = _json(resp, "token_exchange_failed").get("id_token")
        if not isinstance(id_token, str):
            raise OAuthError("token_exchange_failed")
        claims = self.verify_id_token(id_token, nonce)
        ev = claims.get("email_verified")
        email = claims.get("email")
        return OAuthIdentity(
            provider=self.name, subject=claims["sub"],
            email=email.strip().lower() if isinstance(email, str) else None,
            email_verified=ev is True or ev == "true",
            name=claims.get("name") if isinstance(claims.get("name"), str) else None,
        )

    def verify_id_token(self, id_token: str, nonce: str) -> dict:
        try:
            key = self.jwks.get_signing_key_from_jwt(id_token).key
            claims = jwt.decode(
                id_token, key, algorithms=["RS256"], audience=self.s.google_client_id,
                issuer=self.ISSUERS, leeway=30,
                options={"require": ["iss", "aud", "sub", "exp", "iat", "nonce"]},
            )
        except (jwt.PyJWTError, jwt.PyJWKClientError) as exc:
            raise OAuthError("invalid_id_token") from exc
        if not isinstance(claims.get("nonce"), str) or not hmac.compare_digest(claims["nonce"], nonce):
            raise OAuthError("invalid_id_token")
        azp = claims.get("azp")
        if azp is not None and azp != self.s.google_client_id:
            raise OAuthError("invalid_id_token")
        if not isinstance(claims["sub"], str) or not 0 < len(claims["sub"]) <= 255:
            raise OAuthError("invalid_id_token")
        return claims


class GitHubProvider:
    name = "github"
    AUTH_URL = "https://github.com/login/oauth/authorize"
    TOKEN_URL = "https://github.com/login/oauth/access_token"
    API = "https://api.github.com"
    uses_nonce = False
    auth_response_iss = None

    def __init__(self, settings: Settings, http: httpx.Client):
        self.s, self.http = settings, http

    @property
    def configured(self) -> bool:
        return bool(self.s.github_client_id and self.s.github_client_secret)

    def authorization_url(self, *, state: str, code_challenge: str, nonce: str, redirect_uri: str) -> str:
        # GitHub supports PKCE (S256 only) for OAuth apps since July 2025.
        return self.AUTH_URL + "?" + urlencode({
            "client_id": self.s.github_client_id, "redirect_uri": redirect_uri,
            "scope": "read:user user:email", "state": state,
            "code_challenge": code_challenge, "code_challenge_method": "S256",
        })

    def exchange(self, *, code: str, code_verifier: str, redirect_uri: str, nonce: str) -> OAuthIdentity:
        try:
            tok = _json(self.http.post(self.TOKEN_URL, data={
                "client_id": self.s.github_client_id, "client_secret": self.s.github_client_secret,
                "code": code, "redirect_uri": redirect_uri, "code_verifier": code_verifier,
            }, headers={"Accept": "application/json"}), "token_exchange_failed")
            # GitHub returns HTTP 200 with {"error": ...} on failure.
            access = tok.get("access_token")
            if tok.get("error") or not isinstance(access, str) or str(tok.get("token_type", "")).lower() != "bearer":
                raise OAuthError("token_exchange_failed")
            headers = {"Authorization": f"Bearer {access}", "Accept": "application/vnd.github+json",
                       "X-GitHub-Api-Version": "2022-11-28"}
            user = _json(self.http.get(f"{self.API}/user", headers=headers), "profile_fetch_failed")
            emails_resp = self.http.get(f"{self.API}/user/emails", headers=headers)
        except httpx.HTTPError as exc:
            raise OAuthError("provider_unreachable") from exc
        uid = user.get("id")
        if not isinstance(uid, int) or isinstance(uid, bool) or uid <= 0:
            raise OAuthError("profile_fetch_failed")
        if emails_resp.status_code != 200 or not isinstance(emails := emails_resp.json(), list):
            raise OAuthError("profile_fetch_failed")
        primary = next((e for e in emails if isinstance(e, dict) and e.get("primary") is True
                        and e.get("verified") is True and isinstance(e.get("email"), str)), None)
        name = user.get("name") or user.get("login")
        # The GitHub access token is discarded here: this app only needs the identity.
        return OAuthIdentity(
            provider=self.name, subject=str(uid),
            email=primary["email"].strip().lower() if primary else None,
            email_verified=primary is not None,
            name=name if isinstance(name, str) else None,
        )
