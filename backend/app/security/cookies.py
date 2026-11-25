"""Cookie names and flags in one place.

With COOKIE_SECURE=true the names carry the __Host- / __Secure- prefixes, which browsers only
accept from HTTPS (localhost counts as secure in current browsers), and __Host- additionally
forbids a Domain attribute, so a sibling subdomain cannot plant or overwrite them.
"""

from dataclasses import dataclass

from fastapi import Response

from ..config import Settings

REFRESH_COOKIE_PATH = "/api/auth"  # the refresh token is never sent to data endpoints


@dataclass(frozen=True)
class CookieNames:
    access: str
    refresh: str
    csrf: str
    oauth_bind: str


def cookie_names(settings: Settings) -> CookieNames:
    if settings.cookie_secure:
        return CookieNames("__Host-access", "__Secure-refresh", "__Host-csrf", "__Host-oauth_bind")
    return CookieNames("access", "refresh", "csrf", "oauth_bind")


def _set(response: Response, settings: Settings, name: str, value: str, max_age: int, path: str = "/",
         samesite: str = "strict") -> None:
    response.set_cookie(
        name, value, max_age=max_age, path=path, secure=settings.cookie_secure,
        httponly=True, samesite=samesite,  # type: ignore[arg-type]
    )


def set_access_cookie(response: Response, settings: Settings, token: str) -> None:
    _set(response, settings, cookie_names(settings).access, token, settings.access_token_ttl_s)


def set_refresh_cookie(response: Response, settings: Settings, token: str, max_age: int) -> None:
    _set(response, settings, cookie_names(settings).refresh, token, max_age, path=REFRESH_COOKIE_PATH)


def set_csrf_cookie(response: Response, settings: Settings, token: str) -> None:
    _set(response, settings, cookie_names(settings).csrf, token, settings.session_absolute_ttl_s)


def set_oauth_bind_cookie(response: Response, settings: Settings, value: str) -> None:
    # Lax, not Strict: the provider redirects back with a top-level cross-site GET, and Strict
    # cookies would not be sent on it.
    _set(response, settings, cookie_names(settings).oauth_bind, value, settings.oauth_state_ttl_s,
         samesite="lax")


def clear_oauth_bind_cookie(response: Response, settings: Settings) -> None:
    response.delete_cookie(cookie_names(settings).oauth_bind, path="/", secure=settings.cookie_secure,
                           httponly=True, samesite="lax")


def clear_auth_cookies(response: Response, settings: Settings) -> None:
    names = cookie_names(settings)
    response.delete_cookie(names.access, path="/", secure=settings.cookie_secure, httponly=True,
                           samesite="strict")
    response.delete_cookie(names.refresh, path=REFRESH_COOKIE_PATH, secure=settings.cookie_secure,
                           httponly=True, samesite="strict")
