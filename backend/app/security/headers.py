from fastapi import FastAPI, Request

from ..config import Settings


def install_security_headers(app: FastAPI, settings: Settings) -> None:
    @app.middleware("http")
    async def _security_headers(request: Request, call_next):
        response = await call_next(request)
        h = response.headers
        h.setdefault("X-Content-Type-Options", "nosniff")
        h.setdefault("X-Frame-Options", "DENY")
        # no-referrer also stops OAuth `code`/`state` from leaking via Referer after the callback.
        h.setdefault("Referrer-Policy", "no-referrer")
        # The API serves JSON only, so it can use the strictest possible CSP.
        h.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
        h.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        h.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        h.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        h.setdefault("Cache-Control", "no-store")
        if settings.is_production:
            h.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
        return response
