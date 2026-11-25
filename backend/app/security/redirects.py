"""Open-redirect protection: only same-site relative paths are ever used as a post-login target."""

from urllib.parse import urlsplit

DEFAULT_AFTER_LOGIN = "/dashboard"


def safe_next(value: str | None, default: str = DEFAULT_AFTER_LOGIN) -> str:
    if not value or len(value) > 512:
        return default
    # Must be an absolute path on *this* site: "/x". Reject "//evil", "/\\evil" (browsers treat
    # backslash as slash), schemes, and any control characters / whitespace (header injection, tab tricks).
    if not value.startswith("/") or value.startswith("//") or "\\" in value:
        return default
    if any(ord(c) < 0x21 or ord(c) == 0x7F for c in value):
        return default
    parts = urlsplit(value)
    if parts.scheme or parts.netloc:
        return default
    return value
