"""Argon2id password hashing (argon2-cffi defaults follow RFC 9106's recommended profile)."""

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

_ph = PasswordHasher()
# Verified against when the user does not exist, so "unknown e-mail" and "wrong password"
# cost about the same time (reduces account enumeration through timing).
_DUMMY_HASH = _ph.hash("timing-equalisation-dummy-password")


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(stored_hash: str | None, password: str) -> tuple[bool, str | None]:
    """Return (ok, new_hash_if_parameters_changed)."""
    if stored_hash is None:
        try:
            _ph.verify(_DUMMY_HASH, password)
        except VerificationError:
            pass
        return False, None
    try:
        _ph.verify(stored_hash, password)
    except (VerificationError, InvalidHashError):
        return False, None
    return True, (_ph.hash(password) if _ph.check_needs_rehash(stored_hash) else None)
