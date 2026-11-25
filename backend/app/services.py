"""Account resolution for OAuth logins, including the account-linking policy."""

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .models import OAuthAccount, User
from .oauth.providers import OAuthError, OAuthIdentity


def user_by_email(db: Session, email: str) -> User | None:
    return db.scalar(select(User).where(User.email == email.strip().lower()))


def resolve_oauth_user(db: Session, ident: OAuthIdentity, *, link_user_id: str | None) -> User:
    """Policy (safe linking):
    1. Known (provider, subject)  -> that user. In link mode it must be the same user.
    2. Link mode (user was signed in and passed CSRF when starting) -> attach to that user.
    3. Otherwise create a new user, but only with a provider-verified e-mail that no existing
       account uses. We never auto-link by e-mail: password sign-ups have unverified e-mails, so
       auto-linking would let someone pre-register a victim's address and later share the
       victim's account (pre-account-takeover), and providers' e-mail claims can change.
    """
    existing = db.scalar(select(OAuthAccount).where(
        OAuthAccount.provider == ident.provider, OAuthAccount.subject == ident.subject))
    if existing is not None:
        if link_user_id is not None and existing.user_id != link_user_id:
            raise OAuthError("identity_linked_elsewhere")
        user = existing.user
        if not user.is_active:
            raise OAuthError("account_disabled")
        return user

    if link_user_id is not None:
        user = db.get(User, link_user_id)
        if user is None or not user.is_active:
            raise OAuthError("account_disabled")
        if any(a.provider == ident.provider for a in user.oauth_accounts):
            raise OAuthError("provider_already_linked")
        db.add(OAuthAccount(user_id=user.id, provider=ident.provider, subject=ident.subject,
                            email_at_link=ident.email))
        _commit(db)
        return user

    if not ident.email or not ident.email_verified:
        raise OAuthError("email_unverified")
    if user_by_email(db, ident.email) is not None:
        raise OAuthError("account_exists")
    user = User(email=ident.email, display_name=(ident.name or ident.email.split("@")[0])[:50],
                password_hash=None, email_verified=True)
    db.add(user)
    db.flush()
    db.add(OAuthAccount(user_id=user.id, provider=ident.provider, subject=ident.subject,
                        email_at_link=ident.email))
    _commit(db)
    return user


def _commit(db: Session) -> None:
    try:
        db.commit()
    except IntegrityError as exc:  # concurrent callback for the same identity / e-mail
        db.rollback()
        raise OAuthError("account_exists") from exc
