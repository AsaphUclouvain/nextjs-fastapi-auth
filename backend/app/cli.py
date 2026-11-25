"""Admin bootstrap. Roles are only ever changed here (or in the DB), never through the HTTP API.

    python -m app.cli set-role alice@example.com admin
    python -m app.cli disable alice@example.com     # also revokes every login of that user
"""

import sys

import redis
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .db import make_engine
from .models import ROLES, User
from .security.tokens import TokenService


def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[0] not in ("set-role", "disable") or (argv[0] == "set-role" and len(argv) != 3):
        print(__doc__)
        return 2
    s = get_settings()
    with Session(make_engine(s.database_url)) as db:
        user = db.scalar(select(User).where(User.email == argv[1].strip().lower()))
        if user is None:
            print("no such user")
            return 1
        if argv[0] == "set-role":
            if argv[2] not in ROLES:
                print(f"role must be one of {ROLES}")
                return 2
            user.role = argv[2]
        else:
            user.is_active = False
        db.commit()
        TokenService(s, redis.Redis.from_url(s.redis_url, decode_responses=True), lambda: 0).revoke_all(user.id)
        print("ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
