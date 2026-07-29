"""Reset the admin user's password and invalidate active sessions."""

from __future__ import annotations

import argparse

from nta.auth import hash_password
from nta.database import SessionLocal
from nta.models import User
from nta.password_policy import DEFAULT_SEED_ADMIN_PASSWORD
from nta.session_service import invalidate_user_sessions


def main() -> None:
    parser = argparse.ArgumentParser(description="Reset the admin password.")
    parser.add_argument(
        "--username",
        default="admin",
        help="Admin username to reset (default: admin)",
    )
    parser.add_argument(
        "--password",
        default=DEFAULT_SEED_ADMIN_PASSWORD,
        help="New password (default: Admin@123)",
    )
    args = parser.parse_args()

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == args.username).first()
        if user is None:
            raise SystemExit(f"User '{args.username}' not found.")

        user.password_hash = hash_password(args.password)
        user.must_change_password = True
        db.commit()
        db.refresh(user)
        invalidate_user_sessions(db, user)

        print(f"Password reset for user: {user.username}")
        print(f"New password: {args.password}")
        print("User must change password on next login.")
        print("All existing sessions for this user were invalidated.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
