from nta.database import SessionLocal
from nta.seed import ensure_default_admin_password_flag, init_database, migrate_schema, purge_expired_sessions, seed_admin


def main() -> None:
    print("Creating database tables...")
    init_database()
    db = SessionLocal()
    try:
        migrate_schema(db)
        admin = seed_admin(db)
        ensure_default_admin_password_flag(db)
        purge_expired_sessions(db)
        print("Database ready.")
        print(f"Admin user: {admin.username}")
        print("Default password: Admin@123 (must be changed on first login)")
    finally:
        db.close()


if __name__ == "__main__":
    main()
