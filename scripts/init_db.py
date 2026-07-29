from pathlib import Path

from nta.config import settings
from nta.database import SessionLocal
from nta.seed import ensure_default_admin_password_flag, init_database, migrate_schema, purge_expired_sessions, seed_admin

DEFAULT_DATABASE_URL = "postgresql+psycopg://localhost/network_traffic"


def _ensure_database_configured() -> None:
    env_path = Path(".env")
    if settings.database_url != DEFAULT_DATABASE_URL:
        return

    print("ERROR: DATABASE_URL is not configured.")
    print()
    if not env_path.exists():
        print("Missing .env file in the project folder.")
        print("Create it with:")
        print("  copy .env.example .env")
    else:
        print(".env exists but DATABASE_URL is missing or still uses the default.")
        print("Edit .env and set DATABASE_URL to your Neon connection string.")
    print()
    print("Example:")
    print("  DATABASE_URL=postgresql+psycopg://USER:PASSWORD@ep-xxx.region.aws.neon.tech/neondb?sslmode=require")
    print()
    print("Use postgresql+psycopg:// (not postgresql://).")
    raise SystemExit(1)


def main() -> None:
    _ensure_database_configured()
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
