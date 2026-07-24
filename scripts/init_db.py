from nta.database import SessionLocal
from nta.seed import init_database, seed_admin


def main() -> None:
    print("Creating database tables...")
    init_database()
    db = SessionLocal()
    try:
        admin = seed_admin(db)
        print("Database ready.")
        print(f"Admin user: {admin.username}")
        print("Default password: Admin@123")
    finally:
        db.close()


if __name__ == "__main__":
    main()
