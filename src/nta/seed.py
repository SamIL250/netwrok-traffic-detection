from sqlalchemy import inspect, text
from sqlalchemy.orm import Session

from nta.auth import hash_password, verify_password
from nta.database import Base, engine
from nta.detection import ensure_default_rules
from nta.models import KnownDevice, Role, User, UserRole
from nta.password_policy import DEFAULT_SEED_ADMIN_PASSWORD


def init_database() -> None:
    Base.metadata.create_all(bind=engine)


def migrate_schema(db: Session) -> None:
    inspector = inspect(engine)
    if "users" not in inspector.get_table_names():
        return

    columns = {column["name"] for column in inspector.get_columns("users")}
    if "must_change_password" not in columns:
        db.execute(
            text("ALTER TABLE users ADD COLUMN must_change_password BOOLEAN NOT NULL DEFAULT FALSE")
        )
        db.commit()
        columns.add("must_change_password")

    if "token_version" not in columns:
        db.execute(text("ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 1"))
        db.commit()


def purge_expired_sessions(db: Session) -> None:
    from nta.session_service import purge_expired_revoked_tokens

    purge_expired_revoked_tokens(db)


def ensure_default_admin_password_flag(db: Session) -> None:
    admin = db.query(User).filter(User.username == "admin").first()
    if admin is None:
        return
    if verify_password(DEFAULT_SEED_ADMIN_PASSWORD, admin.password_hash):
        admin.must_change_password = True
        db.commit()


def seed_roles(db: Session) -> None:
    for role_name in UserRole:
        existing = db.query(Role).filter(Role.name == role_name.value).first()
        if existing is None:
            db.add(Role(name=role_name.value, description=f"{role_name.value.title()} role"))
    db.commit()


DEFAULT_KNOWN_DEVICES = [
    {"ip_address": "10.0.0.1", "label": "Gateway router"},
    {"ip_address": "192.168.1.1", "label": "Local router"},
    {"ip_address": "10.0.0.12", "label": "Staff workstation"},
    {"ip_address": "10.0.0.18", "label": "Lab computer"},
]


def seed_known_devices(db: Session) -> None:
    for device in DEFAULT_KNOWN_DEVICES:
        existing = db.query(KnownDevice).filter(KnownDevice.ip_address == device["ip_address"]).first()
        if existing is None:
            db.add(KnownDevice(**device))
    db.commit()


def seed_admin(
    db: Session,
    username: str = "admin",
    password: str = DEFAULT_SEED_ADMIN_PASSWORD,
    email: str = "admin@ulk.ac.rw",
) -> User:
    seed_roles(db)
    ensure_default_rules(db)
    seed_known_devices(db)

    admin_role = db.query(Role).filter(Role.name == UserRole.ADMIN.value).one()
    existing = db.query(User).filter(User.username == username).first()
    if existing is not None:
        return existing

    user = User(
        username=username,
        email=email,
        password_hash=hash_password(password),
        role_id=admin_role.id,
        must_change_password=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user
