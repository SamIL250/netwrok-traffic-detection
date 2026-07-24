from sqlalchemy.orm import Session

from nta.auth import hash_password
from nta.database import Base, engine
from nta.detection import ensure_default_rules
from nta.models import Role, User, UserRole


def init_database() -> None:
    Base.metadata.create_all(bind=engine)


def seed_roles(db: Session) -> None:
    for role_name in UserRole:
        existing = db.query(Role).filter(Role.name == role_name.value).first()
        if existing is None:
            db.add(Role(name=role_name.value, description=f"{role_name.value.title()} role"))
    db.commit()


def seed_admin(db: Session, username: str = "admin", password: str = "Admin@123", email: str = "admin@ulk.ac.rw") -> User:
    seed_roles(db)
    ensure_default_rules(db)

    admin_role = db.query(Role).filter(Role.name == UserRole.ADMIN.value).one()
    existing = db.query(User).filter(User.username == username).first()
    if existing is not None:
        return existing

    user = User(
        username=username,
        email=email,
        password_hash=hash_password(password),
        role_id=admin_role.id,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user
