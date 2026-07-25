import bcrypt
from datetime import datetime, timezone
from typing import Annotated

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError
from sqlalchemy.orm import Session

from nta.database import get_db
from nta.models import AuditLog, User
from nta.session_service import decode_access_token, is_token_revoked

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))


def authenticate_user(db: Session, username: str, password: str) -> User | None:
    user = db.query(User).filter(User.username == username, User.is_active.is_(True)).first()
    if user is None or not verify_password(password, user.password_hash):
        return None
    return user


def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: Annotated[Session, Depends(get_db)],
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    session_revoked_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Session expired or revoked",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = decode_access_token(token)
        username = payload.get("sub")
        token_version = payload.get("tv")
        jti = payload.get("jti")
        if not isinstance(username, str):
            raise credentials_exception
    except JWTError as exc:
        raise credentials_exception from exc

    if isinstance(jti, str) and is_token_revoked(db, jti):
        raise session_revoked_exception

    user = db.query(User).filter(User.username == username, User.is_active.is_(True)).first()
    if user is None:
        raise credentials_exception

    if not isinstance(token_version, int) or token_version != user.token_version:
        raise session_revoked_exception

    return user


def require_roles(*allowed_roles: str):
    def role_checker(current_user: Annotated[User, Depends(get_current_user)]) -> User:
        if current_user.role.name not in allowed_roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return current_user

    return role_checker


def log_audit(db: Session, user_id: int | None, action: str, details: str = "") -> None:
    db.add(AuditLog(user_id=user_id, action=action, details=details))
    db.commit()


AGENT_API_KEY_HEADER = "X-Agent-Api-Key"


def verify_agent_api_key(x_agent_api_key: str | None = Header(default=None, alias=AGENT_API_KEY_HEADER)) -> None:
    from nta.config import settings

    if not settings.agent_api_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Agent API key not configured on server",
        )
    if x_agent_api_key != settings.agent_api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid agent API key")
