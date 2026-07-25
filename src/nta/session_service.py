from datetime import datetime, timezone
from uuid import uuid4

from jose import jwt
from sqlalchemy.orm import Session

from nta.config import settings
from nta.models import RevokedToken, User

ALGORITHM = "HS256"


def create_access_token(user: User) -> str:
    from datetime import timedelta

    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.access_token_expire_minutes)
    payload = {
        "sub": user.username,
        "jti": str(uuid4()),
        "tv": user.token_version,
        "exp": expire,
    }
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict[str, object]:
    return jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])


def _ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def is_token_revoked(db: Session, jti: str) -> bool:
    return db.query(RevokedToken.id).filter(RevokedToken.jti == jti).first() is not None


def revoke_token(
    db: Session,
    *,
    jti: str,
    username: str,
    expires_at: datetime,
    reason: str,
) -> None:
    if is_token_revoked(db, jti):
        return

    db.add(
        RevokedToken(
            jti=jti,
            username=username,
            expires_at=_ensure_utc(expires_at),
            reason=reason,
        )
    )
    db.commit()


def revoke_token_from_access_token(db: Session, token: str, *, reason: str) -> None:
    payload = decode_access_token(token)
    jti = payload.get("jti")
    username = payload.get("sub")
    exp = payload.get("exp")
    if not isinstance(jti, str) or not isinstance(username, str) or exp is None:
        return

    expires_at = datetime.fromtimestamp(int(exp), tz=timezone.utc)
    revoke_token(db, jti=jti, username=username, expires_at=expires_at, reason=reason)


def invalidate_user_sessions(db: Session, user: User) -> None:
    user.token_version += 1
    db.commit()
    db.refresh(user)


def purge_expired_revoked_tokens(db: Session) -> None:
    now = datetime.now(timezone.utc)
    db.query(RevokedToken).filter(RevokedToken.expires_at < now).delete()
    db.commit()
