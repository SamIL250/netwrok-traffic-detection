from nta.auth import verify_password
from nta.password_strength import analyze_password_strength

DEFAULT_SEED_ADMIN_PASSWORD = "Admin@123"


def validate_new_password(
    new_password: str,
    *,
    current_password_hash: str | None = None,
    current_password: str | None = None,
) -> None:
    strength = analyze_password_strength(new_password)
    if strength["level"] == "weak":
        raise ValueError("Password is too weak")

    if new_password == DEFAULT_SEED_ADMIN_PASSWORD:
        raise ValueError("Choose a password different from the default admin credentials")

    if current_password and new_password == current_password:
        raise ValueError("New password must be different from your current password")

    if current_password_hash and verify_password(new_password, current_password_hash):
        raise ValueError("New password must be different from your current password")
