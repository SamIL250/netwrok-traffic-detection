import re


def analyze_password_strength(password: str) -> dict[str, object]:
    checks = {
        "length_ok": len(password) >= 8,
        "uppercase_ok": bool(re.search(r"[A-Z]", password)),
        "lowercase_ok": bool(re.search(r"[a-z]", password)),
        "digit_ok": bool(re.search(r"\d", password)),
        "special_ok": bool(re.search(r"[^A-Za-z0-9]", password)),
    }

    score = sum(checks.values())
    if score <= 2:
        level = "weak"
        message = "Password is weak. Add length, numbers, and symbols."
    elif score <= 4:
        level = "medium"
        message = "Password is acceptable but could be stronger."
    else:
        level = "strong"
        message = "Password is strong."

    return {"score": score, "level": level, "message": message, "checks": checks}
