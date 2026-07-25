from collections.abc import Callable

import requests
import streamlit as st

CHANGE_PASSWORD_CSS = """
<style>
    @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&display=swap');

    html, body, [data-testid="stAppViewContainer"] {
        font-family: 'Poppins', sans-serif;
    }

    [data-testid="stAppViewContainer"]:has(.change-password-page-active) section.main > div {
        background: #f1f5f9;
    }

    [data-testid="stAppViewContainer"]:has(.change-password-page-active) .block-container {
        max-width: 100%;
        padding-top: 2rem;
        padding-bottom: 3rem;
    }

    [data-testid="stAppViewContainer"]:has(.change-password-page-active) div[data-testid="stHorizontalBlock"] > div[data-testid="column"]:nth-child(2) > div[data-testid="stVerticalBlockBorderWrapper"] {
        background: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 16px;
        padding: 2rem 1.75rem 1.5rem;
        box-shadow: 0 8px 30px rgba(15, 23, 42, 0.06);
    }

    [data-testid="stAppViewContainer"]:has(.change-password-page-active) [data-testid="stTextInput"] label,
    [data-testid="stAppViewContainer"]:has(.change-password-page-active) [data-testid="stTextInput"] label p {
        font-size: 0.82rem !important;
        font-weight: 600 !important;
        color: #475569 !important;
    }

    [data-testid="stAppViewContainer"]:has(.change-password-page-active) [data-testid="stTextInput"] input {
        border-radius: 10px !important;
        border-color: #e2e8f0 !important;
        background: #f8fafc !important;
        color: #0f172a !important;
        font-family: 'Poppins', sans-serif !important;
    }

    [data-testid="stAppViewContainer"]:has(.change-password-page-active) [data-testid="stTextInput"] input:focus {
        border-color: #93c5fd !important;
        box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.15) !important;
    }

    [data-testid="stAppViewContainer"]:has(.change-password-page-active) div.stButton > button[kind="primary"] {
        margin-top: 0.35rem;
        min-height: 2.75rem;
        width: 100%;
        border-radius: 10px !important;
        background: #2563eb !important;
        border: 1px solid #2563eb !important;
        color: #ffffff !important;
        font-family: 'Poppins', sans-serif !important;
        font-weight: 600 !important;
        box-shadow: none !important;
    }

    [data-testid="stAppViewContainer"]:has(.change-password-page-active) div.stButton > button[kind="primary"]:hover {
        background: #1d4ed8 !important;
        border-color: #1d4ed8 !important;
    }

    [data-testid="stAppViewContainer"]:has(.change-password-page-active) [data-testid="stAlert"] {
        border-radius: 10px;
        font-family: 'Poppins', sans-serif;
    }

    [data-testid="stAppViewContainer"]:has(.change-password-page-active) [data-testid="stMetric"],
    [data-testid="stAppViewContainer"]:has(.change-password-page-active) [data-testid="stMetricValue"],
    [data-testid="stAppViewContainer"]:has(.change-password-page-active) [data-testid="stMetricLabel"] {
        display: none;
    }

    .change-password-page-active {
        display: none;
    }

    .cp-brand-wrap {
        margin-bottom: 1.35rem;
    }

    .cp-section-label {
        margin: 0 0 0.45rem 0;
        font-size: 0.68rem;
        font-weight: 600;
        letter-spacing: 0.12em;
        text-transform: uppercase;
        color: #94a3b8;
    }

    .cp-title {
        margin: 0;
        font-size: 1.25rem;
        font-weight: 700;
        color: #0f172a;
        letter-spacing: -0.02em;
        line-height: 1.2;
    }

    .cp-caption {
        margin: 0.45rem 0 0 0;
        font-size: 0.84rem;
        color: #64748b;
        line-height: 1.5;
    }

    .cp-badge {
        display: inline-block;
        margin-top: 0.85rem;
        padding: 0.28rem 0.65rem;
        border-radius: 999px;
        background: #eff6ff;
        border: 1px solid #bfdbfe;
        color: #2563eb;
        font-size: 0.68rem;
        font-weight: 600;
        letter-spacing: 0.04em;
        text-transform: uppercase;
    }

    .cp-forced-alert {
        margin: 0 0 1.25rem 0;
        padding: 0.9rem 1rem;
        border-radius: 12px;
        background: #fff7ed;
        border: 1px solid #fed7aa;
        color: #9a3412;
        font-size: 0.84rem;
        line-height: 1.5;
    }

    .cp-forced-alert strong {
        color: #7c2d12;
        font-weight: 600;
    }

    .cp-strength-card {
        margin: 0.35rem 0 1rem 0;
        padding: 0.95rem 1rem;
        border-radius: 14px;
        background: #f8fafc;
        border: 1px solid #e2e8f0;
    }

    .cp-strength-label {
        margin: 0;
        font-size: 0.68rem;
        font-weight: 600;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: #94a3b8;
    }

    .cp-strength-value {
        margin: 0.3rem 0 0 0;
        font-size: 1rem;
        font-weight: 700;
        color: #0f172a;
    }

    .cp-strength-value.weak { color: #dc2626; }
    .cp-strength-value.medium { color: #d97706; }
    .cp-strength-value.strong { color: #059669; }

    .cp-strength-message {
        margin: 0.35rem 0 0.75rem 0;
        font-size: 0.82rem;
        color: #64748b;
        line-height: 1.45;
    }

    .cp-check-list {
        margin: 0;
        padding: 0;
        list-style: none;
    }

    .cp-check-item {
        display: flex;
        align-items: center;
        gap: 0.45rem;
        margin: 0.35rem 0 0 0;
        font-size: 0.8rem;
        color: #64748b;
    }

    .cp-check-item.pass {
        color: #059669;
    }

    .cp-check-item.fail {
        color: #94a3b8;
    }

    .cp-check-dot {
        width: 0.45rem;
        height: 0.45rem;
        border-radius: 999px;
        background: #cbd5e1;
        flex-shrink: 0;
    }

    .cp-check-item.pass .cp-check-dot {
        background: #10b981;
    }

    .cp-tip-card {
        margin-top: 1.15rem;
        padding: 0.85rem 1rem;
        border-radius: 12px;
        background: #f8fafc;
        border: 1px solid #e2e8f0;
        color: #475569;
        font-size: 0.82rem;
        line-height: 1.5;
    }

    .cp-tip-card strong {
        color: #0f172a;
        font-weight: 600;
    }
</style>
"""

CHECK_LABELS = {
    "length_ok": "At least 8 characters",
    "uppercase_ok": "Uppercase letter",
    "lowercase_ok": "Lowercase letter",
    "digit_ok": "Number",
    "special_ok": "Special character",
}


def _strength_card_html(strength: dict[str, object]) -> str:
    level = str(strength.get("level", "weak"))
    message = str(strength.get("message", ""))
    checks = strength.get("checks", {})
    if not isinstance(checks, dict):
        checks = {}

    items: list[str] = []
    for key, label in CHECK_LABELS.items():
        passed = bool(checks.get(key))
        state_class = "pass" if passed else "fail"
        items.append(
            f'<li class="cp-check-item {state_class}"><span class="cp-check-dot"></span>{label}</li>'
        )

    return f"""
    <div class="cp-strength-card">
        <p class="cp-strength-label">Password strength</p>
        <p class="cp-strength-value {level}">{level.title()}</p>
        <p class="cp-strength-message">{message}</p>
        <ul class="cp-check-list">{''.join(items)}</ul>
    </div>
    """


def render_change_password_screen(
    token: str,
    *,
    forced: bool,
    api_request: Callable[..., requests.Response],
    format_api_error: Callable[[requests.Response, str], str],
) -> None:
    st.markdown('<div class="change-password-page-active"></div>', unsafe_allow_html=True)
    st.markdown(CHANGE_PASSWORD_CSS, unsafe_allow_html=True)

    _, center, _ = st.columns([0.45, 1.9, 0.45])
    with center:
        if forced:
            badge = "Required action"
            title = "Change your password"
            caption = "Your account is using a temporary or default password. Set a strong new password to continue."
        else:
            badge = "Account security"
            title = "Change password"
            caption = "Update your account password. Use a strong password with mixed characters."

        st.markdown(
            f"""
            <div class="cp-brand-wrap">
                <p class="cp-section-label">Security</p>
                <p class="cp-title">{title}</p>
                <p class="cp-caption">{caption}</p>
                <span class="cp-badge">{badge}</span>
            </div>
            """,
            unsafe_allow_html=True,
        )

        if forced:
            st.markdown(
                """
                <div class="cp-forced-alert">
                    <strong>Action required.</strong>
                    Choose a password different from the default admin credentials before accessing the dashboard.
                </div>
                """,
                unsafe_allow_html=True,
            )

        current_password = st.text_input("Current password", type="password", key="cp-current-password")
        new_password = st.text_input("New password", type="password", key="cp-new-password")
        confirm_password = st.text_input("Confirm new password", type="password", key="cp-confirm-password")

        if new_password:
            strength = api_request("POST", "/api/password/strength", token, params={"password": new_password}).json()
            st.markdown(_strength_card_html(strength), unsafe_allow_html=True)

        button_label = "Set new password" if forced else "Update password"
        if st.button(button_label, type="primary", use_container_width=True):
            if not current_password or not new_password:
                st.error("Enter your current and new passwords.")
            elif new_password != confirm_password:
                st.error("New passwords do not match.")
            else:
                response = api_request(
                    "POST",
                    "/api/auth/change-password",
                    token,
                    json={"current_password": current_password, "new_password": new_password},
                )
                if response.status_code == 200:
                    if forced:
                        st.success("Password updated. Redirecting to the dashboard...")
                    else:
                        st.success("Password updated successfully.")
                    st.rerun()
                else:
                    st.error(format_api_error(response, "Could not update password."))

        st.markdown(
            """
            <div class="cp-tip-card">
                Use at least <strong>8 characters</strong> with uppercase, lowercase, numbers, and symbols.
                Do not reuse the default <strong>Admin@123</strong> password.
            </div>
            """,
            unsafe_allow_html=True,
        )
