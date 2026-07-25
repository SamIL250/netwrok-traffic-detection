from collections.abc import Callable

import streamlit as st

LOGIN_CSS = """
<style>
    @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&display=swap');

    html, body, [data-testid="stAppViewContainer"] {
        font-family: 'Poppins', sans-serif;
    }

    [data-testid="stAppViewContainer"]:has(.login-page-active) [data-testid="stSidebar"] {
        display: none;
    }

    [data-testid="stAppViewContainer"]:has(.login-page-active) section.main > div {
        background: #f1f5f9;
    }

    [data-testid="stAppViewContainer"]:has(.login-page-active) .block-container {
        max-width: 100%;
        padding-top: 2.5rem;
        padding-bottom: 3rem;
    }

    [data-testid="stAppViewContainer"]:has(.login-page-active) div[data-testid="stHorizontalBlock"] > div[data-testid="column"]:nth-child(2) > div[data-testid="stVerticalBlockBorderWrapper"] {
        background: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 16px;
        padding: 2rem 1.75rem 1.5rem;
        box-shadow: 0 8px 30px rgba(15, 23, 42, 0.06);
    }

    [data-testid="stAppViewContainer"]:has(.login-page-active) [data-testid="stForm"] {
        background: transparent;
        border: none;
        border-radius: 0;
        padding: 0;
        box-shadow: none;
    }

    [data-testid="stAppViewContainer"]:has(.login-page-active) [data-testid="stForm"] label {
        font-size: 0.82rem !important;
        font-weight: 600 !important;
        color: #475569 !important;
    }

    [data-testid="stAppViewContainer"]:has(.login-page-active) [data-testid="stForm"] input {
        border-radius: 10px !important;
        border-color: #e2e8f0 !important;
        background: #f8fafc !important;
        color: #0f172a !important;
        font-family: 'Poppins', sans-serif !important;
    }

    [data-testid="stAppViewContainer"]:has(.login-page-active) [data-testid="stForm"] input:focus {
        border-color: #93c5fd !important;
        box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.15) !important;
    }

    [data-testid="stAppViewContainer"]:has(.login-page-active) [data-testid="stFormSubmitButton"] button {
        margin-top: 0.35rem;
        min-height: 2.75rem;
        border-radius: 10px !important;
        background: #2563eb !important;
        border: 1px solid #2563eb !important;
        color: #ffffff !important;
        font-family: 'Poppins', sans-serif !important;
        font-weight: 600 !important;
        box-shadow: none !important;
    }

    [data-testid="stAppViewContainer"]:has(.login-page-active) [data-testid="stFormSubmitButton"] button:hover {
        background: #1d4ed8 !important;
        border-color: #1d4ed8 !important;
    }

    [data-testid="stAppViewContainer"]:has(.login-page-active) [data-testid="stAlert"] {
        border-radius: 10px;
        font-family: 'Poppins', sans-serif;
    }

    .login-page-active {
        display: none;
    }

    .login-brand-title {
        margin: 0;
        font-size: 1.45rem;
        font-weight: 700;
        color: #0f172a;
        letter-spacing: -0.02em;
        line-height: 1.2;
        text-align: center;
    }

    .login-brand-subtitle {
        margin: 0.45rem 0 0 0;
        font-size: 0.88rem;
        color: #64748b;
        line-height: 1.5;
        text-align: center;
    }

    .login-brand-badge {
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

    .login-brand-wrap {
        text-align: center;
        margin-bottom: 1.5rem;
    }

    .login-form-heading {
        margin: 0 0 0.35rem 0;
        font-size: 1.05rem;
        font-weight: 600;
        color: #0f172a;
        text-align: left;
    }

    .login-form-caption {
        margin: 0 0 1.1rem 0;
        font-size: 0.84rem;
        color: #64748b;
        text-align: left;
    }

    .login-help-card {
        margin-top: 1.15rem;
        padding: 0.85rem 1rem;
        border-radius: 12px;
        background: #f8fafc;
        border: 1px solid #e2e8f0;
        color: #475569;
        font-size: 0.82rem;
        line-height: 1.5;
        text-align: center;
    }

    .login-help-card strong {
        color: #0f172a;
        font-weight: 600;
    }
</style>
"""

LOGIN_BRAND_HTML = """
<div class="login-brand-wrap">
    <p class="login-brand-title">Network Traffic Monitor</p>
    <p class="login-brand-subtitle">ULK Kigali security operations console</p>
    <span class="login-brand-badge">Live monitoring</span>
</div>
"""


def render_login_screen(login_fn: Callable[[str, str], str | None]) -> str | None:
    st.markdown('<div class="login-page-active"></div>', unsafe_allow_html=True)
    st.markdown(LOGIN_CSS, unsafe_allow_html=True)

    _, center, _ = st.columns([1, 1.05, 1])
    with center:
        st.markdown(LOGIN_BRAND_HTML, unsafe_allow_html=True)
        st.markdown(
            """
            <p class="login-form-heading">Sign in</p>
            <p class="login-form-caption">Use your assigned credentials to access the monitoring dashboard.</p>
            """,
            unsafe_allow_html=True,
        )

        with st.form("login_form", clear_on_submit=False):
            username = st.text_input("Username", placeholder="Enter your username")
            password = st.text_input("Password", type="password", placeholder="Enter your password")
            submitted = st.form_submit_button("Sign in", type="primary", use_container_width=True)

        if submitted:
            if not username or not password:
                st.error("Enter both username and password.")
            else:
                token = login_fn(username, password)
                if token:
                    return str(token)
                st.error("Invalid username or password.")

        st.markdown(
            """
            <div class="login-help-card">
                Default admin: <strong>admin</strong> / <strong>Admin@123</strong><br>
                You will be required to set a new password immediately after signing in.
            </div>
            """,
            unsafe_allow_html=True,
        )

    return None
