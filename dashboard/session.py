import streamlit as st

from nta.config import settings

AUTH_COOKIE_NAME = "nta_auth_token"
MAX_COOKIE_LOAD_ATTEMPTS = 5


def get_cookie_manager():
    if "cookie_manager" not in st.session_state:
        import extra_streamlit_components as stx

        st.session_state.cookie_manager = stx.CookieManager(key="nta_cookie_manager")

    return st.session_state.cookie_manager


def validate_token(token: str) -> bool:
    import requests

    try:
        response = requests.get(
            f"{settings.api_base_url.rstrip('/')}/api/auth/me",
            headers={"Authorization": f"Bearer {token}"},
            timeout=20,
        )
        return response.status_code == 200
    except requests.RequestException:
        return False


def _read_cookie_token() -> str | None:
    cookie_manager = get_cookie_manager()
    cookies = cookie_manager.get_all(key="read_auth_cookie")
    if not cookies:
        return None
    token = cookies.get(AUTH_COOKIE_NAME)
    if isinstance(token, str) and token:
        return token
    return None


def get_stored_token() -> str | None:
    session_token = st.session_state.get("token")
    if session_token:
        return session_token

    cookie_token = _read_cookie_token()
    if cookie_token:
        st.session_state.token = cookie_token
        st.session_state.pop("_cookie_load_attempts", None)
        return cookie_token

    attempts = st.session_state.get("_cookie_load_attempts", 0)
    if attempts < MAX_COOKIE_LOAD_ATTEMPTS:
        st.session_state._cookie_load_attempts = attempts + 1
        st.rerun()

    return None


def persist_session(token: str) -> None:
    st.session_state.token = token
    st.session_state.pop("_cookie_load_attempts", None)
    get_cookie_manager().set(
        AUTH_COOKIE_NAME,
        token,
        max_age=settings.access_token_expire_minutes * 60,
        same_site="lax",
        key="set_auth_token",
    )


def clear_session() -> None:
    st.session_state.token = None
    st.session_state.pop("_cookie_load_attempts", None)
    get_cookie_manager().delete(AUTH_COOKIE_NAME, key="delete_auth_token")
