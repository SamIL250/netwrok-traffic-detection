import streamlit as st

AUTH_TOKEN_KEY = "token"


def get_stored_token() -> str | None:
    token = st.session_state.get(AUTH_TOKEN_KEY)
    if isinstance(token, str) and token:
        return token
    return None


def persist_session(token: str) -> None:
    st.session_state[AUTH_TOKEN_KEY] = token


def clear_session() -> None:
    st.session_state.pop(AUTH_TOKEN_KEY, None)


def logout_session(token: str | None) -> None:
    if token:
        import requests

        from nta.config import settings

        try:
            requests.post(
                f"{settings.api_base_url.rstrip('/')}/api/auth/logout",
                headers={"Authorization": f"Bearer {token}"},
                timeout=20,
            )
        except requests.RequestException:
            pass

    clear_session()


def get_cookie_manager():
    """Kept for compatibility; auth no longer depends on browser cookies."""
    return None
