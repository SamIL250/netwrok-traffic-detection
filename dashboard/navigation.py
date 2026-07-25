import streamlit as st

NAV_PAGE_KEY = "nav_page"

SIDEBAR_CSS = """
<style>
    @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&display=swap');
    @import url('https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@24,400,0,0&display=swap');

    html, body, [data-testid="stAppViewContainer"], [data-testid="stSidebar"] {
        font-family: 'Poppins', sans-serif;
    }

    [data-testid="stSidebar"] {
        background: #f8fafc;
        border-right: 1px solid #e2e8f0;
    }

    [data-testid="stSidebar"] > div:first-child {
        height: 100vh;
        max-height: 100vh;
        display: flex;
        flex-direction: column;
        overflow: hidden;
        padding-top: 0;
        padding-bottom: 0;
    }

    [data-testid="stSidebarUserContent"] {
        display: flex;
        flex-direction: column;
        flex: 1 1 0;
        min-height: 0;
        max-height: 100%;
        overflow: hidden;
        padding-top: 0;
        padding-bottom: 0;
    }

    [data-testid="stSidebarUserContent"] > div[data-testid="stVerticalBlockBorderWrapper"]:has(.nav-scroll-area-marker) {
        flex: 0 0 auto;
        height: calc(100vh - 19rem);
        max-height: calc(100vh - 19rem);
        min-height: 10rem;
        overflow: hidden;
    }

    [data-testid="stSidebarUserContent"] > div[data-testid="stVerticalBlockBorderWrapper"]:has(.nav-scroll-area-marker) [data-testid="stVerticalBlock"] > div {
        height: 100% !important;
        max-height: 100% !important;
        overflow-y: auto !important;
        overflow-x: hidden !important;
        scrollbar-width: thin;
        scrollbar-color: #cbd5e1 transparent;
    }

    [data-testid="stSidebarUserContent"] > div[data-testid="stVerticalBlockBorderWrapper"]:has(.nav-scroll-area-marker) [data-testid="stVerticalBlock"] > div::-webkit-scrollbar {
        width: 6px;
    }

    [data-testid="stSidebarUserContent"] > div[data-testid="stVerticalBlockBorderWrapper"]:has(.nav-scroll-area-marker) [data-testid="stVerticalBlock"] > div::-webkit-scrollbar-thumb {
        background: #cbd5e1;
        border-radius: 999px;
    }

    [data-testid="stSidebarUserContent"] > div[data-testid="stVerticalBlockBorderWrapper"]:has(.nav-scroll-area-marker) [data-testid="stVerticalBlock"] {
        height: 100%;
        max-height: 100%;
        overflow: hidden;
    }

    [data-testid="stSidebar"] .nav-brand-sticky {
        flex-shrink: 0;
        background: #f8fafc;
        padding: 1.1rem 0.85rem 0.85rem 0.85rem;
        margin: 0;
        border-bottom: 1px solid #e2e8f0;
    }

    [data-testid="stSidebar"] [data-testid="stVerticalBlock"]:has(.nav-brand-sticky) {
        flex-shrink: 0;
    }

    [data-testid="stSidebarUserContent"] > div[data-testid="stVerticalBlockBorderWrapper"]:has(.nav-brand-sticky) {
        flex-shrink: 0;
    }

    [data-testid="stSidebarUserContent"] > div[data-testid="stVerticalBlockBorderWrapper"]:has(.nav-footer-shell-marker) {
        flex-shrink: 0;
        background: #f8fafc;
        border-top: 1px solid #e2e8f0;
        padding: 0.75rem 0.85rem 0.15rem 0.85rem;
    }

    [data-testid="stSidebar"] .nav-scroll-area-marker,
    [data-testid="stSidebar"] .nav-footer-shell-marker {
        display: none;
    }

    [data-testid="stSidebarUserContent"] > div[data-testid="stVerticalBlockBorderWrapper"]:has(.nav-footer-shell-marker) .nav-user-card {
        margin-top: 0;
    }

    [data-testid="stSidebarUserContent"] > div[data-testid="stVerticalBlockBorderWrapper"]:has(.nav-footer-shell-marker) div.stButton > button {
        margin-top: 0.35rem;
    }

    [data-testid="stSidebar"] .nav-brand {
        padding: 0;
    }

    [data-testid="stSidebar"] .nav-brand-divider {
        display: none;
    }

    [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p.nav-section-label {
        margin: 1.1rem 0 0.4rem 0;
        padding: 0 0.15rem 0 0.85rem;
        font-size: 0.68rem;
        font-weight: 600;
        letter-spacing: 0.12em;
        text-transform: uppercase;
        color: #94a3b8;
        text-align: left;
    }

    [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p.nav-section-label:first-of-type {
        margin-top: 0.15rem;
    }

    [data-testid="stSidebar"] .nav-brand-title {
        margin: 0;
        font-size: 1.05rem;
        font-weight: 700;
        color: #0f172a;
        letter-spacing: -0.02em;
        line-height: 1.2;
        text-align: left;
    }

    [data-testid="stSidebar"] .nav-brand-subtitle {
        margin: 0.35rem 0 0 0;
        font-size: 0.78rem;
        color: #64748b;
        line-height: 1.4;
        text-align: left;
    }

    [data-testid="stSidebar"] .nav-brand-badge {
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

    [data-testid="stSidebar"] .nav-user-card {
        padding: 0.85rem 0.95rem;
        border-radius: 14px;
        background: #ffffff;
        border: 1px solid #e2e8f0;
        box-shadow: 0 1px 2px rgba(15, 23, 42, 0.04);
    }

    [data-testid="stSidebar"] .nav-user-label {
        margin: 0;
        font-size: 0.68rem;
        font-weight: 600;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: #94a3b8;
        text-align: left;
    }

    [data-testid="stSidebar"] .nav-user-name {
        margin: 0.25rem 0 0 0;
        font-size: 0.95rem;
        font-weight: 700;
        color: #0f172a;
        text-align: left;
    }

    [data-testid="stSidebar"] .nav-user-role {
        display: inline-block;
        margin-top: 0.45rem;
        padding: 0.18rem 0.55rem;
        border-radius: 999px;
        background: #ecfdf5;
        border: 1px solid #bbf7d0;
        color: #059669;
        font-size: 0.72rem;
        font-weight: 600;
        text-transform: capitalize;
    }

    [data-testid="stSidebar"] div[data-testid="stVerticalBlock"] div.stButton {
        padding-left: 0.85rem;
    }

    [data-testid="stSidebar"] div[data-testid="stVerticalBlock"] div.stButton > button {
        position: relative;
        display: flex !important;
        align-items: center !important;
        justify-content: flex-start !important;
        gap: 0.65rem !important;
        width: 100%;
        min-height: 2.65rem;
        margin: 0.12rem 0;
        padding: 0.55rem 0.85rem 0.55rem 1rem !important;
        border: 1px solid transparent;
        border-radius: 12px;
        background: transparent;
        color: #475569;
        font-family: 'Poppins', sans-serif;
        font-size: 0.92rem;
        font-weight: 500;
        text-align: left !important;
        box-shadow: none;
        overflow: visible;
        transition: background 0.18s ease, color 0.18s ease, border-color 0.18s ease;
    }

    [data-testid="stSidebar"] div[data-testid="stVerticalBlock"] div.stButton > button > span {
        font-family: 'Material Symbols Outlined' !important;
        font-variation-settings: 'FILL' 0, 'wght' 400, 'GRAD' 0, 'opsz' 24;
        font-size: 1.15rem !important;
        line-height: 1 !important;
        flex-shrink: 0;
        width: auto !important;
        min-width: 1.15rem;
    }

    [data-testid="stSidebar"] div[data-testid="stVerticalBlock"] div.stButton > button p {
        font-family: 'Poppins', sans-serif !important;
        text-align: left !important;
        margin: 0 !important;
    }

    [data-testid="stSidebar"] div[data-testid="stVerticalBlock"] div.stButton > button div {
        text-align: left !important;
        justify-content: flex-start !important;
        flex: 1;
    }

    [data-testid="stSidebar"] div[data-testid="stVerticalBlock"] div.stButton > button:hover {
        background: #f1f5f9;
        border-color: #e2e8f0;
        color: #0f172a;
    }

    [data-testid="stSidebar"] div[data-testid="stVerticalBlock"] div.stButton > button[kind="primary"] {
        background: #eff6ff;
        border-color: #dbeafe;
        color: #1d4ed8;
        box-shadow: none;
    }

    [data-testid="stSidebar"] div[data-testid="stVerticalBlock"] div.stButton > button[kind="primary"]::before {
        content: "";
        position: absolute;
        left: -0.72rem;
        top: 50%;
        transform: translateY(-50%);
        width: 4px;
        height: 1.45rem;
        border-radius: 999px;
        background: #2563eb;
        box-shadow: 0 0 0 3px #f8fafc;
    }

    [data-testid="stSidebar"] div[data-testid="stVerticalBlock"] div.stButton > button[kind="primary"]:hover {
        background: #dbeafe;
        border-color: #bfdbfe;
        color: #1e40af;
    }

    [data-testid="stSidebar"] div[data-testid="stVerticalBlock"] div.stButton > button[kind="primary"]:hover::before {
        box-shadow: 0 0 0 3px #f1f5f9;
    }

    [data-testid="stSidebar"] hr {
        margin: 1rem 0;
        border: none;
        border-top: 1px solid #e2e8f0;
    }

    [data-testid="stSidebar"] [data-testid="stWidgetLabel"] {
        display: none;
    }

    [data-testid="stSidebar"] [data-testid="stSidebarCollapseButton"] {
        color: #64748b;
        font-family: 'Material Symbols Outlined' !important;
        font-variation-settings: 'FILL' 0, 'wght' 400, 'GRAD' 0, 'opsz' 24;
    }

    [data-testid="stSidebar"] [data-testid="stSidebarCollapseButton"] span {
        font-family: 'Material Symbols Outlined' !important;
    }
</style>
"""

NAV_SECTIONS: list[dict[str, object]] = [
    {
        "label": "Monitoring",
        "items": [
            {"id": "Dashboard", "label": "Dashboard", "icon": ":material/dashboard:"},
            {"id": "Network Scan", "label": "Network Scan", "icon": ":material/radar:"},
            {"id": "Traffic Logs", "label": "Traffic Logs", "icon": ":material/swap_horiz:"},
            {"id": "Anomalies", "label": "Anomalies", "icon": ":material/gpp_maybe:"},
            {"id": "Intrusion Analytics", "label": "Intrusion Analytics", "icon": ":material/analytics:"},
            {"id": "Alert Management", "label": "Alert Management", "icon": ":material/notifications_active:"},
        ],
    },
    {
        "label": "Administration",
        "roles": ["admin"],
        "items": [
            {"id": "User Management", "label": "User Management", "icon": ":material/manage_accounts:"},
            {"id": "Audit Log", "label": "Audit Log", "icon": ":material/history:"},
            {"id": "Reports", "label": "Reports", "icon": ":material/description:"},
        ],
    },
    {
        "label": "Security Tools",
        "items": [
            {"id": "Password Checker", "label": "Password Checker", "icon": ":material/verified_user:"},
            {"id": "Change Password", "label": "Change Password", "icon": ":material/lock:"},
        ],
    },
]

DEFAULT_PAGE = "Dashboard"


def _visible_sections(role: str) -> list[dict[str, object]]:
    sections: list[dict[str, object]] = []
    for section in NAV_SECTIONS:
        allowed_roles = section.get("roles")
        if allowed_roles and role not in allowed_roles:
            continue
        sections.append(section)
    return sections


def _all_page_ids(role: str) -> list[str]:
    page_ids: list[str] = []
    for section in _visible_sections(role):
        for item in section["items"]:  # type: ignore[index]
            page_ids.append(str(item["id"]))
    return page_ids


def render_sidebar_brand() -> None:
    st.markdown(
        """
        <div class="nav-brand-sticky">
            <div class="nav-brand">
                <p class="nav-brand-title">Network Traffic Monitor</p>
                <p class="nav-brand-subtitle">ULK Kigali security operations console</p>
                <span class="nav-brand-badge">Live monitoring</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_sidebar_user(me: dict[str, str]) -> None:
    st.markdown(
        f"""
        <div class="nav-user-card">
            <p class="nav-user-label">Signed in as</p>
            <p class="nav-user-name">{me["username"]}</p>
            <span class="nav-user-role">{me["role"]}</span>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _render_nav_links(me: dict[str, str], current_page: str) -> None:
    for section in _visible_sections(me["role"]):
        st.markdown(f'<p class="nav-section-label">{section["label"]}</p>', unsafe_allow_html=True)
        for item in section["items"]:  # type: ignore[index]
            page_id = str(item["id"])
            is_active = current_page == page_id
            if st.button(
                str(item["label"]),
                key=f"nav_{page_id}",
                icon=str(item["icon"]),
                use_container_width=True,
                type="primary" if is_active else "secondary",
            ):
                st.session_state[NAV_PAGE_KEY] = page_id
                st.rerun()


def render_sidebar_footer(me: dict[str, str]) -> str | None:
    with st.container(border=False):
        st.markdown('<div class="nav-footer-shell-marker"></div>', unsafe_allow_html=True)
        render_sidebar_user(me)
        if st.button("Sign out", key="nav_logout", icon=":material/logout:", use_container_width=True):
            return "__logout__"
    return None


def render_sidebar_nav(me: dict[str, str]) -> str:
    st.markdown(SIDEBAR_CSS, unsafe_allow_html=True)
    render_sidebar_brand()

    allowed_pages = _all_page_ids(me["role"])
    current_page = st.session_state.get(NAV_PAGE_KEY, DEFAULT_PAGE)
    if current_page not in allowed_pages:
        current_page = DEFAULT_PAGE
        st.session_state[NAV_PAGE_KEY] = current_page

    with st.container(height=320, border=False):
        st.markdown('<div class="nav-scroll-area-marker"></div>', unsafe_allow_html=True)
        _render_nav_links(me, current_page)

    logout = render_sidebar_footer(me)
    if logout:
        return logout

    return current_page
