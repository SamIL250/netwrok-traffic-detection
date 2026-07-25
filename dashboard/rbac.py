import streamlit as st

ROLE_ADMIN = "admin"
ROLE_ANALYST = "analyst"
ROLE_VIEWER = "viewer"

ROLE_LABELS = {
    ROLE_ADMIN: "Administrator",
    ROLE_ANALYST: "Analyst",
    ROLE_VIEWER: "Viewer",
}


def role_label(role: str) -> str:
    return ROLE_LABELS.get(role, role.title())


def is_viewer(role: str) -> bool:
    return role == ROLE_VIEWER


def can_review_anomalies(role: str) -> bool:
    return role in {ROLE_ADMIN, ROLE_ANALYST}


def can_run_detection(role: str) -> bool:
    return role in {ROLE_ADMIN, ROLE_ANALYST}


def can_run_network_scan(role: str) -> bool:
    return role in {ROLE_ADMIN, ROLE_ANALYST}


def can_authorize_devices(role: str) -> bool:
    return role == ROLE_ADMIN


def can_manage_signatures(role: str) -> bool:
    return role in {ROLE_ADMIN, ROLE_ANALYST}


def can_retry_alerts(role: str) -> bool:
    return role in {ROLE_ADMIN, ROLE_ANALYST}


def can_send_test_email(role: str) -> bool:
    return role == ROLE_ADMIN


def can_export_traffic_logs(role: str) -> bool:
    return role in {ROLE_ADMIN, ROLE_ANALYST}


def can_manage_users(role: str) -> bool:
    return role == ROLE_ADMIN


def can_view_audit_logs(role: str) -> bool:
    return role == ROLE_ADMIN


def can_generate_reports(role: str) -> bool:
    return role == ROLE_ADMIN


def can_access_page(role: str, page: str) -> bool:
    admin_pages = {"User Management", "Audit Log", "Reports"}
    if page in admin_pages:
        return role == ROLE_ADMIN
    return True


def render_role_banner(role: str) -> None:
    if role == ROLE_VIEWER:
        st.info("Viewer access — monitoring pages are read-only. Contact an administrator to export data or change settings.")
