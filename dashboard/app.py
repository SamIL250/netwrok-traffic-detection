import io

import pandas as pd
import plotly.express as px
import requests
import streamlit as st

from session import clear_session, get_cookie_manager, get_stored_token, persist_session
from nta.config import settings

st.set_page_config(page_title="Network Traffic Monitor", layout="wide")


def api_request(method: str, path: str, token: str | None = None, timeout: int = 20, **kwargs: object) -> requests.Response:
    headers = kwargs.pop("headers", {})
    if token:
        headers["Authorization"] = f"Bearer {token}"
    url = f"{settings.api_base_url.rstrip('/')}{path}"
    return requests.request(method, url, headers=headers, timeout=timeout, **kwargs)


def format_api_error(response: requests.Response, fallback: str = "Request failed.") -> str:
    try:
        payload = response.json()
    except ValueError:
        return fallback

    detail = payload.get("detail")
    if isinstance(detail, str):
        return detail
    if isinstance(detail, list):
        messages: list[str] = []
        for item in detail:
            if not isinstance(item, dict):
                continue
            msg = item.get("msg")
            if not isinstance(msg, str):
                continue
            loc = item.get("loc", [])
            field = loc[-1] if loc else None
            if isinstance(field, str):
                label = field.replace("_", " ").strip().title()
                messages.append(f"{label}: {msg}.")
            else:
                messages.append(f"{msg}.")
        if messages:
            return " ".join(messages)
    return fallback


def login(username: str, password: str) -> str | None:
    response = requests.post(
        f"{settings.api_base_url.rstrip('/')}/api/auth/login",
        data={"username": username, "password": password},
        timeout=20,
    )
    if response.status_code != 200:
        return None
    return response.json()["access_token"]


def require_login() -> str:
    token = get_stored_token()
    if token:
        return token

    st.title("Network Traffic Monitoring System")
    st.subheader("Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Sign in", type="primary"):
        token = login(username, password)
        if token:
            persist_session(token)
            st.rerun()
        st.error("Invalid username or password")

    st.info("Default admin: admin / Admin@123 (change after first login)")
    st.stop()


def main() -> None:
    get_cookie_manager()
    token = require_login()

    me_response = api_request("GET", "/api/auth/me", token)
    if me_response.status_code == 401:
        clear_session()
        st.rerun()
    if me_response.status_code != 200:
        st.error("Could not verify your session. Check that the API is running.")
        st.stop()

    me = me_response.json()

    st.sidebar.title("Navigation")
    pages = [
        "Dashboard",
        "Network Scan",
        "Traffic Logs",
        "Anomalies",
        "Email Alerts",
        "Password Checker",
        "Change Password",
    ]
    if me["role"] == "admin":
        pages.insert(-1, "User Management")
        pages.insert(-1, "Audit Log")
    page = st.sidebar.radio("Go to", pages)
    if st.sidebar.button("Logout"):
        clear_session()
        st.rerun()

    st.sidebar.success(f"Signed in as {me['username']} ({me['role']})")

    if page == "Dashboard":
        render_dashboard(token)
    elif page == "Network Scan":
        render_network_scan(token, me["role"])
    elif page == "Traffic Logs":
        render_traffic_logs(token)
    elif page == "Anomalies":
        render_anomalies(token, me["role"])
    elif page == "Email Alerts":
        render_email_alerts(token, me["role"])
    elif page == "User Management":
        render_user_management(token, me)
    elif page == "Audit Log":
        render_audit_logs(token, me)
    elif page == "Change Password":
        render_change_password(token)
    else:
        render_password_checker(token)


def render_dashboard(token: str) -> None:
    st.title("Monitoring Dashboard")
    stats = api_request("GET", "/api/dashboard/stats", token).json()

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Sessions", stats["total_sessions"])
    col2.metric("Unique IPs", stats["unique_ips"])
    col3.metric("Encrypted Traffic", f"{stats['encrypted_ratio']}%")
    col4.metric("Open Anomalies", stats["open_anomalies"])

    logs = api_request("GET", "/api/traffic/logs", token, params={"limit": 200}).json()
    if logs:
        df = pd.DataFrame(logs)
        df["captured_at"] = pd.to_datetime(df["captured_at"])
        hourly = df.groupby(df["captured_at"].dt.floor("h")).size().reset_index(name="sessions")
        fig = px.line(hourly, x="captured_at", y="sessions", title="Sessions Over Time")
        st.plotly_chart(fig, use_container_width=True)

        top_sources = df["src_ip"].value_counts().head(10).reset_index()
        top_sources.columns = ["src_ip", "count"]
        st.plotly_chart(px.bar(top_sources, x="src_ip", y="count", title="Top Traffic Sources"), use_container_width=True)
    else:
        st.warning("No traffic logs yet. Run the agent in sample mode to generate data.")

    st.info("Anomaly detection runs automatically on a schedule and after each agent capture batch.")
    if st.button("Run Detection Now (manual)"):
        result = api_request("POST", "/api/detection/run", token)
        if result.status_code == 200:
            anomalies = result.json()
            st.success(f"Detection complete. New anomalies: {len(anomalies)}")
        else:
            st.error("Detection failed")


def render_network_scan(token: str, role: str) -> None:
    st.title("Network Scanner")
    st.caption("Discover active hosts on the network and flag unauthorized devices.")

    scans = api_request("GET", "/api/network/scans", token, params={"limit": 1}).json()
    if scans:
        latest = scans[0]
        col1, col2, col3 = st.columns(3)
        col1.metric("Active Devices", latest["device_count"])
        col2.metric("Unauthorized Devices", latest["unauthorized_count"])
        col3.metric("Last Scan", latest["completed_at"] or latest["started_at"])

    with st.expander("Run a new scan", expanded=not scans):
        subnet_prefix = st.text_input("Subnet prefix", value=settings.agent_subnet_prefix)
        if role in {"admin", "analyst"}:
            if st.button("Start Network Scan", type="primary"):
                with st.spinner("Scanning network... this may take up to a minute."):
                    response = api_request(
                        "POST",
                        "/api/network/scans",
                        token,
                        json={"subnet_prefix": subnet_prefix},
                        timeout=120,
                    )
                if response.status_code == 200:
                    result = response.json()
                    st.success(
                        f"Scan complete: {result['device_count']} active devices, "
                        f"{result['unauthorized_count']} unauthorized."
                    )
                    st.rerun()
                else:
                    st.error("Network scan failed.")
        else:
            st.info("Only admins and analysts can start a network scan.")

    devices = api_request("GET", "/api/network/devices", token).json()
    if not devices:
        st.info("No scan results yet. Run a network scan to discover active devices.")
        return

    df = pd.DataFrame(devices)
    unauthorized = df[df["is_authorized"] == False]  # noqa: E712
    authorized = df[df["is_authorized"] == True]  # noqa: E712

    tab_all, tab_unauthorized, tab_authorized, tab_known = st.tabs(
        ["All Devices", "Unauthorized", "Authorized", "Known Devices"]
    )

    with tab_all:
        st.dataframe(df[["ip_address", "status", "open_ports", "discovered_at"]], use_container_width=True)

    with tab_unauthorized:
        if unauthorized.empty:
            st.success("No unauthorized devices in the latest scan.")
        else:
            st.dataframe(unauthorized[["ip_address", "open_ports", "discovered_at"]], use_container_width=True)

    with tab_authorized:
        st.dataframe(authorized[["ip_address", "open_ports", "discovered_at"]], use_container_width=True)

    with tab_known:
        known_devices = api_request("GET", "/api/network/known-devices", token).json()
        if known_devices:
            st.dataframe(pd.DataFrame(known_devices), use_container_width=True)
        else:
            st.info("No authorized device list configured yet.")

    if role == "admin" and not unauthorized.empty:
        st.subheader("Authorize a device")
        selected_ip = st.selectbox("Select unauthorized device", unauthorized["ip_address"].tolist())
        label = st.text_input("Device label", value=f"Authorized device {selected_ip}")
        if st.button("Mark as Authorized"):
            response = api_request(
                "POST",
                "/api/network/known-devices",
                token,
                json={"ip_address": selected_ip, "label": label},
            )
            if response.status_code == 200:
                st.success(f"{selected_ip} added to the authorized device list.")
                st.rerun()
            else:
                st.error("Could not authorize device.")


def _log_traffic_log_export() -> None:
    token = st.session_state.get("token")
    details = st.session_state.get("traffic_export_audit_details")
    if not token or not details:
        return
    api_request(
        "POST",
        "/api/audit/client-events",
        token,
        json={"resource": "traffic_logs", "details": details},
    )


def render_traffic_logs(token: str) -> None:
    st.title("Traffic Logs")
    st.caption("Filter logs by source IP and/or date range. CSV export uses the current filters.")

    src_ip = st.text_input("Source IP (optional)")
    filter_by_date = st.checkbox("Filter by date range", value=False)

    start_date = None
    end_date = None
    if filter_by_date:
        col_from, col_to = st.columns(2)
        with col_from:
            start_date = st.date_input("From date", key="traffic-start-date")
        with col_to:
            end_date = st.date_input("To date", key="traffic-end-date")

    params: dict[str, object] = {"limit": 200}
    if src_ip:
        params["src_ip"] = src_ip.strip()
    if start_date:
        params["start_date"] = start_date.isoformat()
    if end_date:
        params["end_date"] = end_date.isoformat()

    if start_date and end_date and start_date > end_date:
        st.error("From date must be on or before to date.")
        return

    response = api_request("GET", "/api/traffic/logs", token, params=params)
    if response.status_code != 200:
        st.error(format_api_error(response, "Could not load traffic logs."))
        return

    logs = response.json()
    if not logs:
        st.info("No logs found for the selected filters.")
        return

    df = pd.DataFrame(logs)
    st.caption(f"Showing {len(df)} log entries")
    st.dataframe(df, use_container_width=True)

    filter_parts: list[str] = []
    if src_ip:
        filter_parts.append(f"source IP {src_ip.strip()}")
    if start_date:
        filter_parts.append(f"from {start_date.isoformat()}")
    if end_date:
        filter_parts.append(f"to {end_date.isoformat()}")
    filter_summary = ", ".join(filter_parts) if filter_parts else "no filters"
    st.session_state.traffic_export_audit_details = f"Exported {len(df)} traffic log rows ({filter_summary})"

    file_name_parts: list[str] = []
    if src_ip:
        file_name_parts.append(f"ip-{src_ip.strip()}")
    if start_date:
        file_name_parts.append(f"from-{start_date.isoformat()}")
    if end_date:
        file_name_parts.append(f"to-{end_date.isoformat()}")
    file_suffix = "_".join(file_name_parts) if file_name_parts else "all"
    csv_buffer = io.StringIO()
    df.to_csv(csv_buffer, index=False)
    st.download_button(
        "Download CSV",
        csv_buffer.getvalue(),
        file_name=f"traffic_logs_{file_suffix}.csv",
        mime="text/csv",
        on_click=_log_traffic_log_export,
    )


def render_audit_logs(token: str, me: dict) -> None:
    if me["role"] != "admin":
        st.error("Only administrators can view audit logs.")
        return

    st.title("Audit Log")
    st.caption("Track sign-ins, anomaly reviews, exports, and other administrative actions.")

    actions_response = api_request("GET", "/api/audit/actions", token)
    action_options = ["All actions"]
    if actions_response.status_code == 200:
        action_options.extend(actions_response.json())

    col_action, col_user = st.columns(2)
    with col_action:
        selected_action = st.selectbox("Action", action_options)
    with col_user:
        username = st.text_input("Username (optional)")

    filter_by_date = st.checkbox("Filter by date range", value=False, key="audit-filter-by-date")
    start_date = None
    end_date = None
    if filter_by_date:
        col_from, col_to = st.columns(2)
        with col_from:
            start_date = st.date_input("From date", key="audit-start-date")
        with col_to:
            end_date = st.date_input("To date", key="audit-end-date")

    if start_date and end_date and start_date > end_date:
        st.error("From date must be on or before to date.")
        return

    params: dict[str, object] = {"limit": 200}
    if selected_action != "All actions":
        params["action"] = selected_action
    if username.strip():
        params["username"] = username.strip()
    if start_date:
        params["start_date"] = start_date.isoformat()
    if end_date:
        params["end_date"] = end_date.isoformat()

    response = api_request("GET", "/api/audit/logs", token, params=params)
    if response.status_code != 200:
        st.error(format_api_error(response, "Could not load audit logs."))
        return

    logs = response.json()
    if not logs:
        st.info("No audit entries found for the selected filters.")
        return

    df = pd.DataFrame(logs)
    df["action_label"] = df["action"].str.replace("_", " ").str.title()
    df["username"] = df["username"].fillna("system")
    st.caption(f"Showing {len(df)} audit entries")
    st.dataframe(
        df[["created_at", "username", "action_label", "details"]].rename(
            columns={"created_at": "Time", "username": "User", "action_label": "Action", "details": "Details"}
        ),
        use_container_width=True,
        hide_index=True,
    )

    csv_buffer = io.StringIO()
    df[["created_at", "username", "action", "details"]].to_csv(csv_buffer, index=False)
    st.download_button(
        "Download Audit Log CSV",
        csv_buffer.getvalue(),
        file_name="audit_log.csv",
        mime="text/csv",
    )


def render_anomalies(token: str, role: str) -> None:
    st.title("Anomaly Alerts")
    anomalies = api_request("GET", "/api/anomalies", token).json()

    if not anomalies:
        st.info("No anomalies detected yet.")
        return

    for anomaly in anomalies:
        with st.expander(f"[{anomaly['severity'].upper()}] {anomaly['anomaly_type']} - {anomaly['source_ip']}"):
            st.write(anomaly["description"])
            st.caption(f"Status: {anomaly['status']} | Detected: {anomaly['detected_at']}")

            if role in {"admin", "analyst"} and anomaly["status"] == "open":
                notes = st.text_input("Review notes", key=f"notes-{anomaly['id']}")
                confirm_col, reject_col = st.columns(2)
                if confirm_col.button("Confirm Intrusion", key=f"confirm-{anomaly['id']}"):
                    response = api_request(
                        "POST",
                        f"/api/anomalies/{anomaly['id']}/feedback",
                        token,
                        json={"classification": "confirmed", "notes": notes},
                    )
                    if response.status_code == 200:
                        st.success("Marked as confirmed")
                        st.rerun()
                if reject_col.button("Mark False Positive", key=f"reject-{anomaly['id']}"):
                    response = api_request(
                        "POST",
                        f"/api/anomalies/{anomaly['id']}/feedback",
                        token,
                        json={"classification": "false_positive", "notes": notes},
                    )
                    if response.status_code == 200:
                        st.success("Marked as false positive")
                        st.rerun()


def render_email_alerts(token: str, role: str) -> None:
    st.title("Email Alerts")
    st.caption("Critical anomalies trigger SMTP email alerts and delivery history is stored here.")

    deliveries = api_request("GET", "/api/alerts/delivery", token, params={"limit": 50}).json()
    sent_count = sum(1 for item in deliveries if item["status"] == "sent")
    failed_count = sum(1 for item in deliveries if item["status"] == "failed")

    col1, col2, col3 = st.columns(3)
    col1.metric("Total Alerts", len(deliveries))
    col2.metric("Sent", sent_count)
    col3.metric("Failed", failed_count)

    if role == "admin":
        if st.button("Send Test Email"):
            response = api_request("POST", "/api/alerts/test-email", token)
            if response.status_code == 200:
                result = response.json()
                if result["status"] == "sent":
                    st.success(f"Test email sent to {result['recipient']}")
                else:
                    st.error(f"Test email failed: {result['error_detail']}")
                st.rerun()
            else:
                st.error("Could not send test email.")

    if not deliveries:
        st.info("No email alerts yet. They are sent automatically when high-severity anomalies are detected.")
        return

    df = pd.DataFrame(deliveries)
    st.dataframe(
        df[["created_at", "status", "recipient", "subject", "error_detail", "anomaly_id"]],
        use_container_width=True,
    )


def render_change_password(token: str) -> None:
    st.title("Change Password")
    st.caption("Update your account password. Use a strong password with mixed characters.")

    current_password = st.text_input("Current password", type="password")
    new_password = st.text_input("New password", type="password")
    confirm_password = st.text_input("Confirm new password", type="password")

    if new_password:
        strength = api_request("POST", "/api/password/strength", token, params={"password": new_password}).json()
        st.metric("New password strength", strength["level"].title())
        st.caption(strength["message"])

    if st.button("Update Password", type="primary"):
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
                st.success("Password updated successfully.")
            else:
                st.error(format_api_error(response, "Could not update password."))


def render_user_management(token: str, me: dict) -> None:
    if me["role"] != "admin":
        st.error("Only administrators can manage users.")
        return

    st.title("User Management")
    st.caption("Create accounts, assign roles, disable users, and reset passwords.")

    with st.expander("Create new user", expanded=False):
        username = st.text_input("Username", key="new-user-username")
        email = st.text_input("Email", key="new-user-email")
        password = st.text_input("Initial password", type="password", key="new-user-password")
        role_name = st.selectbox("Role", ["viewer", "analyst", "admin"], key="new-user-role")

        if password:
            strength = api_request("POST", "/api/password/strength", token, params={"password": password}).json()
            st.caption(f"Password strength: {strength['level']} — {strength['message']}")

        if st.button("Create User", type="primary", key="create-user-btn"):
            if not username or not email or not password:
                st.error("Username, email, and password are required.")
            else:
                response = api_request(
                    "POST",
                    "/api/users",
                    token,
                    json={
                        "username": username,
                        "email": email,
                        "password": password,
                        "role_name": role_name,
                    },
                )
                if response.status_code == 200:
                    st.success(f"User '{username}' created.")
                    st.rerun()
                else:
                    st.error(format_api_error(response, "Could not create user."))

    response = api_request("GET", "/api/users", token)
    if response.status_code != 200:
        st.error("Could not load users.")
        return

    users = response.json()
    if not users:
        st.info("No users found.")
        return

    df = pd.DataFrame(users)
    df["status"] = df["is_active"].map({True: "Active", False: "Disabled"})
    st.dataframe(
        df[["username", "email", "role", "status", "created_at"]],
        use_container_width=True,
        hide_index=True,
    )

    st.subheader("Manage user")
    role_order = ["admin", "analyst", "viewer"]
    user_labels = [
        f"{user['username']} ({user['role']}){' — disabled' if not user['is_active'] else ''}"
        for user in users
    ]
    selected_index = st.selectbox("Select user", range(len(users)), format_func=lambda i: user_labels[i])
    selected_user = users[selected_index]
    is_self = selected_user["id"] == me["id"]

    col1, col2 = st.columns(2)
    with col1:
        role_index = role_order.index(selected_user["role"]) if selected_user["role"] in role_order else 0
        new_role = st.selectbox(
            "Role",
            role_order,
            index=role_index,
            disabled=is_self,
            key=f"role-{selected_user['id']}",
        )
    with col2:
        account_enabled = st.checkbox(
            "Account enabled",
            value=selected_user["is_active"],
            disabled=is_self,
            key=f"active-{selected_user['id']}",
        )

    if is_self:
        st.info("You cannot change your own role or disable your own account.")

    role_changed = new_role != selected_user["role"]
    status_changed = account_enabled != selected_user["is_active"]

    if st.button("Save account changes", key=f"save-user-{selected_user['id']}"):
        if not role_changed and not status_changed:
            st.warning("No changes to save.")
        else:
            payload: dict[str, object] = {}
            if role_changed:
                payload["role_name"] = new_role
            if status_changed:
                payload["is_active"] = account_enabled

            update_response = api_request("PATCH", f"/api/users/{selected_user['id']}", token, json=payload)
            if update_response.status_code == 200:
                st.success(f"Updated account for {selected_user['username']}.")
                st.rerun()
            else:
                st.error(format_api_error(update_response, "Could not update user."))

    st.subheader("Force password reset")
    st.caption("Set a new password for this user. Share it securely; they should change it after signing in.")
    reset_password = st.text_input("New password", type="password", key=f"reset-pw-{selected_user['id']}")
    reset_confirm = st.text_input("Confirm new password", type="password", key=f"reset-pw-confirm-{selected_user['id']}")

    if reset_password:
        strength = api_request("POST", "/api/password/strength", token, params={"password": reset_password}).json()
        st.caption(f"Password strength: {strength['level']} — {strength['message']}")

    if st.button("Reset Password", key=f"reset-btn-{selected_user['id']}"):
        if not reset_password:
            st.error("Enter a new password.")
        elif reset_password != reset_confirm:
            st.error("Passwords do not match.")
        else:
            reset_response = api_request(
                "POST",
                f"/api/users/{selected_user['id']}/reset-password",
                token,
                json={"new_password": reset_password},
            )
            if reset_response.status_code == 200:
                st.success(f"Password reset for {selected_user['username']}.")
            else:
                st.error(format_api_error(reset_response, "Could not reset password."))


def render_password_checker(token: str) -> None:
    st.title("Password Strength Checker")
    password = st.text_input("Enter a password to evaluate", type="password")
    if password:
        result = api_request("POST", "/api/password/strength", token, params={"password": password}).json()
        st.metric("Strength", result["level"].title())
        st.write(result["message"])
        st.json(result["checks"])


if __name__ == "__main__":
    main()
