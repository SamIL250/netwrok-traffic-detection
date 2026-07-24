import io

import pandas as pd
import plotly.express as px
import requests
import streamlit as st

from nta.config import settings

st.set_page_config(page_title="Network Traffic Monitor", layout="wide")


def api_request(method: str, path: str, token: str | None = None, **kwargs: object) -> requests.Response:
    headers = kwargs.pop("headers", {})
    if token:
        headers["Authorization"] = f"Bearer {token}"
    url = f"{settings.api_base_url.rstrip('/')}{path}"
    return requests.request(method, url, headers=headers, timeout=20, **kwargs)


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
    if "token" not in st.session_state:
        st.session_state.token = None

    if st.session_state.token:
        return st.session_state.token

    st.title("Network Traffic Monitoring System")
    st.subheader("Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Sign in", type="primary"):
        token = login(username, password)
        if token:
            st.session_state.token = token
            st.rerun()
        st.error("Invalid username or password")

    st.info("Default admin: admin / Admin@123 (change after first login)")
    st.stop()


def main() -> None:
    token = require_login()

    st.sidebar.title("Navigation")
    page = st.sidebar.radio("Go to", ["Dashboard", "Traffic Logs", "Anomalies", "Password Checker"])
    if st.sidebar.button("Logout"):
        st.session_state.token = None
        st.rerun()

    me = api_request("GET", "/api/auth/me", token).json()
    st.sidebar.success(f"Signed in as {me['username']} ({me['role']})")

    if page == "Dashboard":
        render_dashboard(token)
    elif page == "Traffic Logs":
        render_traffic_logs(token)
    elif page == "Anomalies":
        render_anomalies(token, me["role"])
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

    if st.button("Run Detection Now"):
        result = api_request("POST", "/api/detection/run", token)
        if result.status_code == 200:
            anomalies = result.json()
            st.success(f"Detection complete. New anomalies: {len(anomalies)}")
        else:
            st.error("Detection failed")


def render_traffic_logs(token: str) -> None:
    st.title("Traffic Logs")
    src_ip = st.text_input("Filter by source IP (optional)")
    params = {"limit": 200}
    if src_ip:
        params["src_ip"] = src_ip

    logs = api_request("GET", "/api/traffic/logs", token, params=params).json()
    if not logs:
        st.info("No logs found.")
        return

    df = pd.DataFrame(logs)
    st.dataframe(df, use_container_width=True)

    csv_buffer = io.StringIO()
    df.to_csv(csv_buffer, index=False)
    st.download_button("Download CSV", csv_buffer.getvalue(), file_name="traffic_logs.csv", mime="text/csv")


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
