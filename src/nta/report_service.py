from datetime import date, datetime, time, timedelta, timezone
from io import BytesIO

from fpdf import FPDF
from sqlalchemy import func
from sqlalchemy.orm import Session

from nta.models import AlertDelivery, Anomaly, AnomalyStatus, NetworkScan, TrafficLog, User


def _apply_date_filter(query, column, start_date: date | None, end_date: date | None):
    if start_date:
        start_dt = datetime.combine(start_date, time.min, tzinfo=timezone.utc)
        query = query.filter(column >= start_dt)
    if end_date:
        end_dt = datetime.combine(end_date + timedelta(days=1), time.min, tzinfo=timezone.utc)
        query = query.filter(column < end_dt)
    return query


def format_report_period(start_date: date | None, end_date: date | None) -> str:
    if start_date and end_date:
        return f"{start_date.isoformat()} to {end_date.isoformat()}"
    if start_date:
        return f"From {start_date.isoformat()}"
    if end_date:
        return f"Up to {end_date.isoformat()}"
    return "All available data"


def _truncate(text: str, max_length: int = 80) -> str:
    cleaned = " ".join(text.split())
    if len(cleaned) <= max_length:
        return cleaned
    return f"{cleaned[: max_length - 3]}..."


class _ReportPDF(FPDF):
    def footer(self) -> None:
        self.set_y(-15)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(100, 100, 100)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")

    def section_title(self, title: str) -> None:
        self.set_font("Helvetica", "B", 12)
        self.set_text_color(20, 20, 20)
        self.cell(0, 8, title, new_x="LMARGIN", new_y="NEXT")
        self.ln(1)

    def body_text(self, text: str) -> None:
        self.set_font("Helvetica", "", 10)
        self.set_text_color(30, 30, 30)
        self.multi_cell(0, 5, text)
        self.ln(1)

    def key_value(self, label: str, value: str) -> None:
        self.set_font("Helvetica", "B", 10)
        self.cell(55, 6, f"{label}:")
        self.set_font("Helvetica", "", 10)
        self.cell(0, 6, value, new_x="LMARGIN", new_y="NEXT")

    def simple_table(self, headers: list[str], rows: list[list[str]], col_widths: list[int]) -> None:
        self.set_font("Helvetica", "B", 9)
        self.set_fill_color(230, 230, 230)
        for index, header in enumerate(headers):
            self.cell(col_widths[index], 7, header, border=1, fill=True)
        self.ln()

        self.set_font("Helvetica", "", 9)
        for row in rows:
            for index, value in enumerate(row):
                self.cell(col_widths[index], 7, _truncate(value, 48), border=1)
            self.ln()


def generate_network_report_pdf(
    db: Session,
    generated_by: User,
    start_date: date | None = None,
    end_date: date | None = None,
) -> bytes:
    traffic_query = db.query(TrafficLog)
    traffic_query = _apply_date_filter(traffic_query, TrafficLog.captured_at, start_date, end_date)

    anomaly_query = db.query(Anomaly)
    anomaly_query = _apply_date_filter(anomaly_query, Anomaly.detected_at, start_date, end_date)

    total_sessions = traffic_query.count()
    unique_ips = traffic_query.with_entities(func.count(func.distinct(TrafficLog.src_ip))).scalar() or 0
    encrypted_count = traffic_query.filter(TrafficLog.encrypted.is_(True)).count()
    encrypted_ratio = round((encrypted_count / total_sessions * 100), 2) if total_sessions else 0.0
    open_anomalies = anomaly_query.filter(Anomaly.status == AnomalyStatus.OPEN.value).count()
    total_anomalies = anomaly_query.count()

    anomaly_type_rows = (
        anomaly_query.with_entities(Anomaly.anomaly_type, func.count(Anomaly.id))
        .group_by(Anomaly.anomaly_type)
        .order_by(func.count(Anomaly.id).desc())
        .all()
    )
    anomaly_severity_rows = (
        anomaly_query.with_entities(Anomaly.severity, func.count(Anomaly.id))
        .group_by(Anomaly.severity)
        .order_by(func.count(Anomaly.id).desc())
        .all()
    )
    anomaly_status_rows = (
        anomaly_query.with_entities(Anomaly.status, func.count(Anomaly.id))
        .group_by(Anomaly.status)
        .order_by(func.count(Anomaly.id).desc())
        .all()
    )

    recent_anomalies = anomaly_query.order_by(Anomaly.detected_at.desc()).limit(15).all()

    top_sources = (
        traffic_query.with_entities(TrafficLog.src_ip, func.count(TrafficLog.id))
        .group_by(TrafficLog.src_ip)
        .order_by(func.count(TrafficLog.id).desc())
        .limit(10)
        .all()
    )
    protocol_rows = (
        traffic_query.with_entities(TrafficLog.protocol, func.count(TrafficLog.id))
        .group_by(TrafficLog.protocol)
        .order_by(func.count(TrafficLog.id).desc())
        .all()
    )

    latest_scan = db.query(NetworkScan).order_by(NetworkScan.started_at.desc()).first()

    alert_query = db.query(AlertDelivery)
    alert_query = _apply_date_filter(alert_query, AlertDelivery.created_at, start_date, end_date)
    alerts_sent = alert_query.filter(AlertDelivery.status == "sent").count()
    alerts_failed = alert_query.filter(AlertDelivery.status == "failed").count()

    generated_at = datetime.now(timezone.utc)
    pdf = _ReportPDF()
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "Network Traffic Monitoring Report", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(0, 7, "ULK Kigali - ICT Security Monitoring", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.ln(4)

    pdf.section_title("Report Information")
    pdf.key_value("Generated at", generated_at.strftime("%Y-%m-%d %H:%M UTC"))
    pdf.key_value("Generated by", generated_by.username)
    pdf.key_value("Report period", format_report_period(start_date, end_date))
    pdf.ln(2)

    pdf.section_title("Executive Summary")
    pdf.key_value("Traffic sessions", str(total_sessions))
    pdf.key_value("Unique source IPs", str(unique_ips))
    pdf.key_value("Encrypted traffic", f"{encrypted_ratio}%")
    pdf.key_value("Total anomalies", str(total_anomalies))
    pdf.key_value("Open anomalies", str(open_anomalies))
    pdf.key_value("Email alerts sent", str(alerts_sent))
    pdf.key_value("Email alerts failed", str(alerts_failed))
    pdf.ln(2)

    pdf.section_title("Anomaly Breakdown")
    if anomaly_type_rows:
        pdf.body_text("By type:")
        pdf.simple_table(
            ["Type", "Count"],
            [[item[0].replace("_", " ").title(), str(item[1])] for item in anomaly_type_rows],
            [130, 50],
        )
        pdf.ln(2)
    if anomaly_severity_rows:
        pdf.body_text("By severity:")
        pdf.simple_table(
            ["Severity", "Count"],
            [[item[0].title(), str(item[1])] for item in anomaly_severity_rows],
            [130, 50],
        )
        pdf.ln(2)
    if anomaly_status_rows:
        pdf.body_text("By status:")
        pdf.simple_table(
            ["Status", "Count"],
            [[item[0].replace("_", " ").title(), str(item[1])] for item in anomaly_status_rows],
            [130, 50],
        )
        pdf.ln(2)

    pdf.section_title("Recent Anomalies")
    if recent_anomalies:
        pdf.simple_table(
            ["Type", "Severity", "Status", "Source IP", "Description"],
            [
                [
                    item.anomaly_type.replace("_", " ").title(),
                    item.severity.title(),
                    item.status.replace("_", " ").title(),
                    item.source_ip,
                    _truncate(item.description, 60),
                ]
                for item in recent_anomalies
            ],
            [35, 22, 22, 28, 73],
        )
    else:
        pdf.body_text("No anomalies recorded for the selected period.")
    pdf.ln(2)

    pdf.section_title("Traffic Summary")
    if top_sources:
        pdf.body_text("Top traffic sources:")
        pdf.simple_table(
            ["Source IP", "Sessions"],
            [[item[0], str(item[1])] for item in top_sources],
            [100, 80],
        )
        pdf.ln(2)
    if protocol_rows:
        pdf.body_text("Traffic by protocol:")
        pdf.simple_table(
            ["Protocol", "Sessions"],
            [[item[0], str(item[1])] for item in protocol_rows],
            [100, 80],
        )
        pdf.ln(2)
    if not top_sources and not protocol_rows:
        pdf.body_text("No traffic logs recorded for the selected period.")

    pdf.section_title("Network Scan Summary")
    if latest_scan:
        pdf.key_value("Latest subnet", latest_scan.subnet_prefix)
        pdf.key_value("Status", latest_scan.status.title())
        pdf.key_value("Active devices", str(latest_scan.device_count))
        pdf.key_value("Unauthorized devices", str(latest_scan.unauthorized_count))
        scan_time = latest_scan.completed_at or latest_scan.started_at
        if scan_time.tzinfo is None:
            scan_time = scan_time.replace(tzinfo=timezone.utc)
        pdf.key_value("Scan time", scan_time.strftime("%Y-%m-%d %H:%M UTC"))
    else:
        pdf.body_text("No network scans have been recorded yet.")

    buffer = BytesIO()
    pdf.output(buffer)
    return buffer.getvalue()
