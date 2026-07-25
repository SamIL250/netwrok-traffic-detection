import logging
import random
import signal
import socket
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

import requests

from nta.config import settings

logger = logging.getLogger(__name__)

SAMPLE_SOURCES = ["10.0.0.12", "10.0.0.18", "10.0.0.25", "192.168.1.44"]
SAMPLE_DESTINATIONS = ["8.8.8.8", "1.1.1.1", "142.250.185.78", "10.0.0.1"]
SAMPLE_PORTS = [22, 53, 80, 443, 8080, 3306, 5432, 9000]


@dataclass
class AgentConfig:
    api_base_url: str = settings.api_base_url
    mode: str = settings.agent_mode
    interval_seconds: float = settings.agent_interval_seconds
    batch_size: int = settings.agent_batch_size
    interface: str = settings.agent_interface
    retry_seconds: float = settings.agent_retry_seconds
    subnet_prefix: str = settings.agent_subnet_prefix
    auto_detect: bool = settings.agent_auto_detect
    internal_api_key: str = settings.internal_api_key
    shutdown: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        if self.mode not in {"sample", "live"}:
            raise ValueError(f"Unsupported daemon mode: {self.mode}")


class TrafficCaptureAgent:
    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self._logs_sent = 0
        self._cycles = 0

    def run_daemon(self) -> None:
        self._register_signal_handlers()
        logger.info(
            "Starting traffic capture agent in daemon mode (mode=%s, interval=%ss, batch=%s)",
            self.config.mode,
            self.config.interval_seconds,
            self.config.batch_size,
        )

        if not self._wait_for_api():
            logger.error("API never became reachable. Exiting.")
            return

        if self.config.mode == "live":
            self._run_live_daemon()
        else:
            self._run_sample_daemon()

        logger.info("Traffic capture agent stopped (total logs sent: %s).", self._logs_sent)

    def _run_sample_daemon(self) -> None:
        while not self.config.shutdown:
            try:
                sent = self._capture_sample_batch()
                self._cycles += 1
                self._logs_sent += sent
                logger.info(
                    "Cycle %s complete: sent %s logs (total sent: %s)",
                    self._cycles,
                    sent,
                    self._logs_sent,
                )
                self._maybe_trigger_detection()
                time.sleep(self.config.interval_seconds)
            except requests.RequestException as exc:
                logger.error("Failed to send traffic logs: %s", exc)
                time.sleep(self.config.retry_seconds)

    def _run_live_daemon(self) -> None:
        try:
            from scapy.all import sniff
        except ImportError as exc:
            raise SystemExit("Scapy is required for live capture mode") from exc

        def handle_packet(packet: object) -> None:
            if self.config.shutdown:
                return
            try:
                payload = packet_to_payload(packet)
                if payload is None:
                    return
                post_log(self.config.api_base_url, payload)
                self._logs_sent += 1
                if self._logs_sent % self.config.batch_size == 0:
                    self._maybe_trigger_detection()
                if self._logs_sent % 25 == 0:
                    logger.info("Live capture running... total logs sent: %s", self._logs_sent)
            except requests.RequestException as exc:
                logger.error("Failed to send live traffic log: %s", exc)
                time.sleep(self.config.retry_seconds)

        logger.info("Starting continuous live capture on %s", self.config.interface)
        sniff(
            iface=self.config.interface,
            prn=handle_packet,
            store=False,
            stop_filter=lambda _packet: self.config.shutdown,
        )

    def run_once_sample(self, count: int, interval: float) -> None:
        for index in range(count):
            payload = generate_sample_log()
            post_log(self.config.api_base_url, payload)
            logger.info("[%s/%s] logged %s -> %s", index + 1, count, payload["src_ip"], payload["dst_ip"])
            time.sleep(interval)

    def run_once_live(self, interface: str, packet_limit: int) -> None:
        try:
            from scapy.all import IP, TCP, UDP, sniff
        except ImportError as exc:
            raise SystemExit("Scapy is required for live capture mode") from exc

        processed = {"count": 0}

        def handle_packet(packet: object) -> None:
            if processed["count"] >= packet_limit:
                return
            payload = packet_to_payload(packet)
            if payload is None:
                return
            post_log(self.config.api_base_url, payload)
            processed["count"] += 1
            logger.info(
                "[%s/%s] captured %s -> %s",
                processed["count"],
                packet_limit,
                payload["src_ip"],
                payload["dst_ip"],
            )

        logger.info("Starting one-shot live capture on %s", interface)
        sniff(iface=interface, prn=handle_packet, store=False, count=packet_limit)

    def scan_local_hosts(self) -> list[str]:
        active_hosts: list[str] = []
        for host in range(1, 255):
            ip = f"{self.config.subnet_prefix}{host}"
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.05)
            try:
                if sock.connect_ex((ip, 80)) == 0 or sock.connect_ex((ip, 443)) == 0:
                    active_hosts.append(ip)
            except OSError:
                pass
            finally:
                sock.close()
        return active_hosts

    def _register_signal_handlers(self) -> None:
        def handle_shutdown(signum: int, _frame: object) -> None:
            logger.info("Received signal %s; shutting down agent...", signum)
            self.config.shutdown = True

        signal.signal(signal.SIGINT, handle_shutdown)
        signal.signal(signal.SIGTERM, handle_shutdown)

    def _api_is_reachable(self) -> bool:
        response = requests.get(f"{self.config.api_base_url.rstrip('/')}/health", timeout=5)
        return response.status_code == 200

    def _wait_for_api(self) -> bool:
        while not self.config.shutdown:
            if self._api_is_reachable():
                logger.info("API reachable at %s", self.config.api_base_url)
                return True
            logger.warning(
                "API unreachable at %s; retrying in %ss",
                self.config.api_base_url,
                self.config.retry_seconds,
            )
            time.sleep(self.config.retry_seconds)
        return False

    def _capture_sample_batch(self) -> int:
        sent = 0
        for _ in range(self.config.batch_size):
            if self.config.shutdown:
                break
            payload = generate_sample_log()
            post_log(self.config.api_base_url, payload)
            sent += 1
        return sent

    def _maybe_trigger_detection(self) -> None:
        if not self.config.auto_detect or not self.config.internal_api_key:
            return
        try:
            count = trigger_detection(self.config.api_base_url, self.config.internal_api_key)
            logger.info("Auto-detection triggered after capture batch: %s new anomalies", count)
        except requests.RequestException as exc:
            logger.warning("Auto-detection request failed: %s", exc)


def generate_sample_log() -> dict[str, object]:
    encrypted = random.random() > 0.2
    return {
        "src_ip": random.choice(SAMPLE_SOURCES),
        "dst_ip": random.choice(SAMPLE_DESTINATIONS),
        "src_port": random.randint(1024, 65535),
        "dst_port": random.choice(SAMPLE_PORTS),
        "protocol": "HTTPS" if encrypted else "HTTP",
        "encrypted": encrypted,
        "packet_count": random.randint(1, 20),
        "byte_count": random.randint(100, 5000),
    }


def packet_to_payload(packet: object) -> dict[str, object] | None:
    from scapy.all import IP, TCP, UDP

    if not packet.haslayer(IP):
        return None

    ip_layer = packet[IP]
    protocol = "TCP"
    dst_port = None
    encrypted = False

    if packet.haslayer(TCP):
        dst_port = int(packet[TCP].dport)
        encrypted = dst_port == 443
    elif packet.haslayer(UDP):
        protocol = "UDP"
        dst_port = int(packet[UDP].dport)

    return {
        "src_ip": ip_layer.src,
        "dst_ip": ip_layer.dst,
        "dst_port": dst_port,
        "protocol": protocol,
        "encrypted": encrypted,
        "packet_count": 1,
        "byte_count": len(packet),
    }


def post_log(api_base_url: str, payload: dict[str, object]) -> None:
    response = requests.post(f"{api_base_url.rstrip('/')}/api/traffic/logs", json=payload, timeout=10)
    response.raise_for_status()


def trigger_detection(api_base_url: str, internal_api_key: str) -> int:
    response = requests.post(
        f"{api_base_url.rstrip('/')}/api/internal/detection/run",
        headers={"X-Internal-Api-Key": internal_api_key},
        timeout=20,
    )
    response.raise_for_status()
    return len(response.json())


def scan_local_hosts(subnet_prefix: str = "192.168.1.") -> list[str]:
    agent = TrafficCaptureAgent(AgentConfig(subnet_prefix=subnet_prefix))
    hosts = agent.scan_local_hosts()
    logger.info("Discovered %s active hosts at %s", len(hosts), datetime.now(timezone.utc).isoformat())
    for host in hosts:
        logger.info(" - %s", host)
    return hosts
