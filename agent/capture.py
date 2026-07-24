import argparse
import random
import socket
import time
from datetime import datetime

import requests

SAMPLE_SOURCES = ["10.0.0.12", "10.0.0.18", "10.0.0.25", "192.168.1.44"]
SAMPLE_DESTINATIONS = ["8.8.8.8", "1.1.1.1", "142.250.185.78", "10.0.0.1"]
SAMPLE_PORTS = [22, 53, 80, 443, 8080, 3306, 5432, 9000]


def post_log(api_base_url: str, payload: dict[str, object]) -> None:
    response = requests.post(f"{api_base_url.rstrip('/')}/api/traffic/logs", json=payload, timeout=10)
    response.raise_for_status()


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


def run_sample_mode(api_base_url: str, count: int, interval: float) -> None:
    print(f"Generating {count} sample traffic logs...")
    for index in range(count):
        payload = generate_sample_log()
        post_log(api_base_url, payload)
        print(f"[{index + 1}/{count}] logged {payload['src_ip']} -> {payload['dst_ip']}")
        time.sleep(interval)


def run_live_mode(api_base_url: str, interface: str, packet_limit: int) -> None:
    try:
        from scapy.all import IP, TCP, UDP, sniff
    except ImportError as exc:
        raise SystemExit("Scapy is required for live capture mode") from exc

    processed = {"count": 0}

    def handle_packet(packet: object) -> None:
        if processed["count"] >= packet_limit:
            return
        if not packet.haslayer(IP):
            return

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

        payload = {
            "src_ip": ip_layer.src,
            "dst_ip": ip_layer.dst,
            "dst_port": dst_port,
            "protocol": protocol,
            "encrypted": encrypted,
            "packet_count": 1,
            "byte_count": len(packet),
        }
        post_log(api_base_url, payload)
        processed["count"] += 1
        print(f"[{processed['count']}/{packet_limit}] captured {payload['src_ip']} -> {payload['dst_ip']}")

    print(f"Starting live capture on {interface} (requires elevated permissions)...")
    sniff(iface=interface, prn=handle_packet, store=False, count=packet_limit)


def scan_local_hosts(subnet_prefix: str = "192.168.1.") -> list[str]:
    active_hosts: list[str] = []
    for host in range(1, 255):
        ip = f"{subnet_prefix}{host}"
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


def main() -> None:
    parser = argparse.ArgumentParser(description="Network traffic capture agent")
    parser.add_argument("--api-base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--mode", choices=["sample", "live", "scan"], default="sample")
    parser.add_argument("--count", type=int, default=20)
    parser.add_argument("--interval", type=float, default=0.5)
    parser.add_argument("--interface", default="eth0")
    parser.add_argument("--subnet-prefix", default="192.168.1.")
    args = parser.parse_args()

    if args.mode == "sample":
        run_sample_mode(args.api_base_url, args.count, args.interval)
    elif args.mode == "live":
        run_live_mode(args.api_base_url, args.interface, args.count)
    else:
        hosts = scan_local_hosts(args.subnet_prefix)
        print(f"Discovered {len(hosts)} active hosts at {datetime.now().isoformat()}")
        for host in hosts:
            print(f" - {host}")


if __name__ == "__main__":
    main()
