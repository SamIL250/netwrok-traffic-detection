import socket
from dataclasses import dataclass


@dataclass
class HostScanResult:
    ip_address: str
    open_ports: list[int]


DEFAULT_SCAN_PORTS = (80, 443, 22)


def scan_subnet(subnet_prefix: str, ports: tuple[int, ...] = DEFAULT_SCAN_PORTS) -> list[HostScanResult]:
    if not subnet_prefix.endswith("."):
        subnet_prefix = f"{subnet_prefix}."

    discovered: list[HostScanResult] = []
    for host in range(1, 255):
        ip = f"{subnet_prefix}{host}"
        open_ports: list[int] = []
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.05)
            try:
                if sock.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
            except OSError:
                pass
            finally:
                sock.close()
        if open_ports:
            discovered.append(HostScanResult(ip_address=ip, open_ports=open_ports))
    return discovered
