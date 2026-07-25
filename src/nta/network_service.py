from datetime import datetime, timezone

from sqlalchemy.orm import Session

from nta.models import DiscoveredDevice, KnownDevice, NetworkScan
from nta.scanner import scan_subnet


def list_known_devices(db: Session) -> list[KnownDevice]:
    return db.query(KnownDevice).order_by(KnownDevice.ip_address.asc()).all()


def add_known_device(db: Session, ip_address: str, label: str) -> KnownDevice:
    existing = db.query(KnownDevice).filter(KnownDevice.ip_address == ip_address).first()
    if existing is not None:
        existing.label = label
        db.commit()
        db.refresh(existing)
        return existing

    device = KnownDevice(ip_address=ip_address, label=label)
    db.add(device)
    db.commit()
    db.refresh(device)
    return device


def remove_known_device(db: Session, device_id: int) -> bool:
    device = db.query(KnownDevice).filter(KnownDevice.id == device_id).first()
    if device is None:
        return False
    db.delete(device)
    db.commit()
    return True


def get_latest_scan(db: Session) -> NetworkScan | None:
    return db.query(NetworkScan).order_by(NetworkScan.started_at.desc()).first()


def list_scan_history(db: Session, limit: int = 20) -> list[NetworkScan]:
    return db.query(NetworkScan).order_by(NetworkScan.started_at.desc()).limit(limit).all()


def list_discovered_devices(
    db: Session,
    *,
    scan_id: int | None = None,
    unauthorized_only: bool = False,
) -> list[DiscoveredDevice]:
    if scan_id is None:
        latest = get_latest_scan(db)
        if latest is None:
            return []
        scan_id = latest.id

    query = db.query(DiscoveredDevice).filter(DiscoveredDevice.scan_id == scan_id).order_by(
        DiscoveredDevice.ip_address.asc()
    )
    if unauthorized_only:
        query = query.filter(DiscoveredDevice.is_authorized.is_(False))
    return query.all()


def run_network_scan(subnet_prefix: str, user_id: int | None = None) -> NetworkScan:
    from nta.database import SessionLocal

    db = SessionLocal()
    try:
        scan = NetworkScan(
            subnet_prefix=subnet_prefix,
            status="running",
            started_by_id=user_id,
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        known_ips = {device.ip_address for device in list_known_devices(db)}
        results = scan_subnet(subnet_prefix)

        unauthorized_count = 0
        for result in results:
            is_authorized = result.ip_address in known_ips
            if not is_authorized:
                unauthorized_count += 1
            db.add(
                DiscoveredDevice(
                    scan_id=scan.id,
                    ip_address=result.ip_address,
                    open_ports=",".join(str(port) for port in result.open_ports),
                    is_authorized=is_authorized,
                )
            )

        scan.device_count = len(results)
        scan.unauthorized_count = unauthorized_count
        scan.status = "completed"
        scan.completed_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(scan)
        return scan
    finally:
        db.close()


def authorize_discovered_device(db: Session, ip_address: str, label: str) -> KnownDevice:
    known_device = add_known_device(db, ip_address, label)

    latest = get_latest_scan(db)
    if latest is not None:
        devices = db.query(DiscoveredDevice).filter(
            DiscoveredDevice.scan_id == latest.id,
            DiscoveredDevice.ip_address == ip_address,
        ).all()
        for device in devices:
            device.is_authorized = True
        db.commit()

    return known_device
