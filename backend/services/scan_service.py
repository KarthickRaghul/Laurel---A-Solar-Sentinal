# backend/services/scan_service.py
from services.scanner.port_scanner import discover_hosts, is_iot_device, scan_ports, os_fingerprint
from services.scanner.version_detector import detect_version

# In-memory cache (optional, later you can push to MongoDB)
discovered_devices = {
    "alive_hosts": [],
    "iot_hosts": []
}

def run_discovery(subnet: str) -> dict:
    """Discover alive + IoT devices."""
    hosts = discover_hosts(subnet)
    iot_hosts = [h for h in hosts if is_iot_device(h)]

    discovered_devices["alive_hosts"] = hosts
    discovered_devices["iot_hosts"] = iot_hosts

    return discovered_devices


def run_port_scan() -> list:
    """Scan ports for discovered IoT hosts."""
    results = []
    for ip in discovered_devices.get("iot_hosts", []):
        ports = scan_ports(ip)
        results.append({"ip": ip, "open_ports": ports})
    return results


def run_os_fingerprint() -> list:
    """OS fingerprinting for discovered IoT hosts."""
    results = []
    for ip in discovered_devices.get("iot_hosts", []):
        os_info = os_fingerprint(ip)
        results.append({"ip": ip, "os_fingerprint": os_info})
    return results


def run_version_detection() -> list:
    """Detect firmware/software version for discovered IoT hosts."""
    results = []
    for ip in discovered_devices.get("iot_hosts", []):
        version_info = detect_version(ip)
        results.append({"ip": ip, "version_info": version_info})
    return results
