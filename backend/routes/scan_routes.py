# scan_routes.py
from flask import Blueprint, request, jsonify
from services.scan_service import discover_hosts, is_iot_device, scan_ports, os_fingerprint
from services.scanner.version_detector import detect_version
from Schemas.scan_model import ScanResult

scan_bp = Blueprint("scan", __name__, url_prefix="/api/scan")

# -------------------------------
# Discover hosts
# -------------------------------
@scan_bp.route("/discover", methods=["POST"])
def discover():
    """Discover hosts in a subnet and check IoT devices"""
    data = request.get_json(silent=True) or {}
    subnet = data.get("ip", "192.168.1.0/24")

    hosts = discover_hosts(subnet)
    iot_hosts = [h for h in hosts if is_iot_device(h)]

    # Save in DB
    ScanResult.save_result("discover", {"subnet": subnet, "hosts": hosts, "iot_hosts": iot_hosts})

    return jsonify({
        "scanned_subnet": subnet,
        "alive_hosts": hosts,
        "iot_hosts": iot_hosts
    })


# -------------------------------
# Port Scan
# -------------------------------
@scan_bp.route("/ports", methods=["POST"])
def ports():
    """Scan open ports for given IP"""
    data = request.get_json(silent=True) or {}
    ip = data.get("ip")
    if not ip:
        return jsonify({"error": "IP is required"}), 400

    ports = scan_ports(ip)
    ScanResult.save_result("ports", {"ip": ip, "ports": ports})

    return jsonify({
        "ip": ip,
        "open_ports": ports
    })


# -------------------------------
# OS Fingerprinting
# -------------------------------
@scan_bp.route("/os", methods=["POST"])
def os_scan():
    """Run OS detection"""
    data = request.get_json(silent=True) or {}
    ip = data.get("ip")
    if not ip:
        return jsonify({"error": "IP is required"}), 400

    os_info = os_fingerprint(ip)
    ScanResult.save_result("os", {"ip": ip, "os_info": os_info})

    return jsonify({
        "ip": ip,
        "os_fingerprint": os_info
    })


# -------------------------------
# Version Detection
# -------------------------------
@scan_bp.route("/version", methods=["POST"])
def version_scan():
    """Detect firmware/version of IoT device"""
    data = request.get_json(silent=True) or {}
    ip = data.get("ip")
    port = data.get("port", 80)

    if not ip:
        return jsonify({"error": "IP is required"}), 400

    version_info = detect_version(ip, port)
    ScanResult.save_result("version", {"ip": ip, "port": port, "version_info": version_info})

    return jsonify({
        "ip": ip,
        "port": port,
        "version_info": version_info
    })
