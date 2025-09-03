from flask import Flask, request, jsonify
import nmap

app = Flask(__name__)
scanner = nmap.PortScanner()

# -------------------------------
# Helper functions
# -------------------------------

def discover_hosts(subnet):
    """Discover alive hosts using ping sweep (-sn)."""
    scanner.scan(hosts=subnet, arguments='-sn')
    return [host for host in scanner.all_hosts() if scanner[host].state() == "up"]

def is_iot_device(ip):
    """
    Heuristic to check if a device looks like IoT/DER hardware.
    - MAC vendor check if available
    - Typical DER/IoT ports (23, 80, 443, 502, 1883)
    """
    try:
        # MAC vendor check
        mac = scanner[ip]['addresses'].get('mac', '')
        vendor = scanner[ip]['vendor'].get(mac, '') if mac else ''
        iot_vendors = ["Huawei", "Sungrow", "Growatt", "SolarEdge", "Siemens"]
        if any(v in vendor for v in iot_vendors):
            return True

        # Check known IoT/DER ports quickly
        common_ports = [23, 80, 443, 502, 1883]
        scanner.scan(ip, arguments='-p ' + ",".join(map(str, common_ports)))
        for proto in scanner[ip].all_protocols():
            for port, info in scanner[ip][proto].items():
                if info['state'] == 'open':
                    return True
    except Exception:
        return False

    return False

def scan_ports(ip, port_range="1-1000"):
    """Scan open ports + detect services (-sV)."""
    scanner.scan(ip, port_range, arguments='-sV')
    open_ports = []
    for proto in scanner[ip].all_protocols():
        for port, info in scanner[ip][proto].items():
            if info['state'] == 'open':
                open_ports.append({
                    "port": port,
                    "protocol": proto,
                    "service": info.get('name', ''),
                    "product": info.get('product', ''),
                    "version": info.get('version', '')
                })
    return open_ports

def os_fingerprint(ip):
    """Run OS detection (-O)."""
    try:
        scanner.scan(ip, arguments='-O')
        return scanner[ip].get('osmatch', [])
    except Exception:
        return []

# -------------------------------
# Global in-memory store for discovered devices
# -------------------------------
# Structure: { "alive_hosts": [...], "iot_hosts": [...] }
discovered_devices = {
    "alive_hosts": [],
    "iot_hosts": []
}

# -------------------------------
# Flask endpoints
# -------------------------------

@app.route('/api/scan/discover', methods=['POST'])
def api_discover():
    """Discover hosts and store in memory for IoT/DER devices."""
    data = request.get_json(silent=True) or {}
    ip_or_subnet = data.get("ip")

    if ip_or_subnet:
        subnet = ip_or_subnet
    else:
        client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        subnet = ".".join(client_ip.split(".")[:3]) + ".0/24"

    hosts = discover_hosts(subnet)
    iot_hosts = [h for h in hosts if is_iot_device(h)]

    # Store in global structure
    discovered_devices["alive_hosts"] = hosts
    discovered_devices["iot_hosts"] = iot_hosts

    return jsonify({
        "scanned_subnet": subnet,
        "alive_hosts": hosts,
        "iot_hosts": iot_hosts
    })


@app.route('/api/scan/ports', methods=['GET'])
def api_ports():
    """Scan ports + services only for IoT/DER devices discovered."""
    results = []
    for ip in discovered_devices.get("iot_hosts", []):
        ports = scan_ports(ip)
        results.append({
            "ip": ip,
            "open_ports": ports
        })
    return jsonify({
        "devices_ports": results
    })


@app.route('/api/scan/os', methods=['GET'])
def api_os():
    """Run OS fingerprinting only for IoT/DER devices discovered."""
    results = []
    for ip in discovered_devices.get("iot_hosts", []):
        os_info = os_fingerprint(ip)
        results.append({
            "ip": ip,
            "os_fingerprint": os_info
        })
    return jsonify({
        "devices_os": results
    })


# -------------------------------
# Run server
# -------------------------------
if __name__ == "__main__":
    app.run(debug=True)
