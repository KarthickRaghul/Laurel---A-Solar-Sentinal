# scanner/vulnerability_map.py
import json
import os
from scanner.utils import load_json

# Simple static mapping (for demo purpose)
PORT_VULN_MAP = {
    21: ["CVE-1999-0502 (FTP Anonymous Login)"],
    22: ["CVE-2018-15473 (OpenSSH User Enumeration)"],
    23: ["CVE-2001-0554 (Telnet Remote DoS)"],
    80: ["CVE-2021-41773 (Apache Path Traversal)"],
    443: ["CVE-2021-3450 (OpenSSL Certificate Check Bypass)"]
}

def map_vulnerabilities(scan_file):
    """
    Reads scan results JSON and maps open ports → CVEs
    Args:
        scan_file (str): Path to scan JSON file
    Returns:
        dict: Vulnerability mapping
    """
    scan_data = load_json(scan_file)
    vulnerabilities = {}

    for host, protocols in scan_data.items():
        vulnerabilities[host] = {}
        for proto, ports in protocols.items():
            for port, port_data in ports.items():
                if port_data["state"] == "open" and port in PORT_VULN_MAP:
                    vulnerabilities[host][port] = {
                        "service": port_data["name"],
                        "product": port_data.get("product", ""),
                        "version": port_data.get("version", ""),
                        "possible_vulns": PORT_VULN_MAP[port]
                    }

    return vulnerabilities


if __name__ == "__main__":
    # Example usage
    file_path = "data/scans/127_0_0_1_scan.json"
    if os.path.exists(file_path):
        vulns = map_vulnerabilities(file_path)
        print(json.dumps(vulns, indent=2))
    else:
        print("[ERROR] Run a scan first!")
