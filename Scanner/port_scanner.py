# scanner/port_scanner.py
import nmap
import json
import os
from scanner.utils import save_json

def run_scan(target, ports="1-1024", output_dir="data/scans"):
    """
    Runs nmap scan on the target.
    Args:
        target (str): IP or hostname (e.g., "192.168.0.1")
        ports (str): Port range (default: 1-1024)
        output_dir (str): Directory to save results
    Returns:
        dict: Scan results
    """
    nm = nmap.PortScanner()
    print(f"[INFO] Running scan on {target}:{ports} ...")
    
    try:
        nm.scan(target, ports)
    except Exception as e:
        print(f"[ERROR] Nmap scan failed: {e}")
        return {}

    results = {}
    for host in nm.all_hosts():
        results[host] = {}
        for proto in nm[host].all_protocols():
            results[host][proto] = {}
            for port, port_data in nm[host][proto].items():
                results[host][proto][port] = {
                    "state": port_data["state"],
                    "name": port_data.get("name", ""),
                    "product": port_data.get("product", ""),
                    "version": port_data.get("version", "")
                }

    # Save results
    os.makedirs(output_dir, exist_ok=True)
    file_path = os.path.join(output_dir, f"{target.replace('.', '_')}_scan.json")
    save_json(results, file_path)
    print(f"[INFO] Scan results saved at {file_path}")
    
    return results


if __name__ == "__main__":
    # Example usage
    scan_data = run_scan("127.0.0.1", "20-100")
    print(json.dumps(scan_data, indent=2))
