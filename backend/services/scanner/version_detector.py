import requests
import subprocess
import re

def detect_version(ip, port=80):
    """
    Attempt to detect vendor, product, and version of a device.
    Returns a dict like:
    {
        "vendor": "Boa",
        "product": "Webserver",
        "version": "0.94.14rc21"
    }
    If nothing found, returns None.
    """

    result = {
        "vendor": None,
        "product": None,
        "version": None
    }

    # --- 1. Try HTTP endpoints (common IoT status pages) ---
    try:
        for endpoint in ["/status", "/about", "/info"]:
            url = f"http://{ip}:{port}{endpoint}"
            resp = requests.get(url, timeout=3)
            if resp.status_code == 200:
                text = resp.text
                # Look for firmware/version strings
                match = re.search(r"(firmware|version)[:\s]+([\w\.\-]+)", text, re.I)
                if match:
                    result["product"] = "UnknownDevice"
                    result["version"] = match.group(2)
                    return result
    except requests.exceptions.RequestException:
        pass

    # --- 2. Try HTTP headers (like Server: Boa/0.94.14rc21) ---
    try:
        resp = requests.get(f"http://{ip}:{port}", timeout=3)
        server_header = resp.headers.get("Server")
        if server_header:
            # Example: "Boa/0.94.14rc21"
            match = re.match(r"([\w\-]+)[/ ]([\w\.\-]+)", server_header)
            if match:
                result["vendor"] = match.group(1)
                result["product"] = "Webserver"
                result["version"] = match.group(2)
                return result
    except requests.exceptions.RequestException:
        pass

    # --- 3. Fallback: Nmap banner detection ---
    try:
        cmd = ["nmap", "-sV", "-p", str(port), ip]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        output = proc.stdout

        # Example: "80/tcp open  http  Boa httpd 0.94.14rc21"
        match = re.search(r"\d+/tcp\s+open\s+\w+\s+([\w\-]+)[^\d]*(\d[\w\.\-]+)", output)
        if match:
            result["vendor"] = match.group(1)
            result["product"] = "Service"
            result["version"] = match.group(2)
            return result
    except Exception:
        pass

    return None


# Quick test (remove when integrating with scan_service)
if __name__ == "__main__":
    ip = "192.168.1.100"
    print(detect_version(ip))
