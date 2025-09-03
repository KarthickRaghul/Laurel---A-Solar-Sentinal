from flask import Flask, jsonify
import nmap

app = Flask(__name__)
scanner = nmap.PortScanner()

# Using previously discovered IoT hosts
discovered_devices = {
    "alive_hosts": [],
    "iot_hosts": []
}

@app.route('/api/scan/vuln', methods=['GET'])
def api_vuln_scan():
    """Run vulnerability scan on discovered IoT devices."""
    results = []

    for ip in discovered_devices.get("iot_hosts", []):
        try:
            # Run nmap vuln scripts for the host
            scanner.scan(ip, arguments='--script vuln')
            
            host_result = {
                "ip": ip,
                "vulnerabilities": []
            }

            for proto in scanner[ip].all_protocols():
                for port, info in scanner[ip][proto].items():
                    scripts = info.get('script', {})
                    if scripts:
                        for script_name, output in scripts.items():
                            host_result["vulnerabilities"].append({
                                "port": port,
                                "protocol": proto,
                                "script": script_name,
                                "output": output
                            })
            results.append(host_result)

        except Exception as e:
            results.append({
                "ip": ip,
                "error": str(e)
            })

    return jsonify({"vuln_scan_results": results})

if __name__ == "__main__":
    app.run(debug=True)
