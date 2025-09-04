from flask import Flask, jsonify, request
import requests
from scanner.vuln_scanner import vuln_scan

app = Flask(__name__)

def fetch_cves(keyword, max_results=5):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": keyword, "resultsPerPage": max_results}
    try:
        resp = requests.get(url, params=params, timeout=10)
        resp.raise_for_status()
        data = resp.json()

        cve_list = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_list.append({
                "id": cve.get("id"),
                "description": cve.get("descriptions", [{}])[0].get("value", ""),
                "severity": cve.get("metrics", {}),
                "references": [ref.get("url") for ref in cve.get("references", [])]
            })
        return cve_list
    except Exception as e:
        return [{"error": f"Failed to fetch CVEs: {str(e)}"}]

@app.route('/api/scan/cve', methods=['POST'])
def api_cve_scan():
    """
    POST /api/scan/cve
    Request JSON: { "ip": "192.168.1.10" }
    """
    data = request.get_json()
    ip = data.get("ip") if data else None
    if not ip:
        return jsonify({"error": "Please provide JSON with {'ip': '<target>'}"}), 400

    # Run vuln scan
    scan_result = vuln_scan(ip)

    # Collect service keywords for CVE lookup
    services = []
    for vuln in scan_result.get("vulnerabilities", []):
        keyword = vuln.get("script", "")
        if keyword and keyword not in services:
            services.append(keyword)

    # Fetch CVEs for each detected service keyword
    cve_results = {service: fetch_cves(service) for service in services}

    return jsonify({
        "scan_result": scan_result,
        "cve_results": cve_results
    })

if __name__ == "__main__":
    app.run(debug=True)
