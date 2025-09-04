# services/cve_service.py
import requests
from scanner.vuln_scanner import vuln_scan

def fetch_cves(keyword: str, max_results: int = 5):
    """
    Fetch CVEs from NVD using keyword search.
    Returns a list of CVE dicts.
    """
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
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


def run_vuln_scan(ip: str):
    """
    Run vulnerability scan on a host and fetch CVEs for detected services.
    Returns dict: {"scan_result": ..., "cve_results": ...}
    """
    scan_result = vuln_scan(ip)

    # Extract unique service keywords for CVE lookup
    services = []
    for vuln in scan_result.get("vulnerabilities", []):
        keyword = vuln.get("script", "")
        if keyword and keyword not in services:
            services.append(keyword)

    # Fetch CVEs for each detected service
    cve_results = {service: fetch_cves(service) for service in services}

    return {
        "scan_result": scan_result,
        "cve_results": cve_results
    }
