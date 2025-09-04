# routes/cve_routes.py
from flask import Blueprint, request, jsonify
from services.cve_service import run_vuln_scan
from Schemas.cve_model import CVERecord

cve_bp = Blueprint("cve", __name__, url_prefix="/api/cves")

@cve_bp.route("/scan", methods=["POST"])
def scan_cve():
    """
    POST /api/cves/scan
    Request JSON: {"ip": "<target_ip>"}
    """
    data = request.get_json()
    ip = data.get("ip") if data else None
    if not ip:
        return jsonify({"error": "Please provide IP in JSON: {'ip': '<target>'}"}), 400

    result = run_vuln_scan(ip)

    # Optionally, save scan & CVE results to DB
    CVERecord.save_scan(ip, result)

    return jsonify(result), 200
