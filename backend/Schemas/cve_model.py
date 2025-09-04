# backend/models/cve_model.py
from utils.db import db
from bson.objectid import ObjectId
from datetime import datetime

# MongoDB collection for CVE results
cves = db["cves"]

# Helper functions

def insert_cve(ip: str, service: str, cve_list: list):
    """
    Insert CVE scan results into the database.
    Each CVE entry will be associated with the IP and service.
    """
    document = {
        "ip": ip,
        "service": service,
        "cves": cve_list,
        "timestamp": datetime.utcnow()
    }
    result = cves.insert_one(document)
    return str(result.inserted_id)


def get_cves_by_ip(ip: str):
    """
    Fetch all CVE scan results for a specific IP.
    """
    results = list(cves.find({"ip": ip}).sort("timestamp", -1))
    for r in results:
        r["_id"] = str(r["_id"])  # Convert ObjectId to string for JSON serialization
    return results


def get_cves_by_service(service: str):
    """
    Fetch all CVE scan results for a specific service.
    """
    results = list(cves.find({"service": service}).sort("timestamp", -1))
    for r in results:
        r["_id"] = str(r["_id"])
    return results
