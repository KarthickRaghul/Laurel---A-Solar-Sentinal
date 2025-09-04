# backend/routes/device_routes.py
from flask import Blueprint, request, jsonify
from services.device_service import add_device, get_devices, delete_device, update_device
from utils.jwt_utils import verify_token

device_bp = Blueprint("devices", __name__, url_prefix="/api/devices")

# Middleware-like helper
def get_user_from_token(request):
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    token = auth_header.split(" ")[1]
    return verify_token(token)


# ---- Add Device ----
@device_bp.route("/", methods=["POST"])
def create_device():
    payload = get_user_from_token(request)
    if not payload:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    name = data.get("name")
    ip = data.get("ip")
    device_type = data.get("type")

    if not name or not ip or not device_type:
        return jsonify({"error": "Missing required fields"}), 400

    device_id = add_device(payload["user_id"], name, ip, device_type)
    return jsonify({"message": "Device added", "device_id": device_id}), 201


# ---- Get Devices ----
@device_bp.route("/", methods=["GET"])
def list_devices():
    payload = get_user_from_token(request)
    if not payload:
        return jsonify({"error": "Unauthorized"}), 401

    devices = get_devices(payload["user_id"])
    return jsonify({"devices": devices}), 200


# ---- Delete Device ----
@device_bp.route("/<device_id>", methods=["DELETE"])
def remove_device(device_id):
    payload = get_user_from_token(request)
    if not payload:
        return jsonify({"error": "Unauthorized"}), 401

    if delete_device(payload["user_id"], device_id):
        return jsonify({"message": "Device deleted"}), 200
    return jsonify({"error": "Device not found or unauthorized"}), 404


# ---- Update Device ----
@device_bp.route("/<device_id>", methods=["PUT"])
def edit_device(device_id):
    payload = get_user_from_token(request)
    if not payload:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    if update_device(payload["user_id"], device_id, data):
        return jsonify({"message": "Device updated"}), 200
    return jsonify({"error": "Device not found or unauthorized"}), 404
