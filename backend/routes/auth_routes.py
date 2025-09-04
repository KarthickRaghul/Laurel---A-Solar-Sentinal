from flask import Blueprint, request, jsonify
from services.auth_service import register_user, login_user
from utils.jwt_utils import verify_token

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")

@auth_bp.route("/signup", methods=["POST"])
def signup():
    data = request.get_json()
    return jsonify(register_user(
        data.get("username"),
        data.get("email"),
        data.get("password")
    ))

@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    return jsonify(login_user(
        data.get("email"),
        data.get("password")
    ))

@auth_bp.route("/me", methods=["GET"])
def me():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing or invalid token"}), 401

    token = auth_header.split(" ")[1]
    payload = verify_token(token)
    if not payload:
        return jsonify({"error": "Token expired or invalid"}), 401

    return jsonify({"user": payload}), 200
