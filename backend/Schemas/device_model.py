# backend/models/device_model.py
from backend.utils.db import db

# Create or access the "devices" collection in MongoDB
devices = db["devices"]
