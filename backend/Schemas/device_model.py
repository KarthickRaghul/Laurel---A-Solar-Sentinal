# backend/models/device_model.py
from utils.db import db

# Create or access the "devices" collection in MongoDB
devices = db["devices"]
