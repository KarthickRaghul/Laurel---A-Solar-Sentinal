# backend/services/device_service.py
from Schemas.device_model import devices
from bson import ObjectId

def add_device(user_id, name, ip, device_type):
    """
    Add/register a new IoT device to the user's account.
    """
    new_device = {
        "user_id": user_id,
        "name": name,
        "ip": ip,
        "type": device_type
    }
    result = devices.insert_one(new_device)
    return str(result.inserted_id)  # return new device ID


def get_devices(user_id):
    """
    Fetch all devices belonging to a user.
    """
    device_list = list(devices.find({"user_id": user_id}, {"user_id": 0}))
    for device in device_list:
        device["_id"] = str(device["_id"])  # convert ObjectId to string
    return device_list


def delete_device(user_id, device_id):
    """
    Delete a device if it belongs to the user.
    """
    result = devices.delete_one({"_id": ObjectId(device_id), "user_id": user_id})
    return result.deleted_count > 0


def update_device(user_id, device_id, update_data):
    """
    Update device details if it belongs to the user.
    """
    result = devices.update_one(
        {"_id": ObjectId(device_id), "user_id": user_id},
        {"$set": update_data}
    )
    return result.modified_count > 0
