from flask import Flask
from routes.auth_routes import auth_bp
from backend.routes.device_routes import device_bp
from backend.routes.scan_routes import scan_bp

app = Flask(__name__)
app.register_blueprint(auth_bp)
app.register_blueprint(device_bp)
app.register_blueprint(scan_bp)

if __name__ == "__main__":
    app.run(debug=True)
