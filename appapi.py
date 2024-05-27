from flask import (
    Flask,
    request,
    jsonify,
    session,
    send_from_directory,
)
from bson.objectid import ObjectId
import pytz
import re
from flask_pymongo import PyMongo
from passlib.hash import pbkdf2_sha256
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", b'_5#y2L"F4Q8z\n\xec]/')
IST = pytz.timezone("Asia/Kolkata")  # Indian Standard Time
UPLOAD_FOLDER = "uploads"
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MONGO_URI"] = "mongodb://127.0.0.1:27017/docvault-drivetest"
mongo = PyMongo(app)

# Ensure indexes on frequently queried fields like username and email
users = mongo.db.users
users.create_index("username", unique=True)
users.create_index("email", unique=True)

# Set up logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = RotatingFileHandler("app.log", maxBytes=1024 * 1024, backupCount=10)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)


def register_user(username, password, phone, role, email, timestamp):
    password_regex = r"^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
    email_regex = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"

    if not re.match(password_regex, password):
        return (
            False,
            "Password must be at least 8 characters long and contain at least one letter, one special character, and one digit.",
        )

    if not re.match(email_regex, email):
        return False, "Invalid email address."

    hashed_password = pbkdf2_sha256.hash(password)

    try:
        users.insert_one(
            {
                "username": username,
                "password": hashed_password,
                "phone": phone,
                "email": email,
                "role": role,
                "created_at": timestamp,
                "update_at": timestamp,
            }
        )
        return True, None
    except Exception as e:
        logger.error("Error occurred during user registration: %s", str(e))
        return False, "An error occurred during user registration."


def verify_user(username, password):
    username_regex = r"^[a-zA-Z0-9_.-]+$"
    if not re.match(username_regex, username):
        return False

    user_data = users.find_one({"username": username})
    if user_data and pbkdf2_sha256.verify(password, user_data["password"]):
        update_time = datetime.now(IST).strftime("%H:%M %d/%m/%Y")
        users.update_one({"username": username}, {"$set": {"update_at": update_time}})
        return True
    else:
        return False


@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json()
    username = data["username"]
    password = data["password"]
    phone = data["phone"]
    email = data["email"]
    role = data["role"]
    timestamp = datetime.now().strftime("%H:%M %d/%m/%Y")

    success, error_message = register_user(
        username, password, phone, role, email, timestamp
    )
    if success:
        logger.info("User %s registered successfully", username)
        return jsonify({"message": "User registered successfully"}), 201
    else:
        logger.error(
            "Failed user registration for username: %s - %s", username, error_message
        )
        return jsonify({"error": error_message}), 400


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json()
    username = data["username"]
    password = data["password"]
    if verify_user(username, password):
        user_data = users.find_one({"username": username})
        if user_data:
            session["username"] = username
            logger.info("User %s logged in successfully.", user_data["_id"])
            return jsonify({"message": "Login successful"}), 200
    else:
        logger.warning("Failed login attempt for username: %s", username)
        return jsonify({"error": "Invalid credentials"}), 401


@app.route("/api/logout", methods=["POST"])
def api_logout():
    if "username" in session:
        username = session.pop("username", None)
        user_data = users.find_one({"username": username})
        if user_data:
            logger.info("User %s logged out.\n", user_data["_id"])
        return jsonify({"message": "Logout successful"}), 200
    return jsonify({"error": "No user logged in"}), 400


@app.route("/api/upload", methods=["POST"])
def api_upload_file():
    if "username" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    files = request.files.getlist("file")
    if not files or all(file.filename == "" for file in files):
        return jsonify({"error": "No files provided"}), 400

    username = session["username"]
    user_folder = os.path.join(app.config["UPLOAD_FOLDER"], username)
    if not os.path.exists(user_folder):
        os.makedirs(user_folder)

    uploaded_files = []
    for file in files:
        if file.filename == "":
            continue
        filename = secure_filename(file.filename)
        file_path = os.path.join(user_folder, filename)
        file.save(file_path)
        uploaded_files.append(filename)
        logger.info("File '%s' uploaded by user '%s'", filename, username)

    return (
        jsonify({"message": "Files uploaded successfully", "files": uploaded_files}),
        200,
    )


@app.route("/api/files", methods=["GET"])
def api_list_files():
    if "username" in session:
        username = session["username"]
        user_folder = os.path.join(app.config["UPLOAD_FOLDER"], username)
        if os.path.exists(user_folder):
            files = os.listdir(user_folder)
        else:
            files = []
        return jsonify({"files": files}), 200
    return jsonify({"error": "Unauthorized"}), 401


@app.route("/api/download/<filename>", methods=["GET"])
def api_download_file(filename):
    if "username" in session:
        username = session["username"]
        user_folder = os.path.join(app.config["UPLOAD_FOLDER"], username)
        file_path = os.path.join(user_folder, filename)
        if os.path.exists(file_path):
            return send_from_directory(user_folder, filename, as_attachment=True)
    return jsonify({"error": "File not found"}), 404


@app.route("/api/delete/<filename>", methods=["DELETE"])
def api_delete_file(filename):
    if "username" in session:
        username = session["username"]
        user_folder = os.path.join(app.config["UPLOAD_FOLDER"], username)
        file_path = os.path.join(user_folder, filename)
        if os.path.exists(file_path):
            os.remove(file_path)
            logger.info("File '%s' deleted by user '%s'", filename, username)
            return jsonify({"message": "File deleted successfully"}), 200
    return jsonify({"error": "File not found"}), 404


if __name__ == "__main__":
    app.run(debug=True)
