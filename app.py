from flask import (
    Flask,
    render_template,
    request,
    redirect,
    send_file,
    url_for,
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

# Create a file handler and set the log file size and backup count
handler = RotatingFileHandler("app.log", maxBytes=1024 * 1024, backupCount=10)

# Create a logging format
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)

# Add the handler to the logger
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


@app.route("/")
def index():
    if "username" in session:
        username = session["username"]
        # Get list of file names in the user's folder
        user_folder = os.path.join(app.config["UPLOAD_FOLDER"], username)
        if os.path.exists(user_folder):
            files = os.listdir(user_folder)
        else:
            files = []
        return render_template("index.html", username=username, files=files)
    else:
        return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if verify_user(username, password):
            user_data = users.find_one({"username": username})
            if user_data:
                session["username"] = username
                logger.info("User %s logged in successfully.", user_data["_id"])
            return redirect(url_for("index"))
        else:
            logger.warning("Failed login attempt for username: %s", username)
            return render_template("login.html", error="Invalid credentials")
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        phone = request.form["phone"]
        email = request.form["email"]
        role = request.form["role"]
        timestamp = datetime.now().strftime("%H:%M %d/%m/%Y")

        success, error_message = register_user(
            username, password, phone, role, email, timestamp
        )
        if success:
            logger.info("User %s registered successfully", username)
            return redirect(url_for("login"))
        else:
            logger.error(
                "Failed user registration for username: %s - %s",
                username,
                error_message,
            )
            return render_template(
                "register.html",
                error=error_message,
                username=username,
                phone=phone,
                email=email,
                role=role,
            )
    return render_template("register.html")


@app.route("/logout")
def logout():
    if "username" in session:
        username = session.pop("username", None)
        user_data = users.find_one({"username": username})
        if user_data:
            logger.info("User %s logged out.\n", user_data["_id"])
    return redirect(url_for("index"))


@app.route("/upload", methods=["GET", "POST"])
def upload_file():
    if "username" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        # check if the post request has the file part
        if "file" not in request.files:
            return redirect(request.url)

        files = request.files.getlist("file")  # Get list of files

        # If no files selected, redirect back to the upload page
        if not files or all(file.filename == "" for file in files):
            return redirect(request.url)

        # Create a folder with the user's username
        username = session["username"]
        user_folder = os.path.join(app.config["UPLOAD_FOLDER"], username)
        if not os.path.exists(user_folder):
            os.makedirs(user_folder)

        # Loop through each file and save them
        for file in files:
            if file.filename == "":
                continue  # Skip empty files

            filename = secure_filename(file.filename)
            file_path = os.path.join(user_folder, filename)
            file.save(file_path)

            # Log information about the uploaded file
            logger.info("File '%s' uploaded by user '%s'", filename, username)

        return redirect(url_for("index"))

    return render_template("upload.html")


@app.route("/delete_file/<filename>", methods=["POST"])
def delete_file(filename):
    if "username" in session:
        username = session["username"]
        user_folder = os.path.join(app.config["UPLOAD_FOLDER"], username)
        file_path = os.path.join(user_folder, filename)
        if os.path.exists(file_path):
            os.remove(file_path)
            logger.info("File '%s' deleted by user '%s'", filename, username)
    return redirect(url_for("index"))


@app.route("/download_file/<filename>")
def download_file(filename):
    if "username" in session:
        username = session["username"]
        user_folder = os.path.join(app.config["UPLOAD_FOLDER"], username)
        file_path = os.path.join(user_folder, filename)
        if os.path.exists(file_path):
            return send_from_directory(user_folder, filename, as_attachment=True)
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=True)
