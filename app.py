from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import sqlite3

app = Flask(_name_)
CORS(app)  # Allow frontend requests
bcrypt = Bcrypt(app)
app.config['JWT_SECRET_KEY'] = 'your_secret_key'  # Change this to a secure key
jwt = JWTManager(app)

# Initialize SQLite database
def init_db():
    with sqlite3.connect("users.db") as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        """)
        conn.commit()

init_db()  # Create the database table

@app.route("/register", methods=["POST"])
def register():
    data = request.json
    name = data["name"]
    email = data["email"]
    username = data["username"]
    password = data["password"]

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    try:
        with sqlite3.connect("users.db") as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (name, email, username, password) VALUES (?, ?, ?, ?)",
                           (name, email, username, hashed_password))
            conn.commit()
        return jsonify({"message": "User registered successfully"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"message": "Username or email already exists"}), 400

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data["username"]
    password = data["password"]

    with sqlite3.connect("users.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, password FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

    if user and bcrypt.check_password_hash(user[1], password):
        access_token = create_access_token(identity=user[0])
        return jsonify({"message": "Login successful", "token": access_token}), 200
    else:
        return jsonify({"message": "Invalid username or password"}), 401

@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    user_id = get_jwt_identity()
    return jsonify({"message": "Protected route accessed", "user_id": user_id}), 200

if _name_ == "_main_":
    app.run(debug=True)