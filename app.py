from flask import Flask, request, jsonify
import sqlite3
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps
import datetime
import os

app = Flask(__name__)

# -----------------------
# Config
# -----------------------
CORS(app, supports_credentials=True, resources={r"/*": {"origins": os.environ.get("FRONTEND_URL", "*")}})
SECRET_KEY = os.environ.get("SECRET_KEY", "supersecretkey")
DB = "penuaura.db"

# -----------------------
# Database Helper
# -----------------------
def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()
    # Users table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    # Posts table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        category TEXT CHECK(category IN ('poetry','short','novel')) NOT NULL,
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """)
    # Ratings table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS ratings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        post_id INTEGER NOT NULL,
        rating INTEGER CHECK(rating BETWEEN 1 AND 5),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, post_id),
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE
    )
    """)
    # Settings table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS settings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER UNIQUE NOT NULL,
        default_category TEXT CHECK(default_category IN ('poetry','short','novel')) DEFAULT 'poetry',
        theme TEXT CHECK(theme IN ('light','dark')) DEFAULT 'light',
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """)
    conn.commit()
    conn.close()

# -----------------------
# JWT Helper
# -----------------------
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not token:
            return jsonify({"error": "Token is missing!"}), 401
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            user_id = data["user_id"]
        except:
            return jsonify({"error": "Invalid token!"}), 401
        return f(user_id, *args, **kwargs)
    return decorated

# -----------------------
# Auth Routes
# -----------------------
@app.route("/signup", methods=["POST"])
def signup():
    data = request.json
    name = data.get("name")
    email = data.get("email")
    password = data.get("password")

    if not name or not email or not password:
        return jsonify({"error": "All fields are required"}), 400

    hashed_password = generate_password_hash(password, method="pbkdf2:sha256")

    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", (name, email, hashed_password))
        user_id = cur.lastrowid
        cur.execute("INSERT INTO settings (user_id) VALUES (?)", (user_id,))
        conn.commit()
        return jsonify({"message": "User registered successfully!"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Email already exists!"}), 400
    finally:
        conn.close()

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email=?", (email,))
    user = cur.fetchone()
    conn.close()

    if user and check_password_hash(user["password"], password):
        token = jwt.encode({"user_id": user["id"], "exp": datetime.datetime.utcnow() + datetime.timedelta(days=7)}, SECRET_KEY, algorithm="HS256")
        user_dict = dict(user)
        user_dict.pop("password")
        return jsonify({"message": "Login successful", "token": token, "user": user_dict}), 200

    return jsonify({"error": "Invalid credentials"}), 401

# -----------------------
# Posts Routes
# -----------------------
@app.route("/posts", methods=["POST"])
@token_required
def create_post(user_id):
    data = request.json
    title = data.get("title")
    category = data.get("category")
    content = data.get("content")

    if not title or not category or not content:
        return jsonify({"error": "All fields are required"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute("INSERT INTO posts (user_id, title, category, content) VALUES (?, ?, ?, ?)", (user_id, title, category, content))
    conn.commit()
    conn.close()
    return jsonify({"message": "Post created successfully!"}), 201

@app.route("/posts", methods=["GET"])
def get_posts():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT p.id, p.title, p.category, p.content, p.created_at, u.name as author,
               IFNULL(ROUND(AVG(r.rating),2),0) as avg_rating,
               COUNT(r.rating) as total_votes
        FROM posts p
        JOIN users u ON p.user_id = u.id
        LEFT JOIN ratings r ON p.id = r.post_id
        GROUP BY p.id, u.name
        ORDER BY p.created_at DESC
    """)
    posts = [dict(row) for row in cur.fetchall()]
    conn.close()
    return jsonify(posts)

# Add token_required decorator to other routes similarly...
# For brevity, update_post, delete_post, settings, rating routes should also use JWT

# -----------------------
# Run Server
# -----------------------
if __name__ == "__main__":
    init_db()
    app.run(debug=True)
