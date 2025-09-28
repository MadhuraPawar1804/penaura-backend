from flask import Flask, request, jsonify
from flask_cors import CORS
import pymysql
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps
import datetime
import os

# -----------------------
# Config
# -----------------------
app = Flask(__name__)

# Allow your frontend URL or "*" for testing
FRONTEND_URL = os.environ.get("FRONTEND_URL", "https://penaura-frontend.vercel.app")
SECRET_KEY = os.environ.get("SECRET_KEY", "supersecretkey")

MYSQL_HOST = os.environ.get("MYSQL_HOST")
MYSQL_USER = os.environ.get("MYSQL_USER")
MYSQL_PASSWORD = os.environ.get("MYSQL_PASSWORD")
MYSQL_DB = os.environ.get("MYSQL_DB")

# CORS configuration
CORS(app, supports_credentials=True, resources={r"/*": {"origins": FRONTEND_URL}})

# -----------------------
# Database Helper
# -----------------------
def get_db():
    try:
        conn = pymysql.connect(
            host=MYSQL_HOST,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            database=MYSQL_DB,
            cursorclass=pymysql.cursors.DictCursor
        )
        return conn
    except Exception as e:
        print("DB connection failed:", e)
        raise

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
        except Exception as e:
            return jsonify({"error": "Invalid token!", "details": str(e)}), 401
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
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO users (name, email, password) VALUES (%s, %s, %s)",
                (name, email, hashed_password)
            )
            user_id = cur.lastrowid
        conn.commit()
        return jsonify({"message": "User registered successfully!"}), 201
    except pymysql.err.IntegrityError:
        return jsonify({"error": "Email already exists!"}), 400
    except Exception as e:
        return jsonify({"error": "Server error", "details": str(e)}), 500
    finally:
        conn.close()

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    try:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE email=%s", (email,))
            user = cur.fetchone()
    except Exception as e:
        return jsonify({"error": "Server error", "details": str(e)}), 500
    finally:
        conn.close()

    if user and check_password_hash(user["password"], password):
        token = jwt.encode(
            {"user_id": user["id"], "exp": datetime.datetime.utcnow() + datetime.timedelta(days=7)},
            SECRET_KEY,
            algorithm="HS256"
        )
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

    try:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO posts (user_id, title, category, content) VALUES (%s, %s, %s, %s)",
                (user_id, title, category, content)
            )
        conn.commit()
        return jsonify({"message": "Post created successfully!"}), 201
    except Exception as e:
        return jsonify({"error": "Server error", "details": str(e)}), 500
    finally:
        conn.close()

@app.route("/posts", methods=["GET"])
def get_posts():
    try:
        conn = get_db()
        with conn.cursor() as cur:
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
            posts = cur.fetchall()
        return jsonify(posts)
    except Exception as e:
        return jsonify({"error": "Server error", "details": str(e)}), 500
    finally:
        conn.close()

# -----------------------
# Expose app for Vercel
# -----------------------
# ⚠️ Do NOT call app.run() on Vercel
# Use "vercel.json" to configure the serverless function
