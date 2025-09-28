from flask import Flask, request, jsonify, session
import sqlite3
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# -----------------------
# CORS Setup
# -----------------------
CORS(app, supports_credentials=True, resources={r"/*": {"origins": "http://127.0.0.1:5500"}})

# Secret key for sessions
app.secret_key = "supersecretkey"

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
# Helper: check login
# -----------------------
def require_login():
    return "user_id" in session

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

    # Use pbkdf2:sha256 to avoid unsupported scrypt error
    hashed_password = generate_password_hash(password, method="pbkdf2:sha256")

    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
                    (name, email, hashed_password))
        user_id = cur.lastrowid
        # create default settings
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
        session["user_id"] = user["id"]
        user_dict = dict(user)
        user_dict.pop("password")
        return jsonify({"message": "Login successful", "user": user_dict}), 200

    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/logout", methods=["POST"])
def logout():
    session.pop("user_id", None)
    return jsonify({"message": "Logged out successfully"})

# -----------------------
# Posts Routes
# -----------------------
@app.route("/posts", methods=["POST"])
def create_post():
    if not require_login():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    title = data.get("title")
    category = data.get("category")
    content = data.get("content")

    if not title or not category or not content:
        return jsonify({"error": "All fields are required"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute("INSERT INTO posts (user_id, title, category, content) VALUES (?, ?, ?, ?)",
                (session["user_id"], title, category, content))
    conn.commit()
    conn.close()
    return jsonify({"message": "Post created successfully!"}), 201

@app.route("/posts/user/<int:user_id>", methods=["GET"])
def get_user_posts(user_id):
    if not require_login() or session["user_id"] != user_id:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT p.id, p.title, p.category, p.content, p.created_at
        FROM posts p
        WHERE p.user_id=?
        ORDER BY p.created_at DESC
    """, (user_id,))
    posts = [dict(row) for row in cur.fetchall()]
    conn.close()
    return jsonify(posts), 200

@app.route("/posts", methods=["GET"])
def get_posts():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT p.id, p.title, p.category, p.content, p.created_at, u.name as author,
               IFNULL(ROUND(AVG(r.rating), 2), 0) as avg_rating,
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

@app.route("/posts/<int:post_id>", methods=["GET"])
def get_single_post(post_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT p.id, p.title, p.category, p.content, p.created_at, u.name as author,
               IFNULL(ROUND(AVG(r.rating), 2), 0) as avg_rating,
               COUNT(r.rating) as total_votes
        FROM posts p
        JOIN users u ON p.user_id = u.id
        LEFT JOIN ratings r ON p.id = r.post_id
        WHERE p.id=?
        GROUP BY p.id, u.name
    """, (post_id,))
    post = cur.fetchone()
    conn.close()
    if post:
        return jsonify(dict(post))
    return jsonify({"error": "Post not found"}), 404

@app.route("/posts/<int:post_id>", methods=["PUT"])
def update_post(post_id):
    if not require_login():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    title = data.get("title")
    category = data.get("category")
    content = data.get("content")

    if not title or not category or not content:
        return jsonify({"error": "All fields are required"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        UPDATE posts 
        SET title=?, category=?, content=?, updated_at=CURRENT_TIMESTAMP
        WHERE id=? AND user_id=?
    """, (title, category, content, post_id, session["user_id"]))
    if cur.rowcount == 0:
        return jsonify({"error": "Post not found or unauthorized"}), 404
    conn.commit()
    conn.close()
    return jsonify({"message": "Post updated successfully!"})

@app.route("/posts/<int:post_id>", methods=["DELETE"])
def delete_post(post_id):
    if not require_login():
        return jsonify({"error": "Unauthorized"}), 401
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM posts WHERE id=? AND user_id=?", (post_id, session["user_id"]))
    if cur.rowcount == 0:
        return jsonify({"error": "Post not found or unauthorized"}), 404
    conn.commit()
    conn.close()
    return jsonify({"message": "Post deleted successfully!"})

# -----------------------
# Ratings
# -----------------------
@app.route("/posts/<int:post_id>/rate", methods=["POST"])
def rate_post(post_id):
    if not require_login():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    rating = data.get("rating")
    if not rating or not (1 <= rating <= 5):
        return jsonify({"error": "Rating must be between 1 and 5"}), 400

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO ratings (user_id, post_id, rating)
        VALUES (?, ?, ?)
        ON CONFLICT(user_id, post_id) DO UPDATE SET rating=excluded.rating
    """, (session["user_id"], post_id, rating))
    conn.commit()
    conn.close()
    return jsonify({"message": "Rating submitted successfully!"})

@app.route("/posts/<int:post_id>/rating", methods=["GET"])
def get_post_rating(post_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT IFNULL(ROUND(AVG(rating),2),0) as avg_rating, COUNT(rating) as total_votes
        FROM ratings WHERE post_id=?
    """, (post_id,))
    result = cur.fetchone()
    conn.close()
    return jsonify(dict(result))

# -----------------------
# Settings
# -----------------------
@app.route("/settings", methods=["GET"])
def get_settings():
    if not require_login():
        return jsonify({"error": "Unauthorized"}), 401
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT default_category, theme FROM settings WHERE user_id=?", (session["user_id"],))
    settings = cur.fetchone()
    conn.close()
    return jsonify(dict(settings)) if settings else jsonify({})

@app.route("/settings", methods=["PUT"])
def update_settings():
    if not require_login():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    default_category = data.get("default_category")
    theme = data.get("theme")

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        UPDATE settings
        SET default_category=?, theme=?
        WHERE user_id=?
    """, (default_category, theme, session["user_id"]))
    conn.commit()
    conn.close()
    return jsonify({"message": "Settings updated successfully!"})

# -----------------------
# Run Server
# -----------------------
if __name__ == "__main__":
    init_db()
    app.run(debug=True)
