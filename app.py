"""
Advanced Authentication API - Flask + SQLite (users.db)
=========================================================
Features:
- Signup/Login via Email OR Phone Number + Password
- Password hashing (Werkzeug PBKDF2)
- JWT access + refresh tokens
- Account lockout after repeated failed logins (brute-force protection)
- Login history tracking with timestamp, IP, and user agent
- Change password / logout / get profile endpoints
- Input validation & consistent JSON error responses
- Auto-creates users.db with proper schema on first run

Install:
    pip install flask werkzeug pyjwt

Run:
    python app.py

Set a strong secret in production:
    export SECRET_KEY="your-very-secret-key"
"""

import os
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from flask import Flask, request, jsonify, g
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

DB_NAME = "users.db"
SECRET_KEY = os.environ.get("SECRET_KEY", "change-this-secret-key-in-production")
ACCESS_TOKEN_EXP_MINUTES = 30
REFRESH_TOKEN_EXP_DAYS = 7
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

EMAIL_REGEX = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
PHONE_REGEX = r"^\+?[0-9]{7,15}$"


# ------------------------------------------------------------------
# Database
# ------------------------------------------------------------------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_NAME)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            phone TEXT UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until TEXT,
            is_active INTEGER NOT NULL DEFAULT 1
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS login_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            login_time TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            status TEXT NOT NULL DEFAULT 'success',
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    """)

    cur.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_users_phone ON users(phone)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_login_history_user ON login_history(user_id)")

    conn.commit()
    conn.close()


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def now_dt():
    return datetime.now(timezone.utc)


def now_str():
    return now_dt().strftime("%Y-%m-%d %H:%M:%S")


def is_email(value):
    return bool(re.match(EMAIL_REGEX, value))


def is_phone(value):
    return bool(re.match(PHONE_REGEX, value))


def parse_ts(ts):
    return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)


def error(message, status=400):
    return jsonify({"error": message}), status


def generate_tokens(user_id):
    access_payload = {
        "user_id": user_id,
        "type": "access",
        "exp": now_dt() + timedelta(minutes=ACCESS_TOKEN_EXP_MINUTES),
        "iat": now_dt()
    }
    refresh_payload = {
        "user_id": user_id,
        "type": "refresh",
        "exp": now_dt() + timedelta(days=REFRESH_TOKEN_EXP_DAYS),
        "iat": now_dt()
    }
    access_token = jwt.encode(access_payload, SECRET_KEY, algorithm="HS256")
    refresh_token = jwt.encode(refresh_payload, SECRET_KEY, algorithm="HS256")
    return access_token, refresh_token


def store_refresh_token(user_id, token):
    db = get_db()
    expires_at = (now_dt() + timedelta(days=REFRESH_TOKEN_EXP_DAYS)).strftime("%Y-%m-%d %H:%M:%S")
    db.execute(
        "INSERT INTO refresh_tokens (user_id, token, created_at, expires_at) VALUES (?, ?, ?, ?)",
        (user_id, token, now_str(), expires_at)
    )
    db.commit()


# ------------------------------------------------------------------
# Auth decorator
# ------------------------------------------------------------------

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return error("missing or invalid Authorization header", 401)

        token = auth_header.split(" ", 1)[1]
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            if payload.get("type") != "access":
                return error("invalid token type", 401)
            g.user_id = payload["user_id"]
        except jwt.ExpiredSignatureError:
            return error("token has expired", 401)
        except jwt.InvalidTokenError:
            return error("invalid token", 401)

        return f(*args, **kwargs)
    return decorated


# ------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------

@app.route("/api/signup", methods=["POST"])
def signup():
    data = request.get_json(silent=True) or {}
    identifier = (data.get("identifier") or "").strip()
    password = data.get("password") or ""

    if not identifier or not password:
        return error("identifier and password are required")

    if len(password) < 6:
        return error("password must be at least 6 characters")

    email = identifier if is_email(identifier) else None
    phone = identifier if (is_phone(identifier) and not email) else None

    if not email and not phone:
        return error("identifier must be a valid email or phone number")

    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT id FROM users WHERE email = ? OR phone = ?", (email, phone))
    if cur.fetchone():
        return error("user already exists", 409)

    password_hash = generate_password_hash(password)
    created_at = now_str()

    cur.execute(
        "INSERT INTO users (email, phone, password_hash, created_at) VALUES (?, ?, ?, ?)",
        (email, phone, password_hash, created_at)
    )
    db.commit()

    return jsonify({
        "message": "signup successful",
        "identifier": identifier,
        "created_at": created_at
    }), 201


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    identifier = (data.get("identifier") or "").strip()
    password = data.get("password") or ""

    if not identifier or not password:
        return error("identifier and password are required")

    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE email = ? OR phone = ?", (identifier, identifier))
    user = cur.fetchone()

    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    ua = request.headers.get("User-Agent", "unknown")
    login_time = now_str()

    if not user:
        return error("invalid credentials", 401)

    # Check lockout
    if user["locked_until"]:
        locked_until = parse_ts(user["locked_until"])
        if now_dt() < locked_until:
            remaining = int((locked_until - now_dt()).total_seconds() // 60) + 1
            return error(f"account locked. try again in {remaining} minute(s)", 423)

    if not user["is_active"]:
        return error("account is disabled", 403)

    if not check_password_hash(user["password_hash"], password):
        failed = user["failed_attempts"] + 1
        locked_until = None
        if failed >= MAX_FAILED_ATTEMPTS:
            locked_until = (now_dt() + timedelta(minutes=LOCKOUT_MINUTES)).strftime("%Y-%m-%d %H:%M:%S")

        cur.execute(
            "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
            (failed, locked_until, user["id"])
        )
        cur.execute(
            "INSERT INTO login_history (user_id, login_time, ip_address, user_agent, status) VALUES (?, ?, ?, ?, ?)",
            (user["id"], login_time, ip, ua, "failed")
        )
        db.commit()

        if locked_until:
            return error(f"too many failed attempts. account locked for {LOCKOUT_MINUTES} minutes", 423)
        return error("invalid credentials", 401)

    # Success: reset failed attempts, record login
    cur.execute(
        "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
        (user["id"],)
    )
    cur.execute(
        "INSERT INTO login_history (user_id, login_time, ip_address, user_agent, status) VALUES (?, ?, ?, ?, ?)",
        (user["id"], login_time, ip, ua, "success")
    )
    db.commit()

    access_token, refresh_token = generate_tokens(user["id"])
    store_refresh_token(user["id"], refresh_token)

    return jsonify({
        "message": "login successful",
        "identifier": identifier,
        "login_time": login_time,
        "account_created": user["created_at"],
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "Bearer",
        "expires_in_minutes": ACCESS_TOKEN_EXP_MINUTES
    }), 200


@app.route("/api/refresh", methods=["POST"])
def refresh():
    data = request.get_json(silent=True) or {}
    token = data.get("refresh_token")
    if not token:
        return error("refresh_token is required")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        if payload.get("type") != "refresh":
            return error("invalid token type", 401)
    except jwt.ExpiredSignatureError:
        return error("refresh token has expired", 401)
    except jwt.InvalidTokenError:
        return error("invalid refresh token", 401)

    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM refresh_tokens WHERE token = ? AND revoked = 0", (token,))
    row = cur.fetchone()
    if not row:
        return error("refresh token not found or revoked", 401)

    access_token, _ = generate_tokens(payload["user_id"])
    return jsonify({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in_minutes": ACCESS_TOKEN_EXP_MINUTES
    }), 200


@app.route("/api/logout", methods=["POST"])
def logout():
    data = request.get_json(silent=True) or {}
    token = data.get("refresh_token")
    if not token:
        return error("refresh_token is required")

    db = get_db()
    cur = db.cursor()
    cur.execute("UPDATE refresh_tokens SET revoked = 1 WHERE token = ?", (token,))
    db.commit()

    return jsonify({"message": "logged out successfully"}), 200


@app.route("/api/profile", methods=["GET"])
@token_required
def profile():
    db = get_db()
    cur = db.cursor()
    cur.execute(
        "SELECT id, email, phone, created_at, updated_at FROM users WHERE id = ?",
        (g.user_id,)
    )
    user = cur.fetchone()
    if not user:
        return error("user not found", 404)

    return jsonify({
        "id": user["id"],
        "email": user["email"],
        "phone": user["phone"],
        "created_at": user["created_at"],
        "updated_at": user["updated_at"]
    }), 200


@app.route("/api/change-password", methods=["POST"])
@token_required
def change_password():
    data = request.get_json(silent=True) or {}
    old_password = data.get("old_password") or ""
    new_password = data.get("new_password") or ""

    if not old_password or not new_password:
        return error("old_password and new_password are required")
    if len(new_password) < 6:
        return error("new_password must be at least 6 characters")

    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (g.user_id,))
    user = cur.fetchone()

    if not check_password_hash(user["password_hash"], old_password):
        return error("old password is incorrect", 401)

    new_hash = generate_password_hash(new_password)
    cur.execute(
        "UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
        (new_hash, now_str(), g.user_id)
    )
    db.commit()

    return jsonify({"message": "password updated successfully"}), 200


@app.route("/api/history", methods=["GET"])
@token_required
def login_history():
    db = get_db()
    cur = db.cursor()
    cur.execute(
        "SELECT login_time, ip_address, user_agent, status FROM login_history WHERE user_id = ? ORDER BY login_time DESC LIMIT 50",
        (g.user_id,)
    )
    rows = cur.fetchall()

    return jsonify({
        "login_count": len(rows),
        "history": [
            {
                "login_time": r["login_time"],
                "ip_address": r["ip_address"],
                "user_agent": r["user_agent"],
                "status": r["status"]
            } for r in rows
        ]
    }), 200


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "time": now_str()}), 200


# ------------------------------------------------------------------
# Error handlers
# ------------------------------------------------------------------

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "endpoint not found"}), 404


@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "method not allowed"}), 405


@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "internal server error"}), 500


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------

if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
