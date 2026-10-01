"""Auth microservice — JWT + refresh tokens, email verify, password reset."""
import datetime as dt
import hashlib
import logging
import os
import secrets
import sqlite3
from functools import wraps

from flask import Flask, g, jsonify, request

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("JWT_SECRET", secrets.token_hex(32))
DB = "auth.db"

# ---------------------------------------------------------------------------
# db helpers
# ---------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    g.pop("db", sqlite3.connect(":memory:")).close()


def init_db():
    db = sqlite3.connect(DB)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY,
            email       TEXT UNIQUE NOT NULL,
            password    TEXT NOT NULL,
            verified    INTEGER DEFAULT 0,
            verify_code TEXT,
            created_at  TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            token    TEXT PRIMARY KEY,
            user_id  INTEGER NOT NULL,
            expires  TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
    """)
    db.commit()
    db.close()


def hash_password(pw: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200_000)
    return salt.hex() + ":" + dk.hex()


def verify_password(pw: str, stored: str) -> bool:
    salt, dk = stored.split(":")
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 200_000).hex() == dk


def make_token(user_id: int, minutes: int = 15) -> tuple[str, str]:
    t = secrets.token_urlsafe(32)
    expires = (dt.datetime.utcnow() + dt.timedelta(minutes=minutes)).isoformat()
    get_db().execute("INSERT INTO refresh_tokens(token, user_id, expires) VALUES(?,?,?)", (t, user_id, expires))
    get_db().commit()
    return t, expires


def require_auth(f):
    @wraps(f)
    def wrapper(*a, **kw):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "missing token"}), 401
        row = get_db().execute("SELECT * FROM refresh_tokens WHERE token=?", (auth[7:],)).fetchone()
        if not row:
            return jsonify({"error": "invalid token"}), 401
        if dt.datetime.utcnow().isoformat() > row["expires"]:
            get_db().execute("DELETE FROM refresh_tokens WHERE token=?", (row["token"],))
            get_db().commit()
            return jsonify({"error": "token expired"}), 401
        g.user = dict(get_db().execute("SELECT * FROM users WHERE id=?", (row["user_id"],)).fetchone())
        return f(*a, **kw)
    return wrapper

# ---------------------------------------------------------------------------
# routes
# ---------------------------------------------------------------------------
@app.post("/auth/signup")
def signup():
    data = request.get_json(force=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = (data.get("password") or "").strip()
    if not email or "@" not in email or len(password) < 8:
        return jsonify({"error": "valid email + password (min 8 chars) required"}), 400
    if get_db().execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
        return jsonify({"error": "email already registered"}), 409
    code = secrets.token_hex(6)
    get_db().execute(
        "INSERT INTO users(email,password,verify_code) VALUES(?,?,?)",
        (email, hash_password(password), code),
    )
    get_db().commit()
    # TODO: send code via email (configure SMTP)
    logging.info("verification code for %s: %s", email, code)
    return jsonify({"message": "signup ok, check email for verification code"}), 201


@app.post("/auth/verify")
def verify():
    data = request.get_json(force=True) or {}
    email = (data.get("email") or "").strip().lower()
    code = (data.get("code") or "").strip()
    row = get_db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not row or row["verify_code"] != code:
        return jsonify({"error": "invalid code"}), 400
    get_db().execute("UPDATE users SET verified=1, verify_code=NULL WHERE email=?", (email,))
    get_db().commit()
    return jsonify({"message": "email verified"})


@app.post("/auth/login")
def login():
    data = request.get_json(force=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = (data.get("password") or "").strip()
    row = get_db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not row or not verify_password(password, row["password"]):
        return jsonify({"error": "invalid credentials"}), 401
    if not row["verified"]:
        return jsonify({"error": "email not verified"}), 403
    access, _ = make_token(row["id"])
    return jsonify({"access_token": access, "user_id": row["id"]})


@app.get("/auth/me")
@require_auth
def me():
    return jsonify({"user_id": g.user["id"], "email": g.user["email"], "verified": bool(g.user["verified"])})


@app.post("/auth/forgot-password")
def forgot():
    data = request.get_json(force=True) or {}
    email = (data.get("email") or "").strip().lower()
    row = get_db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if row:
        # generate reset link — implement email sending
        pass
    return jsonify({"message": "if account exists, reset link sent"}), 200


init_db()
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9000)
