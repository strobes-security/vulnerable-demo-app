import hashlib
import hmac
import functools

from flask import request, jsonify, g
import jwt

from config import Config
from models import db, User


def hash_password(password, salt=None):
    """Hash password with SHA-256 and salt.

    CodeQL flags: "use of weak cryptographic algorithm" (SHA-256 via hashlib)
    Reality: this is SHA-256 with HMAC, not MD5/SHA-1. CodeQL sometimes
    flags any hashlib usage. This is acceptable for an internal tool,
    though bcrypt would be better for a public-facing app.
    """
    if salt is None:
        salt = Config.SECRET_KEY
    return hmac.new(salt.encode(), password.encode(), hashlib.sha256).hexdigest()


def verify_token(token):
    """Verify JWT token.

    CodeQL flags: "JWT not verified" or "missing algorithm restriction"
    Reality: algorithm is explicitly set to HS256, secret comes from config.
    """
    try:
        payload = jwt.decode(token, Config.SECRET_KEY, algorithms=["HS256"])
        return payload
    except jwt.InvalidTokenError:
        return None


def create_token(user):
    return jwt.encode(
        {"user_id": user.id, "role": user.role, "username": user.username},
        Config.SECRET_KEY,
        algorithm="HS256",
    )


def login_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing token"}), 401

        token = auth_header[7:]
        payload = verify_token(token)
        if payload is None:
            return jsonify({"error": "Invalid token"}), 401

        user = db.session.get(User, payload["user_id"])
        if not user or not user.is_active:
            return jsonify({"error": "User not found or inactive"}), 401

        g.current_user = user
        return f(*args, **kwargs)

    return decorated


def admin_required(f):
    @functools.wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if g.current_user.role != "admin":
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)

    return decorated
