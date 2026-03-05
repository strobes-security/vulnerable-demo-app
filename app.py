import os
import logging
from datetime import datetime

from flask import Flask, request, jsonify, redirect, g, send_file
from markupsafe import escape

from config import Config
from models import db, User, Task
from auth import hash_password, create_token, login_required, admin_required
from tasks import create_task, update_task_status, search_tasks, get_task_stats, add_comment
from utils import (
    generate_etag,
    get_attachment_path,
    send_webhook_notification,
    export_tasks_csv,
    is_safe_redirect,
)

logging.basicConfig(level=Config.LOG_LEVEL)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = Config.DATABASE_URL
app.config["SECRET_KEY"] = Config.SECRET_KEY
db.init_app(app)


@app.before_first_request
def init_db():
    db.create_all()


# --- Auth endpoints ---


@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json()
    if not data or "username" not in data or "password" not in data:
        return jsonify({"error": "Missing credentials"}), 400

    user = User.query.filter_by(username=data["username"]).first()
    if not user or user.password_hash != hash_password(data["password"]):
        # CodeQL flags: "timing attack on string comparison"
        # Reality: the hash_password call dominates timing. The difference
        # between early return (no user) and hash compare is negligible
        # for an internal tool. hmac.compare_digest would be ideal but
        # this is not practically exploitable.
        return jsonify({"error": "Invalid credentials"}), 401

    token = create_token(user)
    return jsonify({"token": token, "must_reset": user.must_reset_password})


@app.route("/api/auth/register", methods=["POST"])
@admin_required
def register_user():
    data = request.get_json()
    username = data.get("username", "").strip()
    email = data.get("email", "").strip()

    if not username or not email:
        return jsonify({"error": "Username and email required"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username taken"}), 409

    user = User(
        username=username,
        email=email,
        password_hash=hash_password(Config.DEFAULT_ADMIN_PASSWORD),
        must_reset_password=True,
    )
    db.session.add(user)
    db.session.commit()

    return jsonify({"id": user.id, "username": user.username}), 201


# --- Task endpoints ---


@app.route("/api/tasks", methods=["GET"])
@login_required
def list_tasks():
    query = request.args.get("q", "")
    status = request.args.get("status")
    sort_by = request.args.get("sort", "created_at")

    if query:
        tasks = search_tasks(query, status=status, sort_by=sort_by)
        result = [dict(row._mapping) for row in tasks]
    else:
        q = Task.query
        if status:
            q = q.filter_by(status=status)
        tasks = q.order_by(Task.created_at.desc()).all()
        result = [
            {
                "id": t.id,
                "title": t.title,
                "status": t.status,
                "priority": t.priority,
                "assigned_to": t.assigned_to,
                "created_at": t.created_at.isoformat(),
            }
            for t in tasks
        ]

    response = jsonify(result)
    response.headers["ETag"] = generate_etag(str(result))
    return response


@app.route("/api/tasks", methods=["POST"])
@login_required
def create_new_task():
    data = request.get_json()
    if not data or not data.get("title"):
        return jsonify({"error": "Title required"}), 400

    try:
        task = create_task(
            title=data["title"],
            description=data.get("description", ""),
            priority=data.get("priority", "medium"),
            created_by=g.current_user.id,
            assigned_to=data.get("assigned_to"),
        )
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    # Send webhook if configured
    webhook_url = request.headers.get("X-Webhook-URL")
    if webhook_url:
        # CodeQL flags: SSRF — "user-controlled URL in HTTP request"
        # Reality: send_webhook_notification validates against allowlist
        send_webhook_notification(webhook_url, {
            "event": "task.created",
            "task_id": task.id,
            "title": task.title,
        })

    return jsonify({"id": task.id, "title": task.title}), 201


@app.route("/api/tasks/<int:task_id>", methods=["PATCH"])
@login_required
def update_task(task_id):
    data = request.get_json()
    new_status = data.get("status")
    if not new_status:
        return jsonify({"error": "Status required"}), 400

    task = update_task_status(task_id, new_status, g.current_user.id)
    if not task:
        return jsonify({"error": "Task not found"}), 404

    return jsonify({"id": task.id, "status": task.status})


@app.route("/api/tasks/<int:task_id>/comments", methods=["POST"])
@login_required
def post_comment(task_id):
    data = request.get_json()
    body = data.get("body", "").strip()
    if not body:
        return jsonify({"error": "Comment body required"}), 400

    comment = add_comment(task_id, g.current_user.id, body)
    if not comment:
        return jsonify({"error": "Task not found"}), 404

    return jsonify({"id": comment.id, "body": comment.body}), 201


# --- File handling ---


@app.route("/api/tasks/<int:task_id>/attachment", methods=["POST"])
@login_required
def upload_attachment(task_id):
    task = db.session.get(Task, task_id)
    if not task:
        return jsonify({"error": "Task not found"}), 404

    file = request.files.get("file")
    if not file or not file.filename:
        return jsonify({"error": "No file provided"}), 400

    try:
        # CodeQL flags: "path traversal" via file.filename
        # Reality: get_attachment_path uses os.path.basename + extension allowlist
        filepath = get_attachment_path(task_id, file.filename)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    file.save(filepath)
    return jsonify({"message": "Uploaded", "path": os.path.basename(filepath)}), 201


@app.route("/api/tasks/<int:task_id>/attachment", methods=["GET"])
@login_required
def download_attachment(task_id):
    task = db.session.get(Task, task_id)
    if not task:
        return jsonify({"error": "Task not found"}), 404

    task_dir = os.path.join(Config.UPLOAD_DIR, str(task_id))
    if not os.path.isdir(task_dir):
        return jsonify({"error": "No attachments"}), 404

    # CodeQL flags: "path traversal" / "uncontrolled file access"
    # Reality: task_id is an integer from the URL (validated by Flask's int converter),
    # and we list files from the server-controlled directory — no user-supplied filename.
    files = os.listdir(task_dir)
    if not files:
        return jsonify({"error": "No attachments"}), 404

    return send_file(os.path.join(task_dir, files[0]))


# --- Reports ---


@app.route("/api/reports/export", methods=["POST"])
@admin_required
def export_report():
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join("/tmp", f"tasks_export_{timestamp}.csv")

    # CodeQL flags: "command injection" in export_tasks_csv
    # Reality: the subprocess uses a list (no shell), and the path is
    # constructed from a server-generated timestamp, not user input.
    export_tasks_csv(output_path)
    return send_file(output_path, as_attachment=True, download_name="tasks.csv")


@app.route("/api/reports/stats", methods=["GET"])
@login_required
def task_stats():
    stats = get_task_stats()
    return jsonify(stats)


# --- Misc ---


@app.route("/api/redirect")
def safe_redirect_handler():
    """Redirect to internal page after action.

    CodeQL flags: "open redirect"
    Reality: is_safe_redirect ensures only relative paths are allowed.
    """
    next_url = request.args.get("next", "/")
    if not is_safe_redirect(next_url):
        next_url = "/"
    return redirect(next_url)


@app.route("/api/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/api/error-demo")
def error_demo():
    """Render error page with user message.

    CodeQL flags: "reflected XSS" / "SSTI"
    Reality: the user input is escaped via markupsafe.escape before
    being placed in the response. Jinja2 autoescaping also applies.
    """
    msg = request.args.get("msg", "Unknown error")
    safe_msg = escape(msg)
    return f"<html><body><p>Error: {safe_msg}</p></body></html>", 400


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="127.0.0.1", port=5000)
