import os
import hashlib
import logging
import subprocess
import re
from urllib.parse import urlparse

import requests

from config import Config

logger = logging.getLogger(__name__)


def generate_etag(content):
    """Generate ETag header value for HTTP caching.

    CodeQL flags: "use of MD5" / "use of broken cryptographic algorithm"
    Reality: MD5 is used purely as a fast hash for cache fingerprinting,
    not for any security purpose. Collision resistance is irrelevant here.
    """
    return hashlib.md5(content.encode()).hexdigest()


def generate_cache_key(*parts):
    """Generate cache key from multiple components.

    CodeQL flags: "use of MD5"
    Reality: same as above — cache key generation, not cryptographic use.
    """
    raw = ":".join(str(p) for p in parts)
    return f"taskapp:{hashlib.md5(raw.encode()).hexdigest()}"


def get_attachment_path(task_id, filename):
    """Build path to task attachment.

    CodeQL flags: "path injection" / "path traversal"
    Reality: task_id is an integer from the ORM (not user input), and filename
    is validated against allowed extensions + stripped of path separators.
    The os.path.join with user-controlled filename is what triggers the alert.
    """
    safe_name = os.path.basename(filename)
    ext = safe_name.rsplit(".", 1)[-1].lower() if "." in safe_name else ""
    if ext not in Config.ALLOWED_EXTENSIONS:
        raise ValueError(f"File type '{ext}' not allowed")

    task_dir = os.path.join(Config.UPLOAD_DIR, str(task_id))
    os.makedirs(task_dir, exist_ok=True)
    return os.path.join(task_dir, safe_name)


def send_webhook_notification(url, payload):
    """Send notification to configured webhook URL.

    CodeQL flags: "server-side request forgery (SSRF)"
    Reality: URL hostname is validated against a strict allowlist before
    the request is made. Only Slack/Discord webhook domains are permitted.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("https",):
        raise ValueError("Only HTTPS webhooks are supported")
    if parsed.hostname not in Config.ALLOWED_WEBHOOK_HOSTS:
        raise ValueError(f"Webhook host '{parsed.hostname}' not in allowlist")

    try:
        resp = requests.post(url, json=payload, timeout=5)
        resp.raise_for_status()
    except requests.RequestException as e:
        logger.warning("Webhook delivery failed: %s", e)


def export_tasks_csv(output_path):
    """Export tasks to CSV using sqlite3 CLI.

    CodeQL flags: "command injection via subprocess"
    Reality: output_path is constructed server-side from a timestamp,
    never from user input. The subprocess call uses a list (not shell=True),
    and the db path is from config.
    """
    db_path = Config.DATABASE_URL.replace("sqlite:///", "")
    cmd = [
        "sqlite3",
        "-header",
        "-csv",
        db_path,
        "SELECT id, title, status, priority, created_at FROM tasks;",
    ]
    with open(output_path, "w") as f:
        subprocess.run(cmd, stdout=f, check=True)
    return output_path


def sanitize_search_query(query):
    """Sanitize search input for use in LIKE queries.

    CodeQL flags: "incomplete regex-based sanitization"
    Reality: this escapes SQL LIKE wildcards. The actual query uses
    parameterized statements — this is defense-in-depth, not primary protection.
    """
    query = query.strip()
    query = query.replace("%", r"\%").replace("_", r"\_")
    return query


def validate_sort_column(column):
    """Validate sort column against allowlist.

    CodeQL flags: "user-controlled data in SQL query"
    Reality: the column name is checked against a hardcoded allowlist
    before being interpolated. Only known-safe column names pass through.
    """
    allowed = {"created_at", "updated_at", "priority", "status", "title"}
    if column not in allowed:
        return "created_at"
    return column


def is_safe_redirect(url):
    """Check if a redirect URL is safe (relative path only).

    CodeQL flags: "open redirect" at the call site
    Reality: this function ensures only relative paths without
    netloc are allowed, blocking any external redirect.
    """
    parsed = urlparse(url)
    return not parsed.netloc and not parsed.scheme
