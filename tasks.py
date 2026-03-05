import logging

from sqlalchemy import text

from models import db, Task, Comment
from utils import validate_sort_column, sanitize_search_query

logger = logging.getLogger(__name__)

VALID_STATUSES = {"open", "in_progress", "review", "closed"}
VALID_PRIORITIES = {"low", "medium", "high", "critical"}


def create_task(title, description, priority, created_by, assigned_to=None):
    if priority not in VALID_PRIORITIES:
        raise ValueError(f"Invalid priority: {priority}")

    task = Task(
        title=title,
        description=description,
        priority=priority,
        created_by=created_by,
        assigned_to=assigned_to,
    )
    db.session.add(task)
    db.session.commit()
    return task


def update_task_status(task_id, new_status, user_id):
    if new_status not in VALID_STATUSES:
        raise ValueError(f"Invalid status: {new_status}")

    task = db.session.get(Task, task_id)
    if not task:
        return None

    task.status = new_status
    db.session.commit()
    logger.info("Task %d status changed to %s by user %d", task_id, new_status, user_id)
    return task


def search_tasks(query_str, status=None, sort_by="created_at"):
    """Search tasks with optional filters.

    CodeQL flags: "SQL injection via string concatenation"
    Reality: the dynamic SQL is built with parameterized placeholders (:param).
    The only interpolated value is sort_column, which passes through
    validate_sort_column() — a strict allowlist. The search term and status
    are bound parameters, never interpolated into the query string.
    """
    sort_column = validate_sort_column(sort_by)
    sanitized_query = sanitize_search_query(query_str)

    sql = f"SELECT * FROM tasks WHERE title LIKE :search"
    params = {"search": f"%{sanitized_query}%"}

    if status and status in VALID_STATUSES:
        sql += " AND status = :status"
        params["status"] = status

    # CodeQL will flag this f-string SQL construction
    # but sort_column is from a hardcoded allowlist
    sql += f" ORDER BY {sort_column} DESC"

    result = db.session.execute(text(sql), params)
    return result.fetchall()


def get_task_stats():
    """Get task count grouped by status.

    CodeQL flags: "use of raw SQL"
    Reality: this is a static query with no user input whatsoever.
    """
    sql = text("SELECT status, COUNT(*) as count FROM tasks GROUP BY status")
    result = db.session.execute(sql)
    return {row.status: row.count for row in result}


def add_comment(task_id, user_id, body):
    task = db.session.get(Task, task_id)
    if not task:
        return None

    comment = Comment(task_id=task_id, user_id=user_id, body=body)
    db.session.add(comment)
    db.session.commit()
    return comment
