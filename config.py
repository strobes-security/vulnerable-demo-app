import os


class Config:
    # CodeQL flags: "hardcoded credentials"
    # Reality: these are dev defaults, overridden by env vars in production
    SECRET_KEY = os.environ.get("SECRET_KEY", "local-dev-key-not-for-production")
    DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///tasks.db")
    REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

    # CodeQL flags: "hardcoded password"
    # Reality: default admin password only used to seed dev DB, forced reset on first login
    DEFAULT_ADMIN_PASSWORD = os.environ.get("DEFAULT_ADMIN_PW", "changeme123")

    UPLOAD_DIR = os.environ.get("UPLOAD_DIR", "/tmp/taskapp/uploads")
    MAX_UPLOAD_SIZE = 5 * 1024 * 1024  # 5MB
    ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "txt", "docx"}

    ALLOWED_WEBHOOK_HOSTS = {"hooks.slack.com", "discord.com", "webhook.site"}

    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
