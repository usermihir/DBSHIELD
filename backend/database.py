import os
from pathlib import Path
import sqlite3

from sql_injection_prevention.sql_proxy import SQLFirewallProxy

try:
    from dotenv import load_dotenv
except ImportError:
    def load_dotenv(*args, **kwargs):
        return False

BASE_DIR = Path(__file__).resolve().parent
ENV_PATH = BASE_DIR.parent / ".env"
load_dotenv(dotenv_path=ENV_PATH)

DEFAULT_DB_PATH = BASE_DIR.parent / "database" / "dbshield.sqlite3"
DB_PATH = Path(os.getenv("SQLITE_DB_PATH", str(DEFAULT_DB_PATH))).expanduser().resolve()
SCHEMA_PATH = BASE_DIR.parent / "database" / "tables.sql"


def initialize_database() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        schema_sql = SCHEMA_PATH.read_text(encoding="utf-8")
        conn.executescript(schema_sql)
        conn.execute(
            f"""
            INSERT OR IGNORE INTO users (username, email, password, role, name, phone)
            VALUES ('admin', 'admin@dbshield.local', 'admin123', 'admin', 'Admin User', '9000000000')
            """
        )
        conn.commit()

def connect_to_db() -> SQLFirewallProxy:
    """
    Return a SQLFirewallProxy wrapping a sqlite3.Connection.

    When ENABLE_DB_PROXY=true in .env, every SQL query executed through this
    connection is parsed into an AST and checked for injection patterns before
    it reaches the database. The proxy is transparent — it exposes the same
    .execute() / .cursor() / .close() interface as a raw sqlite3.Connection.
    """
    proxy_enabled = os.getenv("ENABLE_DB_PROXY", "false").strip().lower() in ("1", "true", "yes", "on")

    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.row_factory = sqlite3.Row

    proxy = SQLFirewallProxy(conn, enabled=proxy_enabled)

    # Register all known-good query templates used by the application.
    # Any query whose structural skeleton matches a registered template is
    # automatically allowed, eliminating false positives.
    _register_app_templates(proxy)

    return proxy


_APP_QUERY_TEMPLATES = [
    # Auth
    "SELECT id, username, email, password, role, name, phone FROM users WHERE username = ?",
    # Students
    "SELECT * FROM students WHERE id = ?",
    "SELECT s.*, u.username, u.name FROM students s JOIN users u ON s.id = u.id WHERE u.username = ?",
    # Courses
    "SELECT * FROM courses",
    "SELECT * FROM courses WHERE course_code = ?",
    "SELECT * FROM courses WHERE title LIKE ?",
    "INSERT INTO courses (course_code, title, credits, instructor_id) VALUES (?, ?, ?, ?)",
    "DELETE FROM courses WHERE course_code = ?",
    # Enrollments
    "SELECT * FROM enrollments WHERE student_id = ?",
    "SELECT e.*, c.title FROM enrollments e JOIN courses c ON e.course_code = c.course_code WHERE e.student_id = ?",
    "INSERT INTO enrollments (student_id, course_code) VALUES (?, ?)",
    "DELETE FROM enrollments WHERE student_id = ? AND course_code = ?",
    "UPDATE enrollments SET grade = ? WHERE student_id = ? AND course_code = ?",
    # Assignments
    "SELECT * FROM assignments WHERE course_code = ?",
    "INSERT INTO assignments (course_code, title, due_date) VALUES (?, ?, ?)",
    # Users
    "INSERT INTO users (username, email, password, role, name) VALUES (?, ?, ?, ?, ?)",
    "DELETE FROM users WHERE username = ?",
    "SELECT id, username, role, name FROM users WHERE role = ?",
    # Materials
    "INSERT INTO course_materials (course_code, title, resource_link) VALUES (?, ?, ?)",
]


def _register_app_templates(proxy: SQLFirewallProxy) -> None:
    """Pre-register every known-good query template with the proxy whitelist."""
    for template in _APP_QUERY_TEMPLATES:
        proxy.register_template(template)

def handle_student_login(username: str, password: str):
    import time
    
    time.sleep(1)
    
    sql_query = f"SELECT * from users WHERE username='{username}' AND password='{password}'"
    conn = connect_to_db()
    try:
        cursor = conn.cursor()
        cursor.execute(sql_query)
        result = cursor.fetchone()
    finally:
        conn.close()

    return dict(result) if result else None
