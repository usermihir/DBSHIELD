"""
test_sql_proxy.py — Unit tests for the AST SQL Firewall Proxy

Run from the project root:
    python -m pytest backend/sql_injection_prevention/tests/ -v

Each test verifies one of the four detection rules:
  1. Stacked queries
  2. Comment stripping
  3. UNION injection
  4. Tautology injection

And a final group verifies that legitimate parameterised queries pass cleanly.
"""
import sys
from pathlib import Path

import pytest

# Make sure the backend package is importable when running from project root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent))

from backend.sql_injection_prevention.sql_proxy import (
    SQLInjectionDetected,
    analyze_sql,
    QueryTemplateWhitelist,
)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _assert_blocked(sql: str, expected_reason: str, whitelist=None) -> None:
    with pytest.raises(SQLInjectionDetected) as exc_info:
        analyze_sql(sql, whitelist)
    assert exc_info.value.reason == expected_reason, (
        f"Expected reason '{expected_reason}', got '{exc_info.value.reason}'"
    )


def _assert_allowed(sql: str, whitelist=None) -> None:
    """Verify that a clean query passes through without raising."""
    analyze_sql(sql, whitelist)  # must not raise


# ---------------------------------------------------------------------------
# Rule 1 — Stacked queries
# ---------------------------------------------------------------------------

class TestStackedQueries:
    def test_drop_table_stacked(self):
        _assert_blocked(
            "SELECT * FROM users WHERE id = 1; DROP TABLE users; --",
            "stacked_queries",
        )

    def test_insert_stacked(self):
        _assert_blocked(
            "SELECT 1; INSERT INTO users VALUES ('evil', 'x', 'x', 'x', 'admin', 'x', '0')",
            "stacked_queries",
        )

    def test_update_stacked(self):
        _assert_blocked(
            "SELECT id FROM users; UPDATE users SET role='admin' WHERE username='student1'",
            "stacked_queries",
        )


# ---------------------------------------------------------------------------
# Rule 2 — Comment stripping
# ---------------------------------------------------------------------------

class TestCommentStripping:
    def test_single_line_comment(self):
        _assert_blocked(
            "SELECT * FROM users WHERE username='admin'--",
            "comment_stripping",
        )

    def test_single_line_comment_with_space(self):
        _assert_blocked(
            "SELECT * FROM users WHERE username='admin' -- and password='x'",
            "comment_stripping",
        )

    def test_multiline_comment(self):
        _assert_blocked(
            "SELECT * FROM users WHERE username='admin'/* injected */",
            "comment_stripping",
        )


# ---------------------------------------------------------------------------
# Rule 3 — UNION injection
# ---------------------------------------------------------------------------

class TestUnionInjection:
    def test_union_select_basic(self):
        _assert_blocked(
            "SELECT id FROM users WHERE id=1 UNION SELECT username FROM users",
            "union_injection",
        )

    def test_union_select_with_literals(self):
        # This payload has UNION and a trailing comment (--).
        # comment_stripping fires first (it's rule 2, UNION check is rule 3).
        # Either detection means the attack is blocked — both are correct behavior.
        with pytest.raises(SQLInjectionDetected) as exc_info:
            analyze_sql("' UNION SELECT 1,'pwned','pwned@example.com','x','admin','Injected','' --")
        assert exc_info.value.reason in ("comment_stripping", "union_injection")

    def test_union_all(self):
        _assert_blocked(
            "SELECT id FROM users UNION ALL SELECT password FROM users",
            "union_injection",
        )

    def test_whitelisted_union_passes(self):
        """A UNION query pre-registered as a template must be allowed through."""
        wl = QueryTemplateWhitelist()
        legitimate_union = (
            "SELECT course_code FROM courses WHERE instructor_id = 1 "
            "UNION SELECT course_code FROM enrollments WHERE student_id = 1"
        )
        wl.register(legitimate_union)
        _assert_allowed(legitimate_union, whitelist=wl)


# ---------------------------------------------------------------------------
# Rule 4 — Tautology injection
# ---------------------------------------------------------------------------

class TestTautologyInjection:
    def test_or_1_equals_1(self):
        _assert_blocked(
            "SELECT * FROM users WHERE username='' OR 1=1",
            "tautology_injection",
        )

    def test_or_string_tautology(self):
        _assert_blocked(
            "SELECT * FROM users WHERE username='' OR 'a'='a'",
            "tautology_injection",
        )

    def test_classic_login_bypass(self):
        _assert_blocked(
            "SELECT * FROM users WHERE username='' OR '1'='1' AND password='' OR '1'='1'",
            "tautology_injection",
        )


# ---------------------------------------------------------------------------
# Legitimate queries — must NOT be blocked
# ---------------------------------------------------------------------------

class TestLegitimateQueries:
    def test_parameterised_select(self):
        _assert_allowed("SELECT id, username, role FROM users WHERE username = ?")

    def test_parameterised_insert(self):
        _assert_allowed(
            "INSERT INTO users (username, email, password, role, name) VALUES (?, ?, ?, ?, ?)"
        )

    def test_parameterised_update(self):
        _assert_allowed(
            "UPDATE enrollments SET grade = ? WHERE student_id = ? AND course_code = ?"
        )

    def test_simple_count(self):
        _assert_allowed("SELECT COUNT(*) FROM users")

    def test_join_query(self):
        _assert_allowed(
            "SELECT u.username, e.course_code, e.grade "
            "FROM users u JOIN enrollments e ON u.id = e.student_id "
            "WHERE u.username = ?"
        )

    def test_schema_inspection(self):
        # This is the kind of query the app itself runs internally
        _assert_allowed("SELECT name FROM sqlite_master WHERE type='table'")
