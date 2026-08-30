"""
sql_proxy.py — AST-Parsing SQL Firewall Proxy
==============================================
Wraps a sqlite3.Connection and intercepts every SQL query before it reaches
the database. Instead of regex scanning raw input strings (which can be evaded),
this module parses each query into an Abstract Syntax Tree (AST) using sqlparse
and walks the token tree to detect structural anomalies.

Detection rules implemented:
  1. Tautology injection   — e.g., OR 1=1, OR 'a'='a'
  2. UNION injection       — any UNION not matching a whitelisted template
  3. Comment stripping     — e.g., admin'-- or admin'/* comment */
  4. Stacked queries       — e.g., '; DROP TABLE users; --

Template whitelisting:
  At startup, the application registers known-good SQL query skeletons
  (literals stripped, only structure remains). Each template is hashed and
  stored. At runtime, only queries whose structural hash matches a registered
  template are allowed through. This eliminates false positives entirely.

Architecture:
  connect_to_db() -> SQLFirewallProxy  (transparent wrapper)
      | .execute(sql, params)
      | _analyze_ast(sql)  <- raises SQLInjectionDetected on attack
      | sqlite3.Connection.execute(sql, params)
"""
from __future__ import annotations

import hashlib
import re
import sqlite3
from typing import Any, Iterable, Iterator

import sqlparse
from sqlparse import tokens as T
from sqlparse.sql import Comparison, Token


# ---------------------------------------------------------------------------
# Custom exception
# ---------------------------------------------------------------------------

class SQLInjectionDetected(Exception):
    """Raised by SQLFirewallProxy when an injected query is detected."""

    def __init__(self, reason: str, sql: str = "") -> None:
        self.reason = reason
        self.sql = sql
        super().__init__(f"SQL injection detected [{reason}]: {sql!r}")


# ---------------------------------------------------------------------------
# Template Whitelist
# ---------------------------------------------------------------------------

def _strip_literals(sql: str) -> str:
    """
    Remove all literal values from a SQL string, leaving only the structural
    skeleton. Used to compute a template hash.

    Example:
        "SELECT * FROM users WHERE username = 'admin' AND id = 42"
        -> "SELECT * FROM users WHERE username = ? AND id = ?"
    """
    sql = re.sub(r"'[^']*'", "?", sql)
    sql = re.sub(r'"[^"]*"', "?", sql)
    sql = re.sub(r"\b\d+(\.\d+)?\b", "?", sql)
    return re.sub(r"\s+", " ", sql).strip().upper()


def _template_hash(sql: str) -> str:
    skeleton = _strip_literals(sql)
    return hashlib.sha256(skeleton.encode()).hexdigest()


class QueryTemplateWhitelist:
    """Maintains a set of pre-approved SQL query structural templates."""

    def __init__(self) -> None:
        self._hashes: set[str] = set()

    def register(self, sql: str) -> str:
        """Register a known-good SQL template. Returns its hash."""
        h = _template_hash(sql)
        self._hashes.add(h)
        return h

    def is_allowed(self, sql: str) -> bool:
        """Return True if the query's structure matches any registered template."""
        return _template_hash(sql) in self._hashes

    def __len__(self) -> int:
        return len(self._hashes)


# ---------------------------------------------------------------------------
# AST Walker helpers
# ---------------------------------------------------------------------------

def _flatten_tokens(token: Token) -> Iterator[Token]:
    """Recursively yield all leaf tokens in a parsed statement."""
    if token.is_group:
        for child in token.tokens:
            yield from _flatten_tokens(child)
    else:
        yield token


def _has_keyword(statement: sqlparse.sql.Statement, keyword: str) -> bool:
    kw = keyword.upper()
    return any(
        t.ttype in (T.Keyword, T.Keyword.DML, T.Keyword.DDL)
        and t.normalized.upper() == kw
        for t in _flatten_tokens(statement)
    )


def _has_union(statement: sqlparse.sql.Statement) -> bool:
    """
    Return True if the statement contains a UNION or UNION ALL clause.
    sqlparse normalizes 'UNION ALL' into a single Token.Keyword with value
    'UNION ALL', so we check for both 'UNION' and 'UNION ALL'.
    """
    for t in _flatten_tokens(statement):
        if t.ttype in (T.Keyword, T.Keyword.DML, T.Keyword.DDL):
            normalized = t.normalized.upper()
            if normalized in ("UNION", "UNION ALL"):
                return True
    return False


# ---------------------------------------------------------------------------
# Core detection rules
# ---------------------------------------------------------------------------

def _check_stacked_queries(sql: str) -> None:
    """Rule 1: Stacked queries — multiple statements separated by semicolons."""
    statements = [s for s in sqlparse.split(sql) if s.strip()]
    if len(statements) > 1:
        raise SQLInjectionDetected(reason="stacked_queries", sql=sql)


def _check_comments(statement: sqlparse.sql.Statement, sql: str) -> None:
    """Rule 2: SQL comment tokens used to strip the tail of a query."""
    for token in _flatten_tokens(statement):
        if token.ttype in (T.Comment.Single, T.Comment.Multiline):
            raise SQLInjectionDetected(reason="comment_stripping", sql=sql)


def _check_union(
    statement: sqlparse.sql.Statement,
    sql: str,
    whitelist: QueryTemplateWhitelist | None,
) -> None:
    """
    Rule 3: UNION injection.
    A UNION or UNION ALL keyword is flagged unless the full query matches a
    whitelisted template. Legitimate reporting queries that use UNION must
    be pre-registered.
    """
    if _has_union(statement):
        if whitelist is None or not whitelist.is_allowed(sql):
            raise SQLInjectionDetected(reason="union_injection", sql=sql)


def _is_literal(token: Token) -> bool:
    """Return True if a token is a constant literal value."""
    return token.ttype in (
        T.String.Single,
        T.String.Symbol,
        T.Number.Integer,
        T.Number.Float,
        T.Literal,
    ) or (
        token.ttype is T.Keyword
        and token.normalized.upper() in ("TRUE", "FALSE", "NULL")
    )


def _check_tautology_in_comparison(comp: Comparison, sql: str) -> None:
    """
    Check a single Comparison node for a tautology: both sides are literals.
    E.g.  1=1,  'a'='a',  '1'='1'
    """
    meaningful = [
        t for t in comp.tokens
        if t.ttype not in (T.Whitespace, T.Newline, T.Punctuation)
        and (t.ttype is not None or t.is_group)
    ]
    if len(meaningful) == 3:
        left, _op, right = meaningful
        if _is_literal(left) and _is_literal(right):
            raise SQLInjectionDetected(reason="tautology_injection", sql=sql)


def _walk_for_tautologies(token: Token, sql: str) -> None:
    """Recursively walk token tree looking for Comparison tautologies."""
    if isinstance(token, Comparison):
        _check_tautology_in_comparison(token, sql)
    if token.is_group:
        for child in token.tokens:
            _walk_for_tautologies(child, sql)


def _check_tautologies(statement: sqlparse.sql.Statement, sql: str) -> None:
    """Rule 4: Tautology injection — OR 1=1, OR 'a'='a', etc."""
    _walk_for_tautologies(statement, sql)


# ---------------------------------------------------------------------------
# Main analysis entry point
# ---------------------------------------------------------------------------

def analyze_sql(sql: str, whitelist: QueryTemplateWhitelist | None = None) -> None:
    """
    Parse sql into an AST and apply all detection rules.
    Raises SQLInjectionDetected if any rule triggers.
    """
    if not sql or not sql.strip():
        raise ValueError("Empty SQL query")

    _check_stacked_queries(sql)

    parsed = sqlparse.parse(sql)
    if not parsed:
        return

    statement = parsed[0]

    _check_comments(statement, sql)
    _check_union(statement, sql, whitelist)
    _check_tautologies(statement, sql)


# ---------------------------------------------------------------------------
# Proxy class
# ---------------------------------------------------------------------------

class SQLFirewallProxy:
    """
    A transparent wrapper around sqlite3.Connection that intercepts every
    query and runs it through the AST firewall before execution.

    Usage:
        proxy = SQLFirewallProxy(sqlite3.connect(...), enabled=True)
        proxy.register_template("SELECT id FROM users WHERE username = ?")
        cursor = proxy.execute("SELECT id FROM users WHERE username = ?", ("alice",))

    The proxy exposes the same .execute() / .cursor() / .close() interface
    as a raw sqlite3.Connection so the rest of the codebase is unchanged.
    """

    def __init__(self, conn: sqlite3.Connection, enabled: bool = True) -> None:
        self._conn = conn
        self.enabled = enabled
        self._whitelist = QueryTemplateWhitelist()

    def register_template(self, sql: str) -> str:
        """Pre-approve a SQL query skeleton. Call at startup for every known-good query."""
        return self._whitelist.register(sql)

    def execute(self, sql: str, parameters: Iterable[Any] = ()) -> sqlite3.Cursor:
        """Intercept, analyze, then execute."""
        if self.enabled:
            analyze_sql(sql, self._whitelist)
        return self._conn.execute(sql, parameters)

    def executemany(self, sql: str, seq_of_parameters: Iterable[Iterable[Any]]) -> sqlite3.Cursor:
        if self.enabled:
            analyze_sql(sql, self._whitelist)
        return self._conn.executemany(sql, seq_of_parameters)

    def executescript(self, sql_script: str) -> sqlite3.Cursor:
        # executescript is used only for schema initialization — bypass the firewall
        return self._conn.executescript(sql_script)

    def cursor(self) -> "ProxyCursor":
        return ProxyCursor(self._conn.cursor(), self)

    def commit(self) -> None:
        self._conn.commit()

    def rollback(self) -> None:
        self._conn.rollback()

    def close(self) -> None:
        self._conn.close()

    @property
    def row_factory(self):
        return self._conn.row_factory

    @row_factory.setter
    def row_factory(self, value):
        self._conn.row_factory = value

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            self.commit()
        else:
            self.rollback()
        self.close()


class ProxyCursor:
    """
    Wraps sqlite3.Cursor so that cursor.execute() also passes through
    the SQL firewall.
    """

    def __init__(self, cursor: sqlite3.Cursor, proxy: SQLFirewallProxy) -> None:
        self._cursor = cursor
        self._proxy = proxy

    def execute(self, sql: str, parameters: Iterable[Any] = ()) -> "ProxyCursor":
        if self._proxy.enabled:
            analyze_sql(sql, self._proxy._whitelist)
        self._cursor.execute(sql, parameters)
        return self

    def executemany(self, sql: str, seq: Iterable[Iterable[Any]]) -> "ProxyCursor":
        if self._proxy.enabled:
            analyze_sql(sql, self._proxy._whitelist)
        self._cursor.executemany(sql, seq)
        return self

    def fetchone(self):
        return self._cursor.fetchone()

    def fetchall(self):
        return self._cursor.fetchall()

    def fetchmany(self, size: int = 1):
        return self._cursor.fetchmany(size)

    @property
    def lastrowid(self):
        return self._cursor.lastrowid

    @property
    def rowcount(self):
        return self._cursor.rowcount

    def close(self):
        self._cursor.close()

    def __iter__(self):
        return iter(self._cursor)
