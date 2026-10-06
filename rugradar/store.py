"""Durable key-value store for memory, checkpoints, feedback and stats.

Two backends, same interface:
  - Upstash Redis over REST, when UPSTASH_REDIS_REST_URL/TOKEN (or Vercel's KV_REST_API_URL/TOKEN) are set.
    This is what makes memory and feedback survive serverless cold starts.
  - SQLite file otherwise (local dev, tests, MCP over stdio).
"""
from __future__ import annotations
import json, os, sqlite3, threading, time
import httpx

_URL = os.environ.get("UPSTASH_REDIS_REST_URL") or os.environ.get("KV_REST_API_URL")
_TOKEN = os.environ.get("UPSTASH_REDIS_REST_TOKEN") or os.environ.get("KV_REST_API_TOKEN")
_DB = os.environ.get("RUGRADAR_STORE", "/tmp/rugradar_store.sqlite")
_lock = threading.Lock()


def backend() -> str:
    return "upstash" if _URL and _TOKEN else "sqlite"


def _redis(*cmd):
    r = httpx.post(_URL, json=[str(c) for c in cmd], headers={"Authorization": f"Bearer {_TOKEN}"}, timeout=5)
    r.raise_for_status()
    return r.json().get("result")


def _conn():
    c = sqlite3.connect(_DB)
    c.execute("CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT, exp REAL)")
    c.execute("CREATE TABLE IF NOT EXISTS lst (k TEXT, v TEXT, ts REAL)")
    return c


def get(key: str):
    if backend() == "upstash":
        v = _redis("GET", key)
        return json.loads(v) if v else None
    with _lock, _conn() as c:
        row = c.execute("SELECT v, exp FROM kv WHERE k=?", (key,)).fetchone()
    if not row or (row[1] and row[1] < time.time()):
        return None
    return json.loads(row[0])


def put(key: str, value, ttl: int | None = None):
    v = json.dumps(value)
    if backend() == "upstash":
        return _redis("SET", key, v, "EX", ttl) if ttl else _redis("SET", key, v)
    with _lock, _conn() as c:
        c.execute("REPLACE INTO kv VALUES (?,?,?)", (key, v, time.time() + ttl if ttl else None))


def push(key: str, value, cap: int = 1000):
    """Append to a capped list (newest first)."""
    v = json.dumps(value)
    if backend() == "upstash":
        _redis("LPUSH", key, v)
        return _redis("LTRIM", key, 0, cap - 1)
    with _lock, _conn() as c:
        c.execute("INSERT INTO lst VALUES (?,?,?)", (key, v, time.time()))
        c.execute("DELETE FROM lst WHERE k=? AND rowid NOT IN (SELECT rowid FROM lst WHERE k=? ORDER BY rowid DESC LIMIT ?)",
                  (key, key, cap))


def items(key: str, n: int = 100) -> list:
    if backend() == "upstash":
        return [json.loads(x) for x in (_redis("LRANGE", key, 0, n - 1) or [])]
    with _lock, _conn() as c:
        rows = c.execute("SELECT v FROM lst WHERE k=? ORDER BY rowid DESC LIMIT ?", (key, n)).fetchall()
    return [json.loads(r[0]) for r in rows]


def incr(key: str, by: int = 1) -> int:
    if backend() == "upstash":
        return int(_redis("INCRBY", key, by))
    cur = get(key) or 0
    put(key, cur + by)
    return cur + by


def hit(key: str, window_s: int) -> int:
    """Count one hit in a fixed window shared by every server instance (INCR + EXPIRE)."""
    if backend() == "upstash":
        n = int(_redis("INCR", key))
        if n == 1:
            _redis("EXPIRE", key, window_s)
        return n
    with _lock, _conn() as c:
        row = c.execute("SELECT v, exp FROM kv WHERE k=?", (key,)).fetchone()
        n = 1 if not row or (row[1] and row[1] < time.time()) else json.loads(row[0]) + 1
        exp = time.time() + window_s if n == 1 else row[1]
        c.execute("REPLACE INTO kv VALUES (?,?,?)", (key, json.dumps(n), exp))
    return n


def safe(fn, *a, default=None, **k):
    """Storage must never break a check: a store outage degrades to 'no memory', not an error."""
    try:
        return fn(*a, **k)
    except Exception:
        return default
