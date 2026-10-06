"""Tiny SQLite TTL cache so repeat checks don't re-hit free APIs."""
import json, sqlite3, time, os, threading

_DB = os.environ.get("RUGRADAR_CACHE", "/tmp/rugradar_cache.sqlite")
_lock = threading.Lock()


def _conn():
    c = sqlite3.connect(_DB)
    c.execute("CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT, exp REAL)")
    return c


def get(key: str):
    with _lock, _conn() as c:
        row = c.execute("SELECT v, exp FROM kv WHERE k=?", (key,)).fetchone()
    if not row or row[1] < time.time():
        return None
    return json.loads(row[0])


def put(key: str, value, ttl: int = 600):
    with _lock, _conn() as c:
        c.execute("REPLACE INTO kv VALUES (?,?,?)", (key, json.dumps(value), time.time() + ttl))
