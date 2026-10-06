"""Agent memory + resumable checkpoints.

memory:      every token remembers its last few checks, so the agent can say what changed
             (and a pool drained since last time becomes a LIQUIDITY_PULLED rule).
checkpoints: each source result is saved under the run's trace_id the moment it lands.
             If a run crashes or times out, /api/resume/{trace_id} finishes it without re-calling
             the sources that already answered. The saved inputs double as a replay fixture,
             which is how a thumbs-down becomes an eval case.
"""
from __future__ import annotations
import time
from . import store

RUN_TTL = 7 * 24 * 3600


def _tok(chain: str, address: str) -> str:
    return f"mem:{chain}:{address}"


def last(chain: str, address: str) -> dict | None:
    hist = store.safe(store.items, _tok(chain, address), 1, default=[]) or []
    if not hist:
        return None
    h = dict(hist[0])
    h["hours_ago"] = max(0.0, (time.time() - h["ts"]) / 3600)
    return h


def remember(chain: str, address: str, verdict: str, score: int, liquidity_usd, holder_count):
    store.safe(store.push, _tok(chain, address), {"ts": time.time(), "verdict": verdict, "score": score,
                                                  "liquidity_usd": liquidity_usd, "holder_count": holder_count}, cap=20)


def summarize(prev: dict | None, verdict: str, score: int, liquidity_usd) -> dict | None:
    if not prev:
        return None
    out = {"last_checked_hours_ago": round(prev["hours_ago"], 1), "last_verdict": prev["verdict"], "last_score": prev["score"]}
    if prev.get("liquidity_usd") and liquidity_usd is not None:
        out["liquidity_change_pct"] = round((liquidity_usd - prev["liquidity_usd"]) / prev["liquidity_usd"] * 100, 1)
    out["changed"] = prev["verdict"] != verdict or abs(prev["score"] - score) >= 10
    return out


# --- checkpoints
def start_run(trace_id: str, req: dict):
    store.safe(store.put, f"run:{trace_id}", {"req": req, "status": "running", "ts": time.time()}, ttl=RUN_TTL)


def finish_run(trace_id: str, summary: dict):
    store.safe(store.put, f"run:{trace_id}", {**summary, "status": "done", "ts": time.time()}, ttl=RUN_TTL)


def get_run(trace_id: str) -> dict | None:
    return store.safe(store.get, f"run:{trace_id}")


def save_step(trace_id: str, step: str, value):
    store.safe(store.put, f"cp:{trace_id}:{step}", {"v": value}, ttl=RUN_TTL)


def load_step(trace_id: str, step: str):
    """Returns (found, value)."""
    hit = store.safe(store.get, f"cp:{trace_id}:{step}")
    return (True, hit["v"]) if hit is not None else (False, None)
