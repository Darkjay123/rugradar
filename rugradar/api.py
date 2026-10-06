from pathlib import Path
from collections import defaultdict
from contextlib import asynccontextmanager
import json, os, statistics, time
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel, Field, ValidationError
from .models import Report, Verdict
from .agent import check_text, run_text, resume, InputError
from .redact import redact
from . import store, memory
from .mcp_server import mcp

mcp_app = mcp.streamable_http_app()


@asynccontextmanager
async def lifespan(app):
    async with mcp.session_manager.run():
        yield

app = FastAPI(title="RugRadar", version="0.3.0", lifespan=lifespan)
app.mount("/mcp", mcp_app)
_hits: dict[str, list[float]] = defaultdict(list)
WEB = Path(__file__).resolve().parent.parent / "web" / "index.html"


def _limit(request: Request, n: int = 20):
    ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip() or (request.client.host if request.client else "?")
    now = time.time()
    _hits[ip] = [t for t in _hits[ip] if now - t < 60]
    if len(_hits[ip]) >= n:
        raise HTTPException(429, "Too many checks. Try again in a minute.")
    _hits[ip].append(now)


def _bad(e):
    if isinstance(e, ValidationError):
        return e.errors()[0]["msg"].replace("Value error, ", "")
    return str(e)


@app.get("/", response_class=HTMLResponse)
def home():
    return WEB.read_text()


@app.get("/api/check", response_model=Report)
def api_check(request: Request, q: str = "", address: str = "", chain: str = "auto", lang: str = "en", amount: int = 50_000):
    _limit(request)
    try:
        return check_text((q or address)[:2000], chain, lang, max(100, min(amount, 1_000_000_000)))
    except (InputError, ValidationError) as e:
        raise HTTPException(422, _bad(e))


@app.get("/api/stream")
def api_stream(request: Request, q: str = "", chain: str = "auto", lang: str = "en", amount: int = 50_000):
    """Server-sent events: each source as it answers, then the report. No staring at a spinner."""
    _limit(request)

    def gen():
        try:
            for ev in run_text(q[:2000], chain, lang, max(100, min(amount, 1_000_000_000))):
                yield f"data: {json.dumps(ev)}\n\n"
        except (InputError, ValidationError) as e:
            yield f"data: {json.dumps({'type': 'error', 'detail': _bad(e)})}\n\n"
        except Exception:
            yield f"data: {json.dumps({'type': 'error', 'detail': 'Something went wrong on our side. Try again.'})}\n\n"
    return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.post("/api/resume/{trace_id}", response_model=Report)
def api_resume(request: Request, trace_id: str):
    _limit(request, 10)
    try:
        return resume(trace_id[:32])
    except InputError as e:
        raise HTTPException(404, str(e))


class Feedback(BaseModel):
    trace_id: str = Field(max_length=32)
    vote: str = Field(pattern="^(up|down)$")
    expected: Verdict | None = None
    note: str = Field(default="", max_length=280)


@app.post("/api/feedback")
def api_feedback(request: Request, fb: Feedback):
    """Every thumbs-down is stored with the exact inputs of that run, ready to become an eval case."""
    _limit(request, 30)
    run = memory.get_run(fb.trace_id)
    if not run:
        raise HTTPException(404, "Unknown check id.")
    note, _ = redact(fb.note)
    store.safe(store.push, "feedback", {"ts": time.time(), "trace_id": fb.trace_id, "vote": fb.vote,
                                        "expected": fb.expected.value if fb.expected else None, "note": note,
                                        "got": run.get("verdict"), "codes": run.get("codes"), "fixture": run.get("fixture"),
                                        "summary": run.get("summary"), "explained_by": run.get("explained_by")}, cap=5000)
    store.safe(store.incr, f"fb:{fb.vote}")
    return {"ok": True}


@app.get("/api/feedback/export")
def api_feedback_export(request: Request, n: int = 500):
    """For evals/promote_feedback.py. Needs the ADMIN_TOKEN header so feedback isn't public."""
    tok = os.environ.get("ADMIN_TOKEN")
    if not tok or request.headers.get("authorization") != f"Bearer {tok}":
        raise HTTPException(401, "admin only")
    return store.safe(store.items, "feedback", min(n, 5000), default=[])


@app.get("/api/stats")
def api_stats():
    """Published numbers: cost per check (not per token), latency, verdict mix, thumbs, and A/B arms."""
    runs = store.safe(store.items, "stats:runs", 2000, default=[]) or []
    by_arm = defaultdict(list)
    for r in runs:
        if r.get("arm"):
            by_arm[f"{r['arm']}:{r.get('model')}"].append(r)
    up, down = store.safe(store.get, "fb:up", default=0) or 0, store.safe(store.get, "fb:down", default=0) or 0
    return {
        "checks": len(runs), "store": store.backend(),
        "cost_per_check_usd": round(statistics.mean([r["cost"] for r in runs]), 6) if runs else 0,
        "p50_ms": int(statistics.median([r["ms"] for r in runs])) if runs else 0,
        "verdicts": {v.value: sum(r["verdict"] == v.value for r in runs) for v in Verdict},
        "routes": {k: sum(r.get("route") == k for r in runs) for k in ("template", "small", "reasoning")},
        "thumbs": {"up": up, "down": down, "approval": round(up / (up + down), 3) if up + down else None},
        "ab": {k: {"n": len(v), "cost_per_check_usd": round(statistics.mean([x["cost"] for x in v]), 6),
                   "p50_ms": int(statistics.median([x["ms"] for x in v])),
                   "rejected_rate": round(sum(bool(x.get("rejected")) for x in v) / len(v), 3)} for k, v in by_arm.items()},
    }


@app.get("/api/health")
def health():
    return {"ok": True, "version": app.version, "store": store.backend()}
