import os
from pathlib import Path
from collections import defaultdict
from contextlib import asynccontextmanager
import json, os, re, statistics, time
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, StreamingResponse, Response
from pydantic import BaseModel, Field, ValidationError
from .models import Report, Verdict
from .agent import check_text, run_text, resume, InputError
from .redact import redact
from . import store, memory
from .page import render as render_page
from . import telegram
from .agent import SHARE_BASE
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


def _limit(request: Request, n: int = 20, scope: str = "check"):
    """n requests per minute per IP, counted in the shared store so it holds across serverless instances."""
    ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip() or (request.client.host if request.client else "?")
    now = time.time()
    count = store.safe(store.hit, f"rl:{scope}:{ip}:{int(now // 60)}", 90)
    if count is None:  # store unreachable: per-instance fallback
        _hits[ip] = [t for t in _hits[ip] if now - t < 60]
        _hits[ip].append(now)
        count = len(_hits[ip])
    if count > n:
        raise HTTPException(429, "Too many checks. Try again in a minute.")


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
    _limit(request, 10, "resume")
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
    _limit(request, 30, "feedback")
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


_TID = re.compile(r"^[a-f0-9]{8,32}$")


def _saved(trace_id: str) -> dict:
    rep = memory.get_report(trace_id) if _TID.match(trace_id) else None
    if not rep:
        raise HTTPException(404, "No saved check with that id. Saved checks last 30 days.")
    return rep


@app.get("/r/{trace_id}.png")
def report_card(trace_id: str):
    from .card import png
    return Response(png(_saved(trace_id)), media_type="image/png", headers={"Cache-Control": "public, max-age=86400"})


@app.get("/r/{trace_id}", response_class=HTMLResponse)
def report_page(trace_id: str):
    """What a shared link opens: the saved check, with a preview card for WhatsApp and X."""
    try:
        return render_page(_saved(trace_id), SHARE_BASE, telegram.watch_link(trace_id))
    except HTTPException:
        return HTMLResponse(f'<!doctype html><meta name="viewport" content="width=device-width,initial-scale=1"><body style="font-family:system-ui;padding:24px">'
                            f'<h2>This check has expired or never existed.</h2><p><a href="{SHARE_BASE}/">Check a token now</a></p>', status_code=404)


@app.post("/api/telegram")
async def telegram_webhook(request: Request):
    if not telegram.TOKEN or request.headers.get("x-telegram-bot-api-secret-token") != telegram.secret():
        raise HTTPException(403, "forbidden")
    try:
        telegram.handle(await request.json())
    except Exception:
        pass  # always 200 so Telegram doesn't retry a bad update forever
    return {"ok": True}


@app.get("/api/telegram/setup")
def telegram_setup(request: Request):
    """Idempotent: points the bot's webhook at this deployment. Harmless if anyone calls it."""
    _limit(request, 3, "tgsetup")
    return telegram.setup(SHARE_BASE)


@app.get("/api/watch/run")
def watch_run():
    """Called every ~15 minutes by a scheduled job. Needs no secret: a shared lock means at most one sweep per
    10 minutes however often it is hit, and a sweep only re-checks tokens people asked to watch."""
    if not telegram.TOKEN:
        return {"ran": False, "why": "telegram is not configured"}
    return telegram.sweep()


@app.get("/api/bench/run")
def bench_run():
    """Hourly: check a few brand-new tokens and score the ones checked 24h ago. One run per 50 minutes."""
    from . import bench
    from .agent import check_text
    if store.safe(store.hit, "bench:lock", 3000, default=1) != 1:
        return {"ran": False, "why": "ran in the last 50 minutes"}
    resolved = bench.resolve()
    added = bench.sample(lambda c, a: check_text(a, c, "en", 50_000).model_dump(mode="json"))
    return {"ran": True, "sampled": added, "resolved": resolved}


@app.get("/api/bench")
def bench_stats():
    """Public track record: how often RugRadar's launch-time verdict predicted a rug (see rugradar/bench.py)."""
    from . import bench
    return bench.stats()


@app.get("/api/report/{trace_id}")
def api_report(trace_id: str):
    return _saved(trace_id)


@app.get("/api/health")
def health():
    # which optional features are switched on (never the keys themselves)
    return {"ok": True, "version": app.version, "store": store.backend(),
            "ai_summaries": bool(os.environ.get("GEMINI_API_KEY") or os.environ.get("FALLBACK_API_KEY")),
            "telegram": bool(os.environ.get("TELEGRAM_BOT_TOKEN")), "telegram_bot": telegram.bot_username()}
