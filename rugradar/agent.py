"""One check = gather facts with tools, decide with rules, explain, log the whole path."""
from __future__ import annotations
import json, os, time, uuid
from .models import CheckRequest, Report, TokenFacts, Verdict
from . import tools, scoring, explain as ex

LOG = os.environ.get("RUGRADAR_LOG", "/tmp/rugradar_traces.jsonl")
TIME_BUDGET_S = 20


def _f(v):
    try:
        return float(v) if v not in (None, "") else None
    except (TypeError, ValueError):
        return None


def build_facts(sec: dict | None, pairs: list, now_ms: float, sim: dict | None = None) -> TokenFacts:
    sec = sec or {}
    best = max(pairs, key=lambda p: (p.get("liquidity") or {}).get("usd") or 0) if pairs else None
    age = None
    if best and best.get("pairCreatedAt"):
        age = max(0.0, (now_ms - best["pairCreatedAt"]) / 3_600_000)
    return TokenFacts(
        name=(sec.get("token_name") or (best or {}).get("baseToken", {}).get("name")),
        symbol=(sec.get("token_symbol") or (best or {}).get("baseToken", {}).get("symbol")),
        holder_count=int(sec["holder_count"]) if str(sec.get("holder_count", "")).isdigit() else None,
        liquidity_usd=((best or {}).get("liquidity") or {}).get("usd"),
        pair_age_hours=age,
        buy_tax=_f(sec.get("buy_tax")),
        sell_tax=_f(sec.get("sell_tax")),
        security=sec,
        has_security_data=bool(sec),
        has_market_data=bool(best),
        sim=sim,
    )


def check(req: CheckRequest, *, sec=None, pairs=None, sim=None, now_ms=None, offline=False) -> Report:
    """sec/pairs can be injected (evals replay recorded tool output)."""
    trace_id, t0, trace = uuid.uuid4().hex[:12], time.time(), []
    now_ms = now_ms or time.time() * 1000
    if sec is None:
        try:
            sec = tools.goplus_security(req.chain, req.address, trace)
        except tools.ToolError as e:
            trace.append({"tool": "goplus", "error": str(e)[:120]})
            sec = None
    if pairs is None and time.time() - t0 < TIME_BUDGET_S:
        try:
            pairs = tools.dexscreener_pairs(req.chain, req.address, trace)
        except tools.ToolError as e:
            trace.append({"tool": "dexscreener", "error": str(e)[:120]})
            pairs = []
    if sim is None and not offline and time.time() - t0 < TIME_BUDGET_S:
        try:
            sim = tools.honeypot_sim(req.chain, req.address, trace)
        except tools.ToolError as e:
            trace.append({"tool": "honeypot_sim", "error": str(e)[:120]})
    facts = build_facts(sec, pairs or [], now_ms, sim)
    verdict, score, findings = scoring.assess(facts)
    trace.append({"step": "rules", "verdict": verdict.value, "score": score, "codes": [f.code for f in findings]})
    summary, by, cost = ex.explain(verdict, findings, trace)
    rep = Report(chain=req.chain, address=req.address, verdict=verdict, score=score, findings=findings,
                 summary=summary, explained_by=by, trace_id=trace_id, cost_usd=round(cost, 6),
                 latency_ms=int((time.time() - t0) * 1000))
    try:
        with open(LOG, "a") as fh:
            fh.write(json.dumps({"trace_id": trace_id, "req": req.model_dump(), "trace": trace,
                                 "verdict": verdict.value, "cost": cost, "ms": rep.latency_ms}) + "\n")
    except OSError:
        pass
    return rep
