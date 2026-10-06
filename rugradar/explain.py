"""Turns findings into a short plain-English summary. The verdict is already decided by rules.

Routing (cheapest path that can do the job):
  template   clear-cut cases, Pidgin, no key            -> free, instant (most traffic)
  small      mixed signals (CAUTION, 3+ findings)       -> gemini-2.5-flash-lite
  reasoning  sources contradict each other               -> gemini-2.5-flash with a capped thinking budget
Fallbacks:   primary provider fails -> any OpenAI-compatible fallback (Groq by default) -> template.
A/B:         RUGRADAR_AB="model:percent" sends that slice of small-route traffic to a challenger model.
Budgets:     max output tokens, max USD per call, request timeout.
Safety:      prompts are versioned files; only rule findings go in (no pasted text, no token names);
             a sensitive-data check runs on the final prompt; output is schema- and guardrail-checked.
"""
from __future__ import annotations
import hashlib, json, os, time
from pathlib import Path
import httpx
from .models import Finding, Verdict
from .i18n import t
from .redact import contains_sensitive

PROMPTS = Path(__file__).resolve().parent.parent / "prompts"
ROUTES = {"small": ("gemini-2.5-flash-lite", "explain_v1"), "reasoning": ("gemini-2.5-flash", "explain_v2_hard")}
# USD per 1k tokens (input, output). Thinking tokens bill as output.
PRICE_PER_1K = {"gemini-2.5-flash-lite": (0.0001, 0.0004), "gemini-2.5-flash": (0.0003, 0.0025),
                "llama-3.1-8b-instant": (0.00005, 0.00008)}
MAX_OUTPUT_TOKENS = {"small": 200, "reasoning": 900}
MAX_COST_USD = {"small": 0.002, "reasoning": 0.006}
TIMEOUT_S = 10
HARD_CODES = {"SOURCES_DISAGREE"}
BANNED = ("safe to buy", "guaranteed", "no risk", "risk-free", "can't lose", "definitely safe")


def lead(verdict: Verdict, lang: str = "en") -> str:
    return t(f"LEAD_{verdict.value}", lang)


def template(verdict: Verdict, findings: list[Finding], lang: str = "en") -> str:
    top = [f.plain for f in findings if f.points > 0][:3]
    return " ".join([lead(verdict, lang), *top]).strip()


def route(verdict: Verdict, findings: list[Finding], lang: str) -> str:
    if lang != "en" or not (os.environ.get("GEMINI_API_KEY") or os.environ.get("FALLBACK_API_KEY")):
        return "template"
    if any(f.code in HARD_CODES for f in findings) and verdict != Verdict.unknown:
        return "reasoning"
    if verdict == Verdict.caution and len([f for f in findings if f.points]) >= 3:
        return "small"
    return "template"


def needs_model(verdict: Verdict, findings: list[Finding]) -> bool:  # kept for older callers
    return route(verdict, findings, "en") != "template"


def ab_arm(trace_id: str, rt: str) -> tuple[str, str]:
    """Deterministic split by trace id, so a run is always in the same arm."""
    model = ROUTES[rt][0]
    spec = os.environ.get("RUGRADAR_AB", "")
    if rt == "small" and ":" in spec:
        challenger, pct = spec.rsplit(":", 1)
        if int(hashlib.sha256(trace_id.encode()).hexdigest(), 16) % 100 < int(pct):
            return challenger, "B"
    return model, "A"


def build_prompt(rt: str, verdict: Verdict, findings: list[Finding]) -> tuple[str, str]:
    version = ROUTES[rt][1]
    facts = [{"code": f.code, "severity": f.severity.value, "meaning": f.plain} for f in findings]
    return (PROMPTS / f"{version}.txt").read_text().format(verdict=verdict.value, facts=json.dumps(facts)), version


def _cost(model, pin_tokens, pout_tokens):
    pin, pout = PRICE_PER_1K.get(model, (0.001, 0.002))
    return pin_tokens / 1000 * pin + pout_tokens / 1000 * pout


def _gemini(model: str, prompt: str, rt: str):
    cfg = {"maxOutputTokens": MAX_OUTPUT_TOKENS[rt], "responseMimeType": "application/json"}
    if rt == "reasoning":
        cfg["thinkingConfig"] = {"thinkingBudget": 512}
    elif "2.5" in model:
        cfg["thinkingConfig"] = {"thinkingBudget": 0}
    r = httpx.post(f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
                   params={"key": os.environ["GEMINI_API_KEY"]}, timeout=TIMEOUT_S,
                   json={"contents": [{"parts": [{"text": prompt}]}], "generationConfig": cfg})
    r.raise_for_status()
    body = r.json()
    text = "".join(p.get("text", "") for p in body["candidates"][0]["content"]["parts"] if not p.get("thought"))
    u = body.get("usageMetadata", {})
    out_toks = u.get("candidatesTokenCount", 0) + u.get("thoughtsTokenCount", 0)
    return text, _cost(model, u.get("promptTokenCount", 0), out_toks)


def _fallback(prompt: str, rt: str):
    base = os.environ.get("FALLBACK_BASE_URL", "https://api.groq.com/openai/v1")
    model = os.environ.get("FALLBACK_MODEL", "llama-3.1-8b-instant")
    r = httpx.post(f"{base}/chat/completions", timeout=TIMEOUT_S,
                   headers={"Authorization": f"Bearer {os.environ['FALLBACK_API_KEY']}"},
                   json={"model": model, "messages": [{"role": "user", "content": prompt}],
                         "max_tokens": MAX_OUTPUT_TOKENS[rt], "response_format": {"type": "json_object"}})
    r.raise_for_status()
    body = r.json()
    u = body.get("usage", {})
    return body["choices"][0]["message"]["content"], _cost(model, u.get("prompt_tokens", 0), u.get("completion_tokens", 0)), model


def _validate(text: str, cost: float, rt: str) -> str | None:
    try:
        summary = json.loads(text)["summary"].strip()
    except (ValueError, KeyError, TypeError, AttributeError):
        return None
    if cost > MAX_COST_USD[rt] or not (20 <= len(summary) <= 600) or any(b in summary.lower() for b in BANNED):
        return None
    return summary


def explain(verdict: Verdict, findings: list[Finding], trace: list, lang: str = "en", trace_id: str = "") -> tuple[str, str, float]:
    rt = route(verdict, findings, lang)
    if rt == "template":
        trace.append({"step": "explain", "route": "template", "ts": time.time()})
        return template(verdict, findings, lang), "template", 0.0

    prompt, version = build_prompt(rt, verdict, findings)
    if contains_sensitive(prompt):  # last line of defence: nothing personal or attacker-chosen reaches a model
        trace.append({"step": "explain", "route": rt, "blocked": "sensitive", "ts": time.time()})
        return template(verdict, findings, lang), "template(blocked)", 0.0

    model, arm = ab_arm(trace_id or "x", rt)
    attempts = []
    if os.environ.get("GEMINI_API_KEY"):
        attempts.append(("primary", model))
    if os.environ.get("FALLBACK_API_KEY"):
        attempts.append(("fallback", os.environ.get("FALLBACK_MODEL", "llama-3.1-8b-instant")))
    spent = 0.0
    for which, m in attempts:
        t0 = time.time()
        try:
            if which == "primary":
                text, cost = _gemini(m, prompt, rt)
            else:
                text, cost, m = _fallback(prompt, rt)
            spent += cost
            summary = _validate(text, cost, rt)
            trace.append({"step": "explain", "route": rt, "model": m, "provider": which, "arm": arm, "prompt": version,
                          "ms": int((time.time() - t0) * 1000), "cost": cost, "rejected": summary is None, "ts": time.time()})
            if summary:
                return f"{lead(verdict)} {summary}", f"{m}@{version}", spent
        except Exception as e:  # provider down, timeout, bad JSON: try the next one
            trace.append({"step": "explain", "route": rt, "model": m, "provider": which, "arm": arm,
                          "error": type(e).__name__, "ms": int((time.time() - t0) * 1000), "ts": time.time()})
    return template(verdict, findings, lang), "template(fallback)", spent
