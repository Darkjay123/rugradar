"""Turns findings into a short plain-English summary.

Routing: no key or a clean token -> free template (most requests).
Mixed signals -> small model, with a hard token + cost budget.
Token names/symbols are attacker-controlled, so they are never put in the prompt.
The model output must pass a schema check, and it may not contradict the rule verdict.
"""
from __future__ import annotations
import json, os, time
import httpx
from .models import Finding, Verdict

PRICE_PER_1K = {"gemini-2.0-flash": (0.0001, 0.0004)}  # input, output USD per 1k tokens
MAX_OUTPUT_TOKENS = 160
MAX_COST_USD = 0.002

LEAD = {
    Verdict.high: "High risk. We would not put money into this token.",
    Verdict.caution: "Be careful. Nothing here proves it's a scam, but there are warning signs.",
    Verdict.low: "No major red flags found. That is not a guarantee, so only use money you can afford to lose.",
    Verdict.unknown: "We couldn't check this token.",
}


def template(verdict: Verdict, findings: list[Finding]) -> str:
    top = [f.plain for f in findings if f.points > 0][:3]
    return " ".join([LEAD[verdict], *top]).strip()


def needs_model(verdict: Verdict, findings: list[Finding]) -> bool:
    return verdict == Verdict.caution and len([f for f in findings if f.points]) >= 3


def explain(verdict: Verdict, findings: list[Finding], trace: list) -> tuple[str, str, float]:
    key = os.environ.get("GEMINI_API_KEY")
    if not key or not needs_model(verdict, findings):
        trace.append({"step": "explain", "route": "template"})
        return template(verdict, findings), "template", 0.0

    model = "gemini-2.0-flash"
    facts = [{"code": f.code, "severity": f.severity.value, "meaning": f.plain} for f in findings]
    prompt = (
        "You explain crypto token risk to a first-time buyer in Nigeria. Use simple English, no jargon, "
        f"max 3 sentences. The verdict is fixed: {verdict.value}. Do not change it or soften it. "
        "Only use these facts:\n" + json.dumps(facts) +
        '\nReply as JSON: {"summary": "..."}'
    )
    t0 = time.time()
    try:
        r = httpx.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
            params={"key": key}, timeout=10,
            json={"contents": [{"parts": [{"text": prompt}]}],
                  "generationConfig": {"maxOutputTokens": MAX_OUTPUT_TOKENS, "responseMimeType": "application/json"}},
        )
        r.raise_for_status()
        body = r.json()
        text = body["candidates"][0]["content"]["parts"][0]["text"]
        summary = json.loads(text)["summary"].strip()
        usage = body.get("usageMetadata", {})
        pin, pout = PRICE_PER_1K[model]
        cost = usage.get("promptTokenCount", 0) / 1000 * pin + usage.get("candidatesTokenCount", 0) / 1000 * pout
        # guardrails: budget, length, and no verdict flip
        bad = cost > MAX_COST_USD or not (20 <= len(summary) <= 600) or \
            any(w in summary.lower() for w in ("safe to buy", "guaranteed", "no risk"))
        trace.append({"step": "explain", "route": model, "ms": int((time.time() - t0) * 1000), "cost": cost, "rejected": bad})
        if bad:
            return template(verdict, findings), "template(fallback)", cost
        return f"{LEAD[verdict]} {summary}", model, cost
    except Exception as e:  # degrade gracefully, never fail the check because the model did
        trace.append({"step": "explain", "route": model, "error": type(e).__name__})
        return template(verdict, findings), "template(fallback)", 0.0
