"""One check = resolve input -> gather facts from every source in parallel -> rules decide -> explain -> log the path."""
from __future__ import annotations
import json, os, time, uuid
from concurrent.futures import ThreadPoolExecutor
from .models import CheckRequest, Report, TokenFacts, Verdict, Money, CHAINS
from . import tools, scoring, explain as ex, parse
from .i18n import t

LOG = os.environ.get("RUGRADAR_LOG", "/tmp/rugradar_traces.jsonl")
SHARE_BASE = os.environ.get("RUGRADAR_URL", "https://github.com/Darkjay123/rugradar")
SOURCE_NAMES = {"goplus": "GoPlus contract scan", "honeypot_sim": "Honeypot.is test trade", "dexscreener": "DexScreener market data",
                "creator_wallet": "creator wallet history", "rugcheck": "RugCheck report"}


class InputError(ValueError):
    pass


def _f(v):
    try:
        return float(v) if v not in (None, "") else None
    except (TypeError, ValueError):
        return None


def resolve(text: str, chain: str | None, trace: list) -> tuple[str, str]:
    """Turn whatever the user pasted into (chain, token address)."""
    got = parse.extract(text)
    if not got["address"]:
        raise InputError("Couldn't find a token address or link in that. Paste the contract address, a DexScreener or pump.fun link, or the message you were sent.")
    chain = (chain or "").lower() if chain and chain.lower() != "auto" else got["chain"]
    addr = got["address"]
    if got["is_pair"] and chain:
        tok = tools.dexscreener_pair_token(chain, addr, trace)
        addr = tok or addr
    if not chain:  # EVM address with no chain: pick the chain where it actually trades the most
        pairs = tools.dexscreener_pairs(None, addr, trace)
        if not pairs:
            raise InputError("We couldn't tell which network this token is on. Pick the chain and try again.")
        best = max(pairs, key=lambda p: (p.get("liquidity") or {}).get("usd") or 0)
        chain = {"ethereum": "ethereum", "bsc": "bsc", "base": "base", "polygon": "polygon", "arbitrum": "arbitrum", "solana": "solana"}[best["chainId"]]
        trace.append({"step": "auto_chain", "chain": chain})
    if chain not in CHAINS:
        raise InputError(f"We don't support that network yet. Try one of: {', '.join(CHAINS)}.")
    return chain, addr


def build_facts(chain: str, sec: dict | None, pairs: list, now_ms: float, sim=None, creator=None, rc=None, fx=None) -> TokenFacts:
    sec = sec or {}
    best = max(pairs, key=lambda p: (p.get("liquidity") or {}).get("usd") or 0) if pairs else None
    age = max(0.0, (now_ms - best["pairCreatedAt"]) / 3_600_000) if best and best.get("pairCreatedAt") else None
    meta = sec.get("metadata") or {}
    bt = (best or {}).get("baseToken", {})
    hc = str(sec.get("holder_count", ""))
    return TokenFacts(
        chain=chain,
        name=sec.get("token_name") or meta.get("name") or bt.get("name"),
        symbol=sec.get("token_symbol") or meta.get("symbol") or bt.get("symbol"),
        holder_count=int(hc) if hc.isdigit() else None,
        liquidity_usd=((best or {}).get("liquidity") or {}).get("usd"),
        pair_age_hours=age, buy_tax=_f(sec.get("buy_tax")), sell_tax=_f(sec.get("sell_tax")),
        security=sec, has_security_data=bool(sec), has_market_data=bool(best),
        sim=sim, creator=creator, rugcheck=rc, ngn_per_usd=fx,
    )


def money_line(verdict: Verdict, f: TokenFacts, findings, amount: int, lang: str) -> Money | None:
    if verdict == Verdict.unknown:
        return None
    stuck = any(x.code in ("HONEYPOT", "HOLDERS_STUCK", "SOL_NON_TRANSFERABLE", "CANNOT_SELL_ALL") for x in findings)
    if stuck or not f.has_market_data:
        return Money(amount_ngn=amount, get_back_ngn=0, note=t("MONEY_ZERO", lang, a=f"{amount:,}"))
    taxes = (f.buy_tax or 0) + (f.sell_tax or 0)
    if verdict != Verdict.low and taxes < 0.05:
        return None  # the risk here isn't tax, so a "you'd get ~all of it back" line would mislead
    back = amount * (1 - (f.buy_tax or 0)) * (1 - (f.sell_tax or 0)) * 0.994  # ~0.3% swap fee each way
    back = int(round(back, -2)) if back >= 1000 else int(back)
    return Money(amount_ngn=amount, get_back_ngn=back, note=t("MONEY", lang, a=f"{amount:,}", b=f"{back:,}"))


def check(req: CheckRequest, *, sec=None, pairs=None, sim=None, creator=None, rc=None, fx=None,
          now_ms=None, offline=False, trace=None, trace_id=None) -> Report:
    """Tool outputs can be injected (evals replay recorded or synthetic data with offline=True)."""
    trace_id, t0, trace = trace_id or uuid.uuid4().hex[:12], time.time(), trace if trace is not None else []
    now_ms = now_ms or time.time() * 1000
    errors = []

    def safe(name, fn, *a):
        try:
            return fn(*a)
        except tools.ToolError as e:
            trace.append({"tool": name, "error": str(e)[:120]})
            errors.append(name)
            return None

    if not offline:
        with ThreadPoolExecutor(max_workers=5) as pool:  # independent sources run in parallel
            jobs = {
                "sec": pool.submit(safe, "goplus", tools.goplus_security, req.chain, req.address, trace) if sec is None else None,
                "pairs": pool.submit(safe, "dexscreener", tools.dexscreener_pairs, req.chain, req.address, trace) if pairs is None else None,
                "sim": pool.submit(safe, "honeypot_sim", tools.honeypot_sim, req.chain, req.address, trace)
                       if sim is None and req.chain != "solana" else None,
                "rc": pool.submit(safe, "rugcheck", tools.rugcheck, req.address, trace) if rc is None and req.chain == "solana" else None,
                "fx": pool.submit(safe, "fx", tools.ngn_per_usd, trace) if fx is None else None,
            }
            res = {k: (v.result() if v else None) for k, v in jobs.items()}
        sec = sec if sec is not None else res["sec"]
        pairs = pairs if pairs is not None else (res["pairs"] or [])
        sim = sim if sim is not None else res["sim"]
        rc = rc if rc is not None else res["rc"]
        fx = fx if fx is not None else res["fx"]
        if creator is None and sec:  # depends on the scan (needs the creator address)
            creator = safe("creator_wallet", tools.creator_check, req.chain, sec.get("creator_address"), trace)

    facts = build_facts(req.chain, sec, pairs or [], now_ms, sim, creator, rc, fx)
    verdict, score, findings, facts = scoring.assess(facts, req.address, req.lang)
    trace.append({"step": "rules", "verdict": verdict.value, "score": score, "codes": [f.code for f in findings]})
    summary, by, cost = ex.explain(verdict, findings, trace, req.lang)
    money = money_line(verdict, facts, findings, req.amount_ngn, req.lang)
    used = [SOURCE_NAMES[s["tool"]] for s in trace if s.get("tool") in SOURCE_NAMES and (s.get("found") or s.get("cached")) and "error" not in s]
    if offline:
        used = [n for k, n in SOURCE_NAMES.items() if {"goplus": sec, "honeypot_sim": sim, "dexscreener": pairs,
                                                      "creator_wallet": creator, "rugcheck": rc}[k]]
    label = {"LOW_RISK": "Low risk", "CAUTION": "Be careful", "HIGH_RISK": "HIGH RISK", "UNKNOWN": "Couldn't check"}[verdict.value]
    share = f"RugRadar check: {label} ({score}/100). {findings[0].plain if findings and findings[0].points else ''} Check any token before you buy: {SHARE_BASE}".replace("  ", " ")
    rep = Report(chain=req.chain, address=req.address, name=(facts.name or "")[:40] or None, symbol=(facts.symbol or "")[:15] or None,
                 verdict=verdict, score=score, findings=findings, summary=summary, money=money,
                 sources=list(dict.fromkeys(used)), lang=req.lang, share_text=share, explained_by=by, trace_id=trace_id,
                 cost_usd=round(cost, 6), latency_ms=int((time.time() - t0) * 1000))
    try:
        with open(LOG, "a") as fh:
            fh.write(json.dumps({"trace_id": trace_id, "req": req.model_dump(), "trace": trace, "errors": errors,
                                 "verdict": verdict.value, "cost": cost, "ms": rep.latency_ms}) + "\n")
    except OSError:
        pass
    return rep


def check_text(text: str, chain: str | None = None, lang: str = "en", amount_ngn: int = 50_000) -> Report:
    trace: list = []
    c, a = resolve(text, chain, trace)
    return check(CheckRequest(chain=c, address=a, lang=lang, amount_ngn=amount_ngn), trace=trace)
