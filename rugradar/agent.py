"""One check = clean the input -> resolve the token -> gather facts from every source in parallel
-> rules decide -> explain -> remember -> log the whole path.

run() is a generator: it yields each step as it happens, so the web app and the API can stream
progress instead of showing a spinner. check() simply drains it.
"""
from __future__ import annotations
import json, os, time, uuid
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FutTimeout
from .models import CheckRequest, Report, TokenFacts, Verdict, Money, CHAINS
from .native import ORDERBOOK
from .chains import NAMES, GOPLUS, tier, canon
from . import tools, scoring, explain as ex, parse, memory, store
from .redact import redact, message_flags
from .i18n import t

LOG = os.environ.get("RUGRADAR_LOG", "/tmp/rugradar_traces.jsonl")
SHARE_BASE = os.environ.get("RUGRADAR_URL", "https://rugradar-dun.vercel.app")
RUN_BUDGET_S = float(os.environ.get("RUGRADAR_RUN_BUDGET_S", "20"))  # whole-check time budget
SOURCE_NAMES = {"goplus": "GoPlus contract scan", "honeypot_sim": "Honeypot.is test trade", "dexscreener": "DexScreener market data",
                "creator_wallet": "creator wallet history", "rugcheck": "RugCheck report",
                "jupiter": "Jupiter live sell quote", "native": "the network's own on-chain data"}
STEP_LABELS = {"goplus": "Scanning the contract code", "dexscreener": "Checking the market and pool",
               "honeypot_sim": "Running a test buy and sell", "rugcheck": "Pulling the Solana risk report",
               "fx": "Getting today's naira rate", "creator_wallet": "Checking the creator's wallet history",
               "jupiter": "Getting a live quote to sell it back"}


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
    chain = canon(chain) if chain and chain.lower() != "auto" else got["chain"]
    addr = got["address"]
    if got["is_pair"] and chain:
        tok = tools.dexscreener_pair_token(chain, addr, trace)
        addr = tok or addr
    if not chain:  # no network given: use the one where this token actually trades the most
        pairs = tools.dexscreener_pairs(None, addr, trace)
        if pairs:
            # total pool money per network, whether the token is the base or the quote side. Forks that copied
            # Ethereum's state (PulseChain) carry the same addresses, so a single pool can't decide it.
            per = {}
            for p in pairs:
                per[p["chainId"]] = per.get(p["chainId"], 0) + ((p.get("liquidity") or {}).get("usd") or 0)
            if "pulsechain" in per and "ethereum" in per:
                per.pop("pulsechain")  # same address on Ethereum and its fork: the original is what people mean
            chain = max(per, key=per.get)
        elif got.get("fallback"):
            chain = got["fallback"]
        else:
            raise InputError("We couldn't tell which network this token is on. Pick the network and try again.")
        trace.append({"step": "auto_chain", "chain": chain, "ts": time.time()})
    if chain not in CHAINS:
        raise InputError(f"We don't support that network yet. We check {len(CHAINS)} networks, including Solana, Ethereum, BNB Chain, Base, TON, Sui and Tron.")
    return chain, addr


def build_facts(chain: str, sec: dict | None, pairs: list, now_ms: float, sim=None, creator=None, rc=None, fx=None, previous=None, exit=None) -> TokenFacts:
    sec = sec or {}
    best = max(pairs, key=lambda p: (p.get("liquidity") or {}).get("usd") or 0) if pairs else None
    # token age = its OLDEST pool. A pump.fun token that just graduated gets a fresh PumpSwap pool, but it isn't new.
    born = min((p["pairCreatedAt"] for p in pairs if p.get("pairCreatedAt")), default=None)
    age = max(0.0, (now_ms - born) / 3_600_000) if born else None
    meta = sec.get("metadata") or {}
    bt = (best or {}).get("baseToken", {})
    hc = str(sec.get("holder_count", ""))
    return TokenFacts(
        chain=chain,
        name=sec.get("token_name") or meta.get("name") or bt.get("name"),
        symbol=sec.get("token_symbol") or meta.get("symbol") or bt.get("symbol"),
        holder_count=int(hc) if hc.isdigit() else None,
        liquidity_usd=(((best or {}).get("liquidity") or {}).get("usd") or None) if chain in ORDERBOOK else ((best or {}).get("liquidity") or {}).get("usd"),
        pair_age_hours=age, buy_tax=_f(sec.get("buy_tax")), sell_tax=_f(sec.get("sell_tax")),
        security=sec, has_security_data=bool(sec), has_market_data=bool(best),
        sim=sim, creator=creator, rugcheck=rc, ngn_per_usd=fx, previous=previous,
        pool_tokens=_f(((best or {}).get("liquidity") or {}).get("base")),
        supply=(_f((best or {}).get("fdv")) / _f(best.get("priceUsd"))) if best and _f(best.get("fdv")) and _f(best.get("priceUsd")) else None,
        txns_h24=((best or {}).get("txns") or {}).get("h24"),
        price_change_h24=_f(((best or {}).get("priceChange") or {}).get("h24")),
        contract_scannable=chain in GOPLUS or bool(sec),
        pool_addresses=[p["pairAddress"] for p in pairs if p.get("pairAddress")] + list((rc or {}).get("pools") or []),
        exit=exit,
    )


def money_line(verdict: Verdict, f: TokenFacts, findings, amount: int, lang: str) -> Money | None:
    if verdict == Verdict.unknown:
        return None
    stuck = any(x.code in ("HONEYPOT", "HOLDERS_STUCK", "SOL_NON_TRANSFERABLE", "CANNOT_SELL_ALL") for x in findings)
    if stuck or not f.has_market_data:
        return Money(amount_ngn=amount, get_back_ngn=0, note=t("MONEY_ZERO", lang, a=f"{amount:,}"))
    ex = f.exit or {}
    if ex.get("ratio"):
        back = amount * ex["ratio"]
        back = int(round(back, -2)) if back >= 1000 else int(back)
        if verdict == Verdict.low or ex["ratio"] <= 0.95:
            return Money(amount_ngn=amount, get_back_ngn=back, note=t("MONEY_LIVE", lang, a=f"{amount:,}", b=f"{back:,}"))
        return None
    taxes = (f.buy_tax or 0) + (f.sell_tax or 0)
    if verdict != Verdict.low and taxes < 0.05:
        return None  # the risk here isn't tax, so a "you'd get ~all of it back" line would mislead
    back = amount * (1 - (f.buy_tax or 0)) * (1 - (f.sell_tax or 0)) * 0.994  # ~0.3% swap fee each way
    back = int(round(back, -2)) if back >= 1000 else int(back)
    return Money(amount_ngn=amount, get_back_ngn=back, note=t("MONEY", lang, a=f"{amount:,}", b=f"{back:,}"))


def _slim_pairs(pairs):
    keep = ("chainId", "liquidity", "pairCreatedAt", "baseToken", "pairAddress", "dexId", "txns", "priceChange", "fdv", "priceUsd")
    top = sorted(pairs or [], key=lambda p: -((p.get("liquidity") or {}).get("usd") or 0))[:5]
    return [{k: p.get(k) for k in keep} for p in top]


def run(req: CheckRequest, *, sec=None, pairs=None, sim=None, creator=None, rc=None, fx=None, now_ms=None,
        offline=False, trace=None, trace_id=None, flags=None, removed=None, use_memory=None, previous=None, exit=None):
    """Yields {"type": "step"|"report", ...}. Tool outputs can be injected (evals replay data with offline=True)."""
    trace_id, t0, trace = trace_id or uuid.uuid4().hex[:12], time.time(), trace if trace is not None else []
    now_ms = now_ms or time.time() * 1000
    use_memory = (not offline) if use_memory is None else use_memory
    errors, timed_out = [], []
    if not offline:
        memory.start_run(trace_id, req.model_dump())

    def step(name, fn, *a):
        """Each source: resume from checkpoint if this run already got it, else call and checkpoint."""
        if not offline:
            found, val = memory.load_step(trace_id, name)
            if found:
                trace.append({"tool": name, "resumed": True, "ts": time.time()})
                return val
        try:
            val = fn(*a)
        except tools.ToolError as e:
            trace.append({"tool": name, "error": str(e)[:120], "ts": time.time()})
            errors.append(name)
            return None
        if not offline:
            memory.save_step(trace_id, name, val)
        return val

    got = {"sec": sec, "pairs": pairs, "sim": sim, "rc": rc, "fx": fx}
    if not offline:
        plan = {"sec": ("goplus", tools.goplus_security, req.chain, req.address, trace) if sec is None else None,
                "pairs": ("dexscreener", tools.dexscreener_pairs, req.chain, req.address, trace) if pairs is None else None,
                "sim": ("honeypot_sim", tools.honeypot_sim, req.chain, req.address, trace) if sim is None and req.chain != "solana" else None,
                "rc": ("rugcheck", tools.rugcheck, req.address, trace) if rc is None and req.chain == "solana" else None,
                "fx": ("fx", tools.ngn_per_usd, trace) if fx is None else None}
        plan = {k: v for k, v in plan.items() if v}
        for k, v in plan.items():
            yield {"type": "step", "tool": v[0], "label": STEP_LABELS[v[0]], "status": "started"}
        pool = ThreadPoolExecutor(max_workers=5)  # independent sources run in parallel
        futs = {pool.submit(step, v[0], *v[1:]): k for k, v in plan.items()}
        try:
            for fut in as_completed(futs, timeout=max(1.0, RUN_BUDGET_S - (time.time() - t0))):
                k = futs[fut]
                got[k] = fut.result()
                yield {"type": "step", "tool": plan[k][0], "label": STEP_LABELS[plan[k][0]],
                       "status": "done" if got[k] else "no data", "ms": int((time.time() - t0) * 1000)}
        except FutTimeout:
            for fut, k in futs.items():
                if not fut.done():
                    timed_out.append(plan[k][0])
                    trace.append({"tool": plan[k][0], "timeout": True, "ts": time.time()})
                    yield {"type": "step", "tool": plan[k][0], "label": STEP_LABELS[plan[k][0]], "status": "timed out"}
        pool.shutdown(wait=False, cancel_futures=True)
        got["pairs"] = got["pairs"] or []
        if creator is None and got["sec"] and time.time() - t0 < RUN_BUDGET_S:  # depends on the scan (needs the creator address)
            yield {"type": "step", "tool": "creator_wallet", "label": STEP_LABELS["creator_wallet"], "status": "started"}
            creator = step("creator_wallet", tools.creator_check, req.chain, got["sec"].get("creator_address"), trace)
            yield {"type": "step", "tool": "creator_wallet", "label": STEP_LABELS["creator_wallet"], "status": "done" if creator else "no data"}
        if exit is None and req.chain == "solana" and got["fx"] and got["pairs"] and time.time() - t0 < RUN_BUDGET_S:
            yield {"type": "step", "tool": "jupiter", "label": STEP_LABELS["jupiter"], "status": "started"}
            exit = step("jupiter", tools.jupiter_roundtrip, req.address, req.amount_ngn / got["fx"], trace)
            yield {"type": "step", "tool": "jupiter", "label": STEP_LABELS["jupiter"], "status": "done" if exit else "no data"}

    prev = previous if previous is not None else (memory.last(req.chain, req.address) if use_memory else None)
    facts = build_facts(req.chain, got["sec"], got["pairs"] or [], now_ms, got["sim"], creator, got["rc"], got["fx"], prev,
                        dict(exit, ngn=req.amount_ngn) if exit else None)
    verdict, score, findings, facts = scoring.assess(facts, req.address, req.lang)
    if timed_out and verdict == Verdict.low:  # never call it low risk on half the evidence
        verdict = Verdict.unknown if not facts.has_security_data else Verdict.caution
    trace.append({"step": "rules", "verdict": verdict.value, "score": score, "codes": [f.code for f in findings], "ts": time.time()})
    yield {"type": "step", "tool": "rules", "label": "Applying the safety rules", "status": "done"}
    summary, by, cost = ex.explain(verdict, findings, trace, req.lang, trace_id)
    money = money_line(verdict, facts, findings, req.amount_ngn, req.lang)

    used = [SOURCE_NAMES[s["tool"]] for s in trace if s.get("tool") in SOURCE_NAMES and (s.get("found") or s.get("cached") or s.get("resumed")) and "error" not in s]
    if offline:
        used = [n for k, n in SOURCE_NAMES.items() if {"goplus": got["sec"] if req.chain in GOPLUS else None,
                                                      "native": got["sec"] if req.chain not in GOPLUS else None, "honeypot_sim": got["sim"], "dexscreener": got["pairs"],
                                                      "creator_wallet": creator, "rugcheck": got["rc"], "jupiter": exit}[k]]
    tried = list(dict.fromkeys(SOURCE_NAMES[s["tool"]] for s in trace if s.get("tool") in SOURCE_NAMES and not s.get("skipped")))
    coverage = None if offline else {"read": len(set(used)), "missing": [n for n in tried if n not in used]}
    label = {"LOW_RISK": "Low risk", "CAUTION": "Be careful", "HIGH_RISK": "HIGH RISK", "UNKNOWN": "Couldn't check"}[verdict.value]
    top = findings[0].plain if findings and findings[0].points else ""
    share_url = f"{SHARE_BASE}/r/{trace_id}" if not offline and trace_id else None
    share = (f"RugRadar check: {label} ({score}/100). {top} See the full check: {share_url}" if share_url else
             f"RugRadar check: {label} ({score}/100). {top} Check any token before you buy: {SHARE_BASE}").replace("  ", " ")
    explain_step = next((s for s in reversed(trace) if s.get("step") == "explain"), {})
    rep = Report(chain=req.chain, chain_name=NAMES.get(req.chain), coverage_tier=tier(req.chain), address=req.address, name=(facts.name or "")[:40] or None, symbol=(facts.symbol or "")[:15] or None,
                 verdict=verdict, score=score, findings=findings, summary=summary, money=money,
                 sources=list(dict.fromkeys(used)), lang=req.lang, share_text=share, share_url=share_url, explained_by=by, trace_id=trace_id,
                 cost_usd=round(cost, 6), latency_ms=int((time.time() - t0) * 1000),
                 message_flags=flags or [], removed=removed or [],
                 memory=memory.summarize(prev, verdict.value, score, facts.liquidity_usd),
                 route=explain_step.get("route", "template"), prompt_version=explain_step.get("prompt"), timed_out=timed_out,
                 coverage=coverage, checked_at=datetime.fromtimestamp(t0, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))

    if not offline:
        if use_memory and verdict != Verdict.unknown:
            memory.remember(req.chain, req.address, verdict.value, score, facts.liquidity_usd, facts.holder_count)
        memory.finish_run(trace_id, {"req": req.model_dump(), "verdict": verdict.value, "score": score,
                                     "codes": [f.code for f in findings], "summary": summary, "explained_by": by,
                                     "fixture": {"chain": req.chain, "address": req.address, "sec": got["sec"], "pairs": _slim_pairs(got["pairs"]),
                                                 "sim": got["sim"], "rc": got["rc"], "creator": creator, "fx": got["fx"], "exit": exit, "recorded_at_ms": now_ms}})
        memory.save_report(trace_id, rep.model_dump(mode="json"))
        record_stats(rep, explain_step)
        try:
            with open(LOG, "a") as fh:
                fh.write(json.dumps({"trace_id": trace_id, "ts": t0, "req": req.model_dump(), "trace": trace, "errors": errors,
                                     "timed_out": timed_out, "verdict": verdict.value, "cost": cost, "ms": rep.latency_ms}) + "\n")
        except OSError:
            pass
    yield {"type": "report", "report": rep.model_dump()}


def record_stats(rep: Report, explain_step: dict):
    """Cost per task (not per token), latency, verdict mix and A/B arm, for /api/stats."""
    store.safe(store.push, "stats:runs", {"ts": time.time(), "verdict": rep.verdict.value, "cost": rep.cost_usd, "ms": rep.latency_ms,
                                          "route": rep.route, "arm": explain_step.get("arm"), "model": explain_step.get("model"),
                                          "rejected": explain_step.get("rejected"), "trace_id": rep.trace_id}, cap=2000)


def check(req: CheckRequest, **kw) -> Report:
    rep = None
    for ev in run(req, **kw):
        if ev["type"] == "report":
            rep = ev["report"]
    return Report(**rep)


HEX64_CHAINS = {"aptos", "movement", "sui", "starknet"}


def prepare(text: str, chain: str | None = None) -> tuple[str, list[dict], list[str]]:
    """Strip private data from what the user pasted and flag the pitch itself, before anything else sees it."""
    clean, removed = redact(text, keep_bare_hex=canon(chain) in HEX64_CHAINS if chain else False)
    return clean, message_flags(text), removed


def run_text(text: str, chain: str | None = None, lang: str = "en", amount_ngn: int = 50_000):
    clean, flags, removed = prepare(text, chain)
    flags = message_flags(text, lang)
    trace: list = []
    try:
        c, a = resolve(clean, chain, trace)
    except InputError:
        if any("key" in str(r).lower() for r in (removed or [])):
            raise InputError("That looked like a private key, so we deleted it without reading it. Never paste a private key anywhere. "
                             "If it was a token address on Aptos, Sui, Movement or Starknet, pick that network first, or paste its DexScreener link.")
        raise
    yield from run(CheckRequest(chain=c, address=a, lang=lang, amount_ngn=amount_ngn), trace=trace, flags=flags, removed=removed)


def check_text(text: str, chain: str | None = None, lang: str = "en", amount_ngn: int = 50_000) -> Report:
    rep = None
    for ev in run_text(text, chain, lang, amount_ngn):
        if ev["type"] == "report":
            rep = ev["report"]
    return Report(**rep)


def resume(trace_id: str) -> Report:
    """Finish a run that crashed or timed out. Sources already answered come from checkpoints, not the network."""
    r = memory.get_run(trace_id)
    if not r:
        raise InputError("We don't have a run with that id (runs are kept for 7 days).")
    return check(CheckRequest(**r["req"]), trace_id=trace_id, use_memory=False)
