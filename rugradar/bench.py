"""Forward benchmark: does RugRadar's verdict at launch predict what actually happens?

Every hour a few brand-new tokens are checked the moment they appear (RugRadar verdict + pool money + price,
frozen in time). 24 hours later each one is looked at again:
  rugged  = pool money pulled (down 90%+ from launch) or RugCheck marks it rugged, or every pool is gone
  dumped  = pool still there but the price fell 90%+
  alive   = neither
Then: of the tokens that rugged or dumped, how many did RugRadar flag at launch (catch rate), and of the
tokens it called HIGH RISK, how many really went bad (precision). Nobody picks the tokens and nothing is
re-labelled after the fact, so the number is honest, including when it's bad.
"""
from __future__ import annotations
import time
import httpx
from . import store

INDEX = "bench:index"
WAIT_S = 24 * 3600
_C = httpx.Client(timeout=10.0, headers={"User-Agent": "rugradar-bench/1.0"})


def _key(chain, addr):
    return f"bench:{chain}:{addr}"


def _best(pairs):
    pairs = [p for p in pairs or [] if (p.get("liquidity") or {}).get("usd") is not None]
    return max(pairs, key=lambda p: p["liquidity"]["usd"]) if pairs else None


def fresh_tokens(limit: int = 12) -> list[tuple[str, str]]:
    """Newest launches from two independent feeds: RugCheck's new Solana mints and DexScreener's new token pages."""
    out = []
    try:
        for t in _C.get("https://api.rugcheck.xyz/v1/stats/new_tokens").json() or []:
            if t.get("mint"):
                out.append(("solana", t["mint"]))
    except Exception:
        pass
    try:
        for t in _C.get("https://api.dexscreener.com/token-profiles/latest/v1").json() or []:
            if t.get("tokenAddress") and t.get("chainId"):
                out.append((t["chainId"], t["tokenAddress"]))
    except Exception:
        pass
    seen, uniq = set(), []
    for c, a in out:
        if (c, a) not in seen:
            seen.add((c, a))
            uniq.append((c, a))
    return uniq[:limit]


def market_now(chain: str, addrs: list[str]) -> dict:
    """{address: best pair or None} from DexScreener, 30 addresses per call."""
    res = {}
    for i in range(0, len(addrs), 30):
        chunk = addrs[i:i + 30]
        try:
            pairs = _C.get(f"https://api.dexscreener.com/tokens/v1/{chain}/{','.join(chunk)}").json() or []
        except Exception:
            continue
        by = {}
        for p in pairs:
            by.setdefault((p.get("baseToken") or {}).get("address"), []).append(p)
        for a in chunk:
            res[a] = _best(by.get(a) or [])
    return res


def sample(check, n: int = 3, now: float | None = None) -> int:
    """Check up to n new tokens that have a live pool and haven't been benchmarked yet."""
    now = now or time.time()
    added = 0
    for chain, addr in fresh_tokens():
        if added >= n:
            break
        if store.safe(store.get, _key(chain, addr)):
            continue
        p = market_now(chain, [addr]).get(addr)
        if not p or (p.get("liquidity") or {}).get("usd", 0) < 1_000:
            continue                                      # no real pool yet: nothing to rug, skip
        try:
            rep = check(chain, addr)
        except Exception:
            continue
        if not rep or rep.get("verdict") == "UNKNOWN":
            continue
        rec = {"chain": chain, "addr": addr, "ts": now, "verdict": rep["verdict"], "score": rep["score"],
               "codes": sorted({f["code"] for f in rep.get("findings", []) if f.get("points")}),
               "liq0": p["liquidity"]["usd"], "price0": float(p.get("priceUsd") or 0), "outcome": None,
               "url": rep.get("share_url")}
        store.safe(store.put, _key(chain, addr), rec, ttl=60 * 24 * 3600)
        store.safe(store.push, INDEX, _key(chain, addr), cap=5000)
        added += 1
    return added


def outcome(rec: dict, pair: dict | None, rugcheck_rugged: bool | None = None) -> str:
    if rugcheck_rugged or pair is None:
        return "rugged"
    liq, price = (pair.get("liquidity") or {}).get("usd") or 0, float(pair.get("priceUsd") or 0)
    if rec["liq0"] >= 1_000 and liq < rec["liq0"] * 0.10:
        return "rugged"
    if rec["price0"] and price < rec["price0"] * 0.10:
        return "dumped"
    return "alive"


def resolve(now: float | None = None, limit: int = 60) -> int:
    now = now or time.time()
    keys = store.safe(store.items, INDEX, 5000, default=[]) or []
    due = []
    for k in keys:
        r = store.safe(store.get, k)
        if r and r.get("outcome") is None and now - r["ts"] >= WAIT_S:
            due.append((k, r))
        if len(due) >= limit:
            break
    by_chain = {}
    for k, r in due:
        by_chain.setdefault(r["chain"], []).append((k, r))
    done = 0
    for chain, rows in by_chain.items():
        mk = market_now(chain, [r["addr"] for _, r in rows])
        for k, r in rows:
            rugged = None
            if chain == "solana":
                try:
                    rugged = bool(_C.get(f"https://api.rugcheck.xyz/v1/tokens/{r['addr']}/report/summary").json().get("rugged"))
                except Exception:
                    rugged = None
            r["outcome"], r["resolved_ts"] = outcome(r, mk.get(r["addr"]), rugged), now
            store.safe(store.put, k, r, ttl=60 * 24 * 3600)
            done += 1
    return done


def stats() -> dict:
    keys = store.safe(store.items, INDEX, 5000, default=[]) or []
    recs = [r for r in (store.safe(store.get, k) for k in keys) if r]
    res = [r for r in recs if r.get("outcome")]
    bad = [r for r in res if r["outcome"] in ("rugged", "dumped")]
    flagged = lambda r: r["verdict"] in ("HIGH_RISK", "CAUTION")
    high = [r for r in res if r["verdict"] == "HIGH_RISK"]
    alive = [r for r in res if r["outcome"] == "alive"]
    pct = lambda a, b: round(100 * a / b, 1) if b else None
    return {"tokens_checked_at_launch": len(recs), "waiting_24h": len(recs) - len(res), "resolved": len(res),
            "went_bad": len(bad), "rugged": sum(r["outcome"] == "rugged" for r in res),
            "caught_at_launch_pct": pct(sum(flagged(r) for r in bad), len(bad)),
            "high_risk_that_went_bad_pct": pct(sum(r["outcome"] != "alive" for r in high), len(high)),
            "healthy_called_high_risk_pct": pct(sum(r["verdict"] == "HIGH_RISK" for r in alive), len(alive)),
            "method": "New tokens from RugCheck and DexScreener feeds, checked within minutes of listing, re-checked "
                      "24h later. Rugged = pool money down 90%+ or gone, or RugCheck marks it rugged; dumped = price down 90%+."}
