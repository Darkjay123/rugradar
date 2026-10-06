"""Data tools. Every call has a timeout, retries with backoff, a cache, and a recorded trace step.
Sources (each one the 'best at' tool from the competitor research):
  GoPlus token security (EVM + Solana)  - static contract scan, 30+ chains
  honeypot.is                           - live buy/sell simulation + what happened to recent holders
  GoPlus address security               - the deployer wallet's history (ChainAware-style behaviour check)
  RugCheck                              - Solana-native risk report + LP lock
  DexScreener                           - market depth, pool age, chain auto-detect
  open.er-api.com                       - USD to NGN, so pool sizes read in naira
"""
from __future__ import annotations
import time, random
import httpx
from . import cache
from .models import CHAINS

DEX_CHAIN = {"ethereum": "ethereum", "bsc": "bsc", "base": "base", "polygon": "polygon", "arbitrum": "arbitrum", "solana": "solana"}
HP_CHAINS = {"ethereum": "1", "bsc": "56", "base": "8453"}
UA = {"User-Agent": "rugradar/0.2 (+https://github.com/Darkjay123/rugradar)"}


class ToolError(Exception):
    pass


def _get_json(url: str, params: dict | None = None, tries: int = 3, timeout: float = 8.0, ok404: bool = False) -> dict | None:
    last = None
    for attempt in range(tries):
        try:
            r = httpx.get(url, params=params, timeout=timeout, headers=UA)
            if ok404 and r.status_code in (400, 404):
                return None
            if r.status_code == 429 or r.status_code >= 500:
                raise ToolError(f"upstream {r.status_code}")
            r.raise_for_status()
            return r.json()
        except (httpx.HTTPError, ToolError, ValueError) as e:
            last = e
            time.sleep((2 ** attempt) * 0.4 + random.random() * 0.2)  # backoff with jitter, not a blind loop
    raise ToolError(f"{url.split('?')[0]} failed after {tries} tries: {last}")


def _cached(name: str, key: str, ttl: int, trace: list, fn):
    hit = cache.get(key)
    if hit is not None:
        trace.append({"tool": name, "cached": True, "ms": 0})
        return hit or None
    t0 = time.time()
    val = fn()
    cache.put(key, val if val is not None else {}, ttl=ttl)
    trace.append({"tool": name, "cached": False, "ms": int((time.time() - t0) * 1000), "found": bool(val)})
    return val


def goplus_security(chain: str, address: str, trace: list) -> dict | None:
    def fetch():
        if chain == "solana":
            data = _get_json("https://api.gopluslabs.io/api/v1/solana/token_security", {"contract_addresses": address})
        else:
            data = _get_json(f"https://api.gopluslabs.io/api/v1/token_security/{CHAINS[chain]}", {"contract_addresses": address})
        res = (data or {}).get("result") or {}
        return res.get(address) or res.get(address.lower()) or None
    return _cached("goplus", f"gp:{chain}:{address}", 900, trace, fetch)


def creator_check(chain: str, creator: str | None, trace: list) -> dict | None:
    if not creator or chain == "solana" or not creator.startswith("0x"):
        return None

    def fetch():
        data = _get_json(f"https://api.gopluslabs.io/api/v1/address_security/{creator}", {"chain_id": CHAINS[chain]})
        return (data or {}).get("result") or None
    return _cached("creator_wallet", f"cr:{chain}:{creator.lower()}", 3600, trace, fetch)


def dexscreener_pairs(chain: str | None, address: str, trace: list) -> list:
    """chain=None returns pairs on every supported chain (used for auto-detect)."""
    def fetch():
        data = _get_json(f"https://api.dexscreener.com/latest/dex/tokens/{address}")
        pairs = [p for p in ((data or {}).get("pairs") or []) if p.get("chainId") in DEX_CHAIN.values()]
        return pairs
    pairs = _cached("dexscreener", f"dx:{address}", 120, trace, fetch) or []
    return [p for p in pairs if chain is None or p.get("chainId") == DEX_CHAIN[chain]]


def dexscreener_pair_token(chain: str, pair: str, trace: list) -> str | None:
    """A DexScreener link points at a pool; resolve it to the token being traded."""
    def fetch():
        data = _get_json(f"https://api.dexscreener.com/latest/dex/pairs/{DEX_CHAIN[chain]}/{pair}")
        ps = (data or {}).get("pairs") or ([data["pair"]] if (data or {}).get("pair") else [])
        return {"token": ps[0]["baseToken"]["address"]} if ps else None
    out = _cached("dexscreener_pair", f"dxp:{chain}:{pair}", 3600, trace, fetch)
    return (out or {}).get("token")


def honeypot_sim(chain: str, address: str, trace: list) -> dict | None:
    if chain not in HP_CHAINS:
        trace.append({"tool": "honeypot_sim", "skipped": "chain"})
        return None

    def fetch():
        data = _get_json("https://api.honeypot.is/v2/IsHoneypot", {"address": address, "chainID": HP_CHAINS[chain]},
                         timeout=12, ok404=True)
        if not data or data.get("simulationSuccess") is None:
            return None
        sim, ha = data.get("simulationResult") or {}, data.get("holderAnalysis") or {}
        return {"ok": bool(data.get("simulationSuccess")),
                "is_honeypot": bool((data.get("honeypotResult") or {}).get("isHoneypot")),
                "buy_tax": sim.get("buyTax"), "sell_tax": sim.get("sellTax"),
                "holders_tested": int(ha.get("holders") or 0), "holders_failed": int(ha.get("failed") or 0),
                "holders_siphoned": int(ha.get("siphoned") or 0)}
    return _cached("honeypot_sim", f"hp:{chain}:{address}", 600, trace, fetch)


def rugcheck(address: str, trace: list) -> dict | None:
    def fetch():
        data = _get_json(f"https://api.rugcheck.xyz/v1/tokens/{address}/report/summary", ok404=True)
        if not data:
            return None
        return {"risks": [{"name": r.get("name"), "level": r.get("level"), "description": r.get("description")}
                          for r in (data.get("risks") or [])],
                "score_normalised": data.get("score_normalised"), "lp_locked_pct": data.get("lpLockedPct")}
    return _cached("rugcheck", f"rc:{address}", 600, trace, fetch)


def ngn_per_usd(trace: list) -> float | None:
    def fetch():
        data = _get_json("https://open.er-api.com/v6/latest/USD", tries=2)
        rate = ((data or {}).get("rates") or {}).get("NGN")
        return {"rate": rate} if rate else None
    out = _cached("fx", "fx:usd:ngn", 6 * 3600, trace, fetch)
    return (out or {}).get("rate")
