"""Data tools. Every call has a timeout, retries with backoff, a cache, and a recorded trace step."""
from __future__ import annotations
import time, random
import httpx
from . import cache
from .models import CHAINS

DEX_CHAIN = {"ethereum": "ethereum", "bsc": "bsc", "base": "base", "polygon": "polygon", "arbitrum": "arbitrum"}


class ToolError(Exception):
    pass


def _get_json(url: str, params: dict | None, tries: int = 3, timeout: float = 8.0) -> dict:
    last = None
    for attempt in range(tries):
        try:
            r = httpx.get(url, params=params, timeout=timeout, headers={"User-Agent": "rugradar/0.1"})
            if r.status_code == 429 or r.status_code >= 500:
                raise ToolError(f"upstream {r.status_code}")
            r.raise_for_status()
            return r.json()
        except (httpx.HTTPError, ToolError, ValueError) as e:
            last = e
            # exponential backoff with jitter, not a blind loop
            time.sleep((2 ** attempt) * 0.4 + random.random() * 0.2)
    raise ToolError(f"{url} failed after {tries} tries: {last}")


def goplus_security(chain: str, address: str, trace: list) -> dict | None:
    key = f"gp:{chain}:{address}"
    hit = cache.get(key)
    t0 = time.time()
    if hit is not None:
        trace.append({"tool": "goplus", "cached": True, "ms": 0})
        return hit or None
    data = _get_json(f"https://api.gopluslabs.io/api/v1/token_security/{CHAINS[chain]}",
                     {"contract_addresses": address})
    result = (data.get("result") or {}).get(address) or (data.get("result") or {}).get(address.lower())
    cache.put(key, result or {}, ttl=900)
    trace.append({"tool": "goplus", "cached": False, "ms": int((time.time() - t0) * 1000), "found": bool(result)})
    return result


def dexscreener_pairs(chain: str, address: str, trace: list) -> list:
    key = f"dx:{chain}:{address}"
    hit = cache.get(key)
    t0 = time.time()
    if hit is not None:
        trace.append({"tool": "dexscreener", "cached": True, "ms": 0})
        return hit
    data = _get_json(f"https://api.dexscreener.com/latest/dex/tokens/{address}", None)
    pairs = [p for p in (data.get("pairs") or []) if p.get("chainId") == DEX_CHAIN[chain]]
    cache.put(key, pairs, ttl=120)  # market data goes stale fast
    trace.append({"tool": "dexscreener", "cached": False, "ms": int((time.time() - t0) * 1000), "pairs": len(pairs)})
    return pairs
