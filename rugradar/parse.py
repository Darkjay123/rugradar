"""Newcomers don't have 'a contract address'. They have a link, a forwarded Telegram/WhatsApp 'gem'
message, or an explorer page. Pull the token out of whatever they paste."""
from __future__ import annotations
import re

EVM = re.compile(r"0x[a-fA-F0-9]{40}")
SOL = re.compile(r"(?<![1-9A-HJ-NP-Za-km-z])[1-9A-HJ-NP-Za-km-z]{32,44}(?![1-9A-HJ-NP-Za-km-z])")

EXPLORERS = {
    "etherscan.io": "ethereum", "bscscan.com": "bsc", "basescan.org": "base",
    "polygonscan.com": "polygon", "arbiscan.io": "arbitrum", "solscan.io": "solana",
}
DEX_CHAINS = {"ethereum": "ethereum", "bsc": "bsc", "base": "base", "polygon": "polygon", "arbitrum": "arbitrum", "solana": "solana"}


def extract(text: str) -> dict:
    """Returns {"address", "chain" (or None), "is_pair" (DexScreener links point at pools, not tokens)}."""
    t = (text or "").strip()
    m = re.search(r"dexscreener\.com/([a-z]+)/([1-9A-HJ-NP-Za-km-z]{32,44}|0x[a-fA-F0-9]{40})", t)
    if m and m.group(1) in DEX_CHAINS:
        return {"address": m.group(2), "chain": DEX_CHAINS[m.group(1)], "is_pair": True}
    m = re.search(r"pump\.fun/(?:coin/)?([1-9A-HJ-NP-Za-km-z]{32,44})", t)
    if m:
        return {"address": m.group(1), "chain": "solana", "is_pair": False}
    for host, chain in EXPLORERS.items():
        m = re.search(re.escape(host) + r"/(?:token|address|account)/([1-9A-HJ-NP-Za-km-z]{32,44}|0x[a-fA-F0-9]{40})", t)
        if m:
            return {"address": m.group(1), "chain": chain, "is_pair": False}
    m = EVM.search(t)
    if m:
        return {"address": m.group(0), "chain": None, "is_pair": False}
    sols = [s for s in SOL.findall(t) if not s.isdigit()]
    if sols:
        sols.sort(key=lambda s: (not s.endswith("pump"), -len(s)))  # pump.fun mints end in 'pump'
        return {"address": sols[0], "chain": "solana", "is_pair": False}
    return {"address": None, "chain": None, "is_pair": False}
