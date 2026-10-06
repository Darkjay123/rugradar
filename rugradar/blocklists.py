"""Community scam lists (refreshed weekly by scripts/refresh_blocklists.py). Loaded lazily: only when needed."""
from __future__ import annotations
import gzip, re
from functools import lru_cache
from pathlib import Path

D = Path(__file__).parent / "data"
URLISH = re.compile(r"(?:https?://)?(?:www\.)?((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})(?=[/:?#\s\"'<>)\]]|$)", re.I)
SAFE_TLDS = {"near", "tg"}  # NEAR account names look like domains (token.rhealab.near): not links


@lru_cache(maxsize=None)
def _load(name: str) -> frozenset:
    p = D / f"{name}.txt.gz"
    if not p.exists():
        return frozenset()
    with gzip.open(p, "rt") as f:
        return frozenset(x for x in f.read().split("\n") if x)


def domains_in(text: str) -> list[str]:
    out = []
    for m in URLISH.finditer(text or ""):
        d = m.group(1).lower().strip(".")
        if d.rsplit(".", 1)[-1] in SAFE_TLDS or d not in out:
            if d.rsplit(".", 1)[-1] not in SAFE_TLDS:
                out.append(d)
    return out[:20]


def phishing_domains(text: str) -> list[str]:
    """Domains in the text that a public phishing list has flagged (the domain itself or any parent of it)."""
    ds = domains_in(text)
    if not ds:
        return []
    deny, allow = _load("phish_domains"), _load("allow_domains")
    hits = []
    for d in ds:
        parts = d.split(".")
        cands = [".".join(parts[i:]) for i in range(len(parts) - 1)]
        if any(c in allow for c in cands):
            continue
        if any(c in deny for c in cands):
            hits.append(d)
    return hits


def scam_address(addr: str | None) -> bool:
    return bool(addr) and addr.lower() in _load("scam_addresses")


def sui_scam_coin(coin_type: str) -> bool:
    return coin_type in _load("sui_blocklist")
