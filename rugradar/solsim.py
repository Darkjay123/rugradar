"""Solana test sale: build a real Jupiter sell from wallets that actually hold the token and run it through the
network's own simulator (simulateTransaction, signatures not checked). Nothing is signed or sent.

A sale counts as BLOCKED only when the token itself refuses it: the token program or a transfer hook fails (frozen
account, non-transferable, hook rejects). Failures that say nothing about the token (out of compute, slippage, the
wallet has no SOL for fees, stale quote) are inconclusive and that wallet is skipped.
"""
from __future__ import annotations
import re
import time
from concurrent.futures import ThreadPoolExecutor
import httpx

RPCS = ["https://solana-rpc.publicnode.com", "https://api.mainnet-beta.solana.com"]
JUP = "https://lite-api.jup.ag/swap/v1"
WSOL = "So11111111111111111111111111111111111111112"
TOKEN_PROGRAMS = {"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"}
SYSTEMISH = TOKEN_PROGRAMS | {"11111111111111111111111111111111", "ComputeBudget111111111111111111111111111111",
                              "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL", "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"}
# SPL token errors that mean our test was set up wrong, not that the token blocks sales:
# 0x1 insufficient funds, 0x3 mint mismatch, 0x4 owner mismatch, 0x9 uninitialized account
SETUP_ERRORS = {"0x1", "0x3", "0x4", "0x9"}
INCONCLUSIVE_TEXT = ("exceeded cus", "computational budget exceeded", "insufficient lamports", "insufficientfundsforfee",
                     "accountnotfound", "blockhashnotfound", "invalidaccountforfee", "0x1771", "0x1789", "slippage",
                     "insufficient funds for rent")
TARGET_LAMPORTS = 200_000_000          # aim each test sale at about 0.2 SOL: big enough to see a tax, small enough to route
FEE_SLACK = 3_000_000                  # network fee + temporary wSOL account rent, so a clean sale never looks taxed

_C = httpx.Client(timeout=8.0, headers={"User-Agent": "rugradar/1.0"})


def _rpc(method: str, params: list):
    for u in RPCS:
        try:
            j = _C.post(u, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).json()
            if "result" in j:
                return j["result"]
        except Exception:
            continue
    return None


def _jup(method: str, path: str, **kw):
    """One Jupiter call with a single short retry on its rate limit. Returns (json or None, rate_limited)."""
    for attempt in (0, 1):
        try:
            r = _C.request(method, f"{JUP}/{path}", **kw)
        except Exception:
            return None, False
        if r.status_code == 429:
            if attempt == 0:
                time.sleep(1.2)
                continue
            return None, True
        try:
            return r.json(), False
        except Exception:
            return None, False
    return None, True


def _quote(mint: str, amount: int):
    q, _ = _jup("GET", "quote", params={"inputMint": mint, "outputMint": WSOL, "amount": amount, "slippageBps": 2000})
    return q if q and q.get("outAmount") else None


def classify(err, logs: list[str]) -> str:
    """'ok', 'blocked' (the token refused the sale) or 'inconclusive'.

    Blocked only when the program that failed first is the token program itself, or a program the token program
    called (a Token-2022 transfer hook). A DEX or router failing, even with a scary message like "frozen" or the same
    error number, says nothing about the token. Token-program errors that come from our test setup (not enough
    balance, wrong owner, account not set up) are inconclusive, not a trap.
    """
    if err is None:
        return "ok"
    text = (str(err) + " " + " ".join(logs or [])).lower()
    if any(k in text for k in INCONCLUSIVE_TEXT):
        return "inconclusive"
    stack, parent_of, deepest = [], {}, None
    for line in logs or []:
        if (m := re.match(r"Program (\w+) invoke \[(\d+)\]", line)):
            stack = stack[: int(m.group(2)) - 1] + [m.group(1)]
            parent_of.setdefault(m.group(1), stack[-2] if len(stack) >= 2 else None)
        elif deepest is None and (m := re.match(r"Program (\w+) failed: (.*)", line)):
            deepest, why = m.group(1), m.group(2).lower()
    if deepest is None:
        return "inconclusive"
    if deepest in TOKEN_PROGRAMS:
        code = re.search(r"custom program error: (0x[0-9a-f]+)", why)
        return "inconclusive" if code and code.group(1) in SETUP_ERRORS else "blocked"
    if parent_of.get(deepest) in TOKEN_PROGRAMS:
        return "blocked"
    return "inconclusive"

def _try(q: dict, owner: str) -> dict:
    s, limited = _jup("POST", "swap", json={"quoteResponse": q, "userPublicKey": owner, "wrapAndUnwrapSol": True,
                                            "dynamicComputeUnitLimit": True, "prioritizationFeeLamports": 0})
    tx = (s or {}).get("swapTransaction")
    if not tx:
        return {"wallet": owner, "result": "inconclusive", "rate_limited": limited}
    pre = _rpc("getBalance", [owner])
    sim = _rpc("simulateTransaction", [tx, {"encoding": "base64", "sigVerify": False, "replaceRecentBlockhash": True,
                                            "accounts": {"encoding": "base64", "addresses": [owner]}}])
    if not sim or not pre:
        return {"wallet": owner, "result": "inconclusive"}
    v = sim.get("value") or {}
    res = classify(v.get("err"), v.get("logs") or [])
    row = {"wallet": owner, "result": res}
    if res == "ok":
        post = (v.get("accounts") or [None])[0]
        expected = int(q["outAmount"])
        if post and expected >= 20_000_000:   # under 0.02 SOL the fixed costs swamp any tax reading
            got = post["lamports"] - pre["value"]
            row["tax"] = round(max(0.0, 1 - (got + FEE_SLACK) / expected), 4)
    return row


def _shared_quote(mint: str, cands: list):
    """One quote sized to about 0.2 SOL (or a tenth of the smallest holding), reused for every wallet: a quote
    doesn't depend on who sells, so this keeps the test to 1-2 quote calls however many wallets we try."""
    amount = max(1, min(int(h["amount"]) for h in cands) // 10)
    q = _quote(mint, amount)
    if q and int(q["outAmount"]) > TARGET_LAMPORTS * 2:
        q = _quote(mint, max(1, amount * TARGET_LAMPORTS // int(q["outAmount"]))) or q
    return q


def sell_test(mint: str, rc: dict | None, trace: list | None = None, max_wallets: int = 4) -> dict | None:
    cands = [h for h in ((rc or {}).get("sell_candidates") or []) if h.get("owner") and int(h.get("amount") or 0) > 0]
    if not cands:
        return None
    t0 = time.time()
    cands = cands[:max_wallets]
    q = _shared_quote(mint, cands)
    if not q:
        if trace is not None:
            trace.append({"tool": "sell_test", "found": False, "why": "no sell route", "ts": time.time()})
        return None
    with ThreadPoolExecutor(max_wallets) as ex:
        rows = list(ex.map(lambda h: _try(q, h["owner"]), cands))
    tested = [r for r in rows if r["result"] in ("ok", "blocked")]
    if not tested:
        if trace is not None:
            trace.append({"tool": "sell_test", "found": False, "why": "inconclusive", "ts": time.time()})
        return None
    failed = sum(r["result"] == "blocked" for r in tested)
    taxes = sorted(r["tax"] for r in tested if "tax" in r)
    med = taxes[len(taxes) // 2] if taxes else None
    out = {"ok": True, "source": "rugradar", "holders_tested": len(tested), "holders_failed": failed,
           "is_honeypot": failed >= 2 and failed / len(tested) >= 0.5,
           "some_stuck": failed == 1 and len(tested) >= 2,
           "sell_tax": round(med * 100, 2) if med is not None else None,
           "wallets": [{"wallet": r["wallet"], "can_sell": r["result"] == "ok", **({"tax": r["tax"]} if "tax" in r else {})}
                       for r in tested],
           "ms": int((time.time() - t0) * 1000)}
    if trace is not None:
        trace.append({"tool": "sell_test", "found": True, "tested": len(tested), "failed": failed, "ms": out["ms"],
                      "ts": time.time()})
    return out
