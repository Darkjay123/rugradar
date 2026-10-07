"""TON test sale: replay a real transfer of the token from real holders' wallets, against the live chain.

On TON every holder owns a separate jetton-wallet contract, and that contract decides whether the tokens can
move. Honeypot jettons ship wallet code (or a blacklist in the master) that refuses to send to the DEX pool.
For a few real holders we build the exact message their own wallet would send to move part of their balance
into the token's main pool, and ask tonapi to emulate it on current state (signature check skipped, nothing is
broadcast, nothing is signed with anyone's key). If the holder's jetton wallet refuses, the token blocks sales.

No dependencies: the few cells we need are built and serialized here.
"""
from __future__ import annotations
import base64, hashlib, os, time
from concurrent.futures import ThreadPoolExecutor
import httpx

T = "https://tonapi.io/v2"
UA = {"User-Agent": "rugradar/0.4 (+https://github.com/Darkjay123/rugradar)"}
WALLETS = ("wallet_v5r1", "wallet_v4r2", "wallet_v3r2")
DEFAULT_SUBWALLET = {"wallet_v4r2": 698983191, "wallet_v3r2": 698983191, "wallet_v5r1": 2147483409}
SETUP_EXIT = {33, 34, 35, 36, 13, -14}  # wallet seqno/subwallet/expiry checks, out of gas: our message, not the token


# ---------------------------------------------------------------- cells
class Cell:
    __slots__ = ("bits", "refs", "_h", "_d")

    def __init__(self, bits: str = "", refs=()):
        assert len(bits) <= 1023 and len(refs) <= 4
        self.bits, self.refs, self._h, self._d = bits, list(refs), None, None

    def _desc_data(self) -> bytes:
        b = len(self.bits)
        d1, d2 = len(self.refs), b // 8 + (b + 7) // 8
        bits = self.bits + ("1" + "0" * ((8 - (b + 1) % 8) % 8) if b % 8 else "")
        data = int(bits, 2).to_bytes(len(bits) // 8, "big") if bits else b""
        return bytes([d1, d2]) + data

    def depth(self) -> int:
        if self._d is None:
            self._d = 0 if not self.refs else 1 + max(r.depth() for r in self.refs)
        return self._d

    def hash(self) -> bytes:
        if self._h is None:
            rep = self._desc_data() + b"".join(r.depth().to_bytes(2, "big") for r in self.refs) + b"".join(r.hash() for r in self.refs)
            self._h = hashlib.sha256(rep).digest()
        return self._h

    def boc(self) -> bytes:
        order, seen = [], set()

        def visit(c):  # reverse post-order = every cell before the cells it points to
            if c.hash() in seen:
                return
            seen.add(c.hash())
            for r in c.refs:
                visit(r)
            order.append(c)
        visit(self)
        order.reverse()
        idx = {c.hash(): i for i, c in enumerate(order)}
        size = max(1, (len(order).bit_length() + 7) // 8)
        body = b"".join(c._desc_data() + b"".join(idx[r.hash()].to_bytes(size, "big") for r in c.refs) for c in order)
        off = max(1, (len(body).bit_length() + 7) // 8)
        n = len(order).to_bytes(size, "big")
        return (bytes.fromhex("b5ee9c72") + bytes([size, off]) + n + (1).to_bytes(size, "big") + (0).to_bytes(size, "big")
                + len(body).to_bytes(off, "big") + (0).to_bytes(size, "big") + body)


class B:
    def __init__(self):
        self.bits, self.refs = [], []

    def u(self, v: int, n: int):
        self.bits.append(format(v & ((1 << n) - 1), f"0{n}b") if n else "")
        return self

    def bit(self, v):
        return self.u(1 if v else 0, 1)

    def coins(self, v: int):
        ln = (v.bit_length() + 7) // 8
        self.u(ln, 4)
        return self.u(v, ln * 8) if ln else self

    def addr(self, raw: str | None):
        if raw is None:
            return self.u(0, 2)
        wc, h = raw.split(":")
        return self.u(0b100, 3).u(int(wc), 8).u(int(h, 16), 256)

    def raw_bytes(self, b: bytes):
        return self.u(int.from_bytes(b, "big"), len(b) * 8) if b else self

    def ref(self, c: Cell):
        self.refs.append(c)
        return self

    def end(self) -> Cell:
        return Cell("".join(self.bits), self.refs)


def raw_address(a: str) -> str | None:
    """'EQ…'/'UQ…' friendly form or '0:hex' raw form -> '0:hex'."""
    a = (a or "").strip()
    if ":" in a:
        wc, h = a.split(":", 1)
        return f"{int(wc)}:{h.lower()}" if len(h) == 64 else None
    try:
        b = base64.urlsafe_b64decode(a.replace("+", "-").replace("/", "_") + "==")
    except (ValueError, TypeError):
        return None
    if len(b) != 36:
        return None
    wc = b[1] - 256 if b[1] > 127 else b[1]
    return f"{wc}:{b[2:34].hex()}"


# ---------------------------------------------------------------- messages
def jetton_transfer_body(amount: int, to: str, response: str) -> Cell:
    return (B().u(0x0F8A7EA5, 32).u(0, 64).coins(amount).addr(to).addr(response)
            .bit(0).coins(1).bit(0).end())  # no custom payload, 1 nanoton forward, empty forward payload


def internal_msg(dest: str, value: int, body: Cell) -> Cell:
    return (B().u(0, 1).bit(1).bit(1).bit(0).addr(None).addr(dest).coins(value).bit(0).coins(0).coins(0)
            .u(0, 64).u(0, 32).bit(0).bit(1).ref(body).end())


def wallet_external(version: str, wallet: str, subwallet: int, seqno: int, msg: Cell, valid_until: int) -> Cell:
    sig = b"\0" * 64  # emulation skips the signature check; nothing here can ever be broadcast
    if version == "wallet_v5r1":
        out = B().ref(Cell()).u(0x0EC3C86D, 32).u(3, 8).ref(msg).end()
        body = (B().u(0x7369676E, 32).u(subwallet, 32).u(valid_until, 32).u(seqno, 32).bit(1).ref(out).bit(0)
                .raw_bytes(sig).end())
    else:
        b = B().raw_bytes(sig).u(subwallet, 32).u(valid_until, 32).u(seqno, 32)
        if version == "wallet_v4r2":
            b.u(0, 8)
        body = b.u(3, 8).ref(msg).end()
    return B().u(0b10, 2).addr(None).addr(wallet).coins(0).bit(0).bit(1).ref(body).end()


# ---------------------------------------------------------------- network
_C = httpx.Client(timeout=12, headers={**UA, **({"Authorization": f"Bearer {os.environ['TONAPI_KEY']}"} if os.environ.get("TONAPI_KEY") else {})})


def _req(method, path, **kw):
    for attempt in range(3):
        try:
            r = _C.request(method, T + path, **kw)
        except httpx.HTTPError:
            r = None
        if r is not None and r.status_code == 429:
            time.sleep(1.1 + attempt)
            continue
        if r is None or r.status_code >= 500:
            time.sleep(0.4)
            continue
        if r.status_code != 200:
            return None
        try:
            return r.json()
        except ValueError:
            return None
    return None


def _walk(t):
    yield t
    for c in t.get("children") or []:
        yield from _walk(c)


def classify(trace: dict, wallet: str, jetton_wallet: str) -> tuple[str, int | None]:
    """'ok' | 'blocked' | 'inconclusive' from an emulated trace."""
    root = (trace or {}).get("transaction") or {}
    if raw_address((root.get("account") or {}).get("address", "")) != wallet or not root.get("success"):
        return "inconclusive", (root.get("compute_phase") or {}).get("exit_code")
    node = next((n for n in _walk(trace) if raw_address(n["transaction"]["account"]["address"]) == jetton_wallet), None)
    if not node:
        return "inconclusive", None
    tx = node["transaction"]
    code = (tx.get("compute_phase") or {}).get("exit_code")
    if not tx.get("success") or tx.get("aborted"):
        return ("inconclusive" if code in SETUP_EXIT else "blocked"), code
    kids = node.get("children") or []
    if not kids:
        return "blocked", code  # accepted the message but never sent the tokens on
    k = kids[0]["transaction"]
    kcode = (k.get("compute_phase") or {}).get("exit_code")
    if not k.get("success") or k.get("aborted"):
        return ("inconclusive" if kcode in SETUP_EXIT else "blocked"), kcode
    return "ok", None


def _try(h: dict, info: dict, pool: str) -> dict:
    wallet, jw = h["owner"], h["jetton_wallet"]
    seq = _req("GET", f"/wallet/{wallet}/seqno")
    if not seq or "seqno" not in seq:
        return {"wallet": wallet, "result": "inconclusive"}
    ver = info["version"]
    msg = internal_msg(jw, 300_000_000, jetton_transfer_body(max(1, h["balance"] // 2), pool, wallet))
    ext = wallet_external(ver, wallet, DEFAULT_SUBWALLET[ver], int(seq["seqno"]), msg, int(time.time()) + 600)
    j = _req("POST", "/wallet/emulate", json={"boc": base64.b64encode(ext.boc()).decode(),
                                              "params": [{"address": wallet, "balance": 2_000_000_000}]})
    if not j or "trace" not in j:
        return {"wallet": wallet, "result": "inconclusive"}
    res, code = classify(j["trace"], wallet, jw)
    return {"wallet": wallet, "result": res, **({"exit_code": code} if code is not None else {})}


def sell_test(master: str, pairs: list, trace: list | None = None, max_wallets: int = 3) -> dict | None:
    best = max(pairs or [], key=lambda p: (p.get("liquidity") or {}).get("usd") or 0, default=None)
    pool = raw_address((best or {}).get("pairAddress", ""))
    if not pool:
        return None
    t0 = time.time()
    hs = (_req("GET", f"/jettons/{master}/holders", params={"limit": 15}) or {}).get("addresses") or []
    pools = {raw_address(p.get("pairAddress", "")) for p in pairs or []}
    cands = []
    for h in hs:
        o = h.get("owner") or {}
        own = raw_address(o.get("address", ""))
        if o.get("is_wallet") and own and own not in pools and int(h.get("balance") or 0) > 0:
            cands.append({"owner": own, "jetton_wallet": raw_address(h["address"]), "balance": int(h["balance"])})
    if not cands:
        return None
    bulk = _req("POST", "/accounts/_bulk", json={"account_ids": [c["owner"] for c in cands]}) or {}
    info = {}
    for a in bulk.get("accounts") or []:
        ver = next((i for i in a.get("interfaces") or [] if i in WALLETS), None)
        if ver and a.get("status") == "active":
            info[raw_address(a["address"])] = {"version": ver}
    cands = [c for c in cands if c["owner"] in info][:max_wallets]
    if not cands:
        return None
    with ThreadPoolExecutor(len(cands)) as ex:
        rows = list(ex.map(lambda c: _try(c, info[c["owner"]], pool), cands))
    tested = [r for r in rows if r["result"] in ("ok", "blocked")]
    if not tested:
        if trace is not None:
            trace.append({"tool": "sell_test", "found": False, "why": "inconclusive", "ts": time.time()})
        return None
    failed = sum(r["result"] == "blocked" for r in tested)
    out = {"ok": True, "source": "rugradar", "holders_tested": len(tested), "holders_failed": failed,
           "is_honeypot": failed >= 2 and failed / len(tested) >= 0.5,
           "some_stuck": failed == 1 and len(tested) >= 2,
           "sell_tax": None, "kind": "transfer_to_pool",
           "wallets": [{"wallet": r["wallet"], "can_sell": r["result"] == "ok"} for r in tested],
           "ms": int((time.time() - t0) * 1000)}
    if trace is not None:
        trace.append({"tool": "sell_test", "found": True, "tested": len(tested), "failed": failed, "ms": out["ms"], "ts": time.time()})
    return out
