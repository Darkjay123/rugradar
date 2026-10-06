"""RugRadar's own test sale, on every EVM network.

How: for real wallets that hold the token (top holders, and people who BOUGHT it from the pool recently), we ask a
public node "what would happen if this wallet sent half its tokens to the pool?" (an eth_call: read-only, nothing
signed, nothing sent). Sending to the pool is exactly what a sale does at the token level, so a token that blocks
sellers reverts here, and a token with a hidden sell tax delivers less to the pool than was sent.

A tiny probe contract (contracts/SellProbe.sol, compiled with solc 0.8.24 --optimize) is placed at the holder's
address for that one simulated call, so it can read balances before and after in the same call. Nodes that don't
support that still give a plain yes/no on whether the transfer reverts.
"""
from __future__ import annotations
import time
from concurrent.futures import ThreadPoolExecutor
from .native import P, NativeError, HOSTS
from urllib.parse import urlparse

PROBE = "0x608060405234801561000f575f80fd5b505f366060828080610021858261030b565b9250925092505f61003284306101fd565b91505f90506127106100448484610358565b61004e9190610375565b90505f61005b86866101fd565b9150505f5a90505f80886001600160a01b031663a9059cbb898760405160240161009a9291906001600160a01b03929092168252602082015260400190565b6040516020818303038152906040529060e01b6020820180516001600160e01b0383818316178352505050506040516100d39190610394565b5f604051808303815f865af19150503d805f811461010c576040519150601f19603f3d011682016040523d82523d5f602084013e610111565b606091505b50915091505f5a61012290856103c0565b90505f8380156101575750825115806101575750602083511015801561015757508280602001905181019061015791906103d3565b90505f6101648c8c6101fd565b9150505f6101728d306101fd565b915050828a8a8a8511610185575f61018f565b61018f8b866103c0565b848e1161019c575f6101a6565b6101a6858f6103c0565b6040805195151560208701528501939093526060840191909152608083015260a082015260c0810185905260e0016040516020818303038152906040529d5050505050505050505050505050915050805190602001f35b5f805f80856001600160a01b03166370a082318660405160240161023091906001600160a01b0391909116815260200190565b6040516020818303038152906040529060e01b6020820180516001600160e01b0383818316178352505050506040516102699190610394565b5f60405180830381855afa9150503d805f81146102a1576040519150601f19603f3d011682016040523d82523d5f602084013e6102a6565b606091505b50915091508180156102ba57506020815110155b156102e0576001818060200190518101906102d591906103f9565b9350935050506102e9565b5f809350935050505b9250929050565b80356001600160a01b0381168114610306575f80fd5b919050565b5f805f6060848603121561031d575f80fd5b610326846102f0565b9250610334602085016102f0565b9150604084013590509250925092565b634e487b7160e01b5f52601160045260245ffd5b808202811582820484141761036f5761036f610344565b92915050565b5f8261038f57634e487b7160e01b5f52601260045260245ffd5b500490565b5f82515f5b818110156103b35760208186018101518583015201610399565b505f920191825250919050565b8181038181111561036f5761036f610344565b5f602082840312156103e3575f80fd5b815180151581146103f2575f80fd5b9392505050565b5f60208284031215610409575f80fd5b505191905056fea26469706673582212207a80661317e5f456f3ec6c9aaacc94545d46d11aa0e8ddf18c16cfe8401573ba64736f6c63430008180033"
RPCS = {
 "kava": [
  "https://kava-evm-rpc.publicnode.com",
  "https://evm.kava.io",
  "https://evm.kava-rpc.com"
 ],
 "robinhood": [
  "https://rpc.mainnet.chain.robinhood.com",
  "https://robinhood.rpc.blxrbdn.com",
  "https://robinhood-rpc.publicnode.com"
 ],
 "polygon": [
  "https://rpc.nodeflare.app/polygon/public",
  "https://rpc-mainnet.matic.quiknode.pro",
  "https://polygon-bor-rpc.publicnode.com"
 ],
 "arc": [
  "https://arc-rpc.publicnode.com",
  "https://rpc.beamrpc.com",
  "https://rpc.mainnet.arc.io"
 ],
 "cronos": [
  "https://evm.cronos.org",
  "https://cronos-evm-rpc.publicnode.com",
  "https://public.1rpc.io/cro"
 ],
 "avalanche": [
  "https://api.avax.network/ext/bc/C/rpc",
  "https://avalanche-c-chain-rpc.publicnode.com",
  "https://public.1rpc.io/avax/c"
 ],
 "monad": [
  "https://monad-mainnet.api.onfinality.io/public",
  "https://monad-mainnet-rpc.spidernode.net",
  "https://infra.originstake.com/monad/evm"
 ],
 "arbitrum": [
  "https://rpc.hostdefi.com/api/rpc/arbitrum",
  "https://arb1.arbitrum.io/rpc",
  "https://arbitrum-one-public.nodies.app"
 ],
 "sonic": [
  "https://lb.routeme.sh/rpc/evm/146",
  "https://rpc.soniclabs.com",
  "https://sonic-json-rpc.stakely.io"
 ],
 "worldchain": [
  "https://worldchain-mainnet.g.alchemy.com/public",
  "https://worldchain-mainnet.gateway.tenderly.co",
  "https://sparkling-autumn-dinghy.worldchain-mainnet.quiknode.pro"
 ],
 "abstract": [
  "https://api.mainnet.abs.xyz",
  "https://abstract.api.onfinality.io/public"
 ],
 "optimism": [
  "https://rpc.hostdefi.com/api/rpc/optimism",
  "https://mainnet.optimism.io",
  "https://public.1rpc.io/op"
 ],
 "stable": [
  "https://stable-mainnet.rpc.sentio.xyz",
  "https://rpc.stable.xyz"
 ],
 "plasma": [
  "https://rpc.swiftnodes.io/rpc/plasma",
  "https://rpc.plasma.to"
 ],
 "linea": [
  "https://rpc.linea.build",
  "https://public.1rpc.io/linea",
  "https://linea.api.pocket.network"
 ],
 "mantle": [
  "https://rpc.mantle.xyz",
  "https://mantle-rpc.publicnode.com",
  "https://mantle.api.pocket.network"
 ],
 "blast": [
  "https://rpc.blast.io",
  "https://blast-rpc.publicnode.com"
 ],
 "berachain": [
  "https://rpc.berachain.com",
  "https://berachain-rpc.publicnode.com",
  "https://rpc.berachain-apis.com"
 ],
 "opbnb": [
  "https://opbnb-mainnet-rpc.bnbchain.org",
  "https://opbnb-rpc.publicnode.com",
  "https://public.1rpc.io/opbnb"
 ],
 "zksync": [
  "https://mainnet.era.zksync.io",
  "https://zksync.drpc.org",
  "https://public.1rpc.io/zksync2-era"
 ],
 "unichain": [
  "https://lb.routeme.sh/rpc/evm/130",
  "https://mainnet.unichain.org",
  "https://unichain.api.onfinality.io/public"
 ],
 "soneium": [
  "https://rpc.soneium.org",
  "https://soneium-mainnet.rpc.sentio.xyz",
  "https://rpc.swiftnodes.io/rpc/soneium"
 ],
 "conflux": [
  "https://evm.confluxrpc.com",
  "https://conflux-espace.blockpi.network/v1/rpc/public"
 ],
 "merlinchain": [
  "https://rpc.merlinchain.io"
 ],
 "scroll": [
  "https://lb.routeme.sh/rpc/evm/534352",
  "https://rpc.scroll.io",
  "https://public.1rpc.io/scroll"
 ],
 "story": [
  "https://mainnet.datarpc.io",
  "https://mainnet.storyrpc.io",
  "https://evm-rpc.story.mainnet.dteam.tech"
 ],
 "manta": [
  "https://public.1rpc.io/manta",
  "https://manta-pacific-gascap.calderachain.xyz/http",
  "https://r1.pacific.manta.systems/http"
 ],
 "ethereum": [
  "https://xrpc.cl/eth",
  "https://one.valve.city/rpc/vk_demo/evm/1",
  "https://eth-mainnet.nodereal.io/v1/1659dfb40aa24bbb8153a677b98064d7"
 ],
 "bsc": [
  "https://lb.routeme.sh/rpc/evm/56",
  "https://bsc-dataseed.bnbchain.org",
  "https://bsc-dataseed1.defibit.io"
 ],
 "base": [
  "https://mainnet.base.org",
  "https://developer-access-mainnet.base.org",
  "https://base.public.blockpi.network/v1/rpc/public"
 ],
 "pulsechain": [
  "https://rpc.pulsechain.com",
  "https://rpc-pulsechain.g4mm4.io",
  "https://rpc.degenprotocol.io"
 ],
 "hyperevm": [
  "https://hyperevm.rpc.sentio.xyz",
  "https://rpc.hyperliquid.xyz/evm",
  "https://rpc.hypurrscan.io"
 ],
 "ink": [
  "https://lb.routeme.sh/rpc/evm/57073",
  "https://rpc-gel.inkonchain.com",
  "https://rpc-qnd.inkonchain.com"
 ],
 "megaeth": [
  "https://rpc-megaeth-mainnet.globalstake.io",
  "https://megaeth.drpc.org",
  "https://megaeth.rpc.sentio.xyz"
 ],
 "apechain": [
  "https://rpc.apechain.com"
 ],
 "fantom": [
  "https://rpcapi.fantom.network",
  "https://rpc.fantom.network",
  "https://rpc2.fantom.network"
 ],
 "metis": [
  "https://lb.routeme.sh/rpc/evm/1088",
  "https://andromeda.metis.io/?owner=1088",
  "https://metis.api.onfinality.io/public"
 ],
 "celo": [
  "https://lb.routeme.sh/rpc/evm/42220",
  "https://forno.celo.org",
  "https://rpc.ankr.com/celo"
 ],
 "beam": [
  "https://build.onbeam.com/rpc",
  "https://subnets.avax.network/beam/mainnet/rpc"
 ],
 "flowevm": [
  "https://mainnet.evm.nodes.onflow.org"
 ],
 "katana": [
  "https://lb.routeme.sh/rpc/evm/747474",
  "https://rpc.swiftnodes.io/rpc/katana",
  "https://katana.rpc.sentio.xyz"
 ],
 "flare": [
  "https://flare-api.flare.network/ext/C/rpc",
  "https://rpc.ankr.com/flare",
  "https://rpc.au.cc/flare"
 ],
 "fuse": [
  "https://rpc.fuse.io",
  "https://fuse.api.pocket.network"
 ],
 "telos": [
  "https://rpc.telos.net",
  "https://public.1rpc.io/telos/evm"
 ],
 "seiv2": [
  "https://evm-rpc.sei-apis.com",
  "https://sei-evm-rpc.stakeme.pro",
  "https://sei.api.pocket.network"
 ],
 "injective": [
  "https://sentry.evm-rpc.injective.network/"
 ]
}
for _v in RPCS.values():
    HOSTS.update(urlparse(u).hostname for u in _v)
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
DEAD = {"0x" + "0" * 40, "0x000000000000000000000000000000000000dead"}


def _rpc(urls, method, params, timeout_s=6.0):
    last = None
    for u in urls:
        try:
            j = P(u, {"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
            if "error" in j:
                last = NativeError(str(j["error"])[:160])
                msg = str(j["error"]).lower()
                if "revert" in msg or "execution" in msg:
                    raise last  # a real answer from the token, not a node problem
                continue
            return j.get("result")
        except NativeError as e:
            if "revert" in str(e).lower() or "execution" in str(e).lower():
                raise
            last = e
    raise NativeError(f"no node answered: {last}")


def _w(a: str) -> str:
    return a.lower().replace("0x", "").rjust(64, "0")


def _probe(urls, token, pool, holder):
    data = "0x" + _w(token) + _w(pool) + hex(5000)[2:].rjust(64, "0")
    try:
        r = _rpc(urls, "eth_call", [{"from": holder, "to": holder, "data": data, "gas": "0x1c9c380"}, "latest", {holder: {"code": PROBE}}])
    except NativeError as e:
        return {"error": str(e)}
    h = (r or "0x")[2:]
    if len(h) < 384:
        return {"error": "short answer"}
    ok, mine, amt, recv, sent, gas = (int(h[i:i + 64], 16) for i in range(0, 384, 64))
    return {"ok": bool(ok), "balance": mine, "amount": amt, "received": recv, "sent": sent, "gas": gas}


def _plain(urls, token, pool, holder, amount):
    data = "0xa9059cbb" + _w(pool) + hex(amount)[2:].rjust(64, "0")
    try:
        _rpc(urls, "eth_call", [{"from": holder, "to": token, "data": data}, "latest"])
        return True
    except NativeError as e:
        return False if ("revert" in str(e).lower() or "execution" in str(e).lower()) else None


def recent_buyers(urls, token, pool, n=6):
    """Wallets that received this token FROM the pool lately = people who just bought it."""
    try:
        head = int(_rpc(urls, "eth_blockNumber", []), 16)
    except (NativeError, TypeError, ValueError):
        return []
    for span in (3000, 800, 200):
        try:
            logs = _rpc(urls, "eth_getLogs", [{"address": token, "fromBlock": hex(max(0, head - span)), "toBlock": "latest",
                                               "topics": [TRANSFER_TOPIC, "0x" + _w(pool)]}]) or []
        except NativeError:
            continue
        out = []
        for lg in reversed(logs):
            t = lg.get("topics") or []
            if len(t) > 2:
                a = "0x" + t[2][-40:]
                if a not in out and a not in DEAD:
                    out.append(a)
            if len(out) >= n:
                break
        return out
    return []


def _is_eoa(urls, a):
    try:
        c = _rpc(urls, "eth_getCode", [a, "latest"])
        return c in ("0x", "0x0", None) or (isinstance(c, str) and c.startswith("0xef0100"))  # EIP-7702 wallets count
    except NativeError:
        return False


def sell_test(chain: str, token: str, pairs: list, holders: list, skip: set, trace: list | None = None, max_wallets: int = 6) -> dict | None:
    urls = RPCS.get(chain)
    if not urls:
        return None
    t0 = time.time()
    pools = [p["pairAddress"] for p in sorted(pairs, key=lambda p: -((p.get("liquidity") or {}).get("usd") or 0))
             if isinstance(p.get("pairAddress"), str) and len(p["pairAddress"]) == 42 and p["pairAddress"].startswith("0x")]
    if not pools:
        return None
    pool = pools[0].lower()
    poolset = {p.lower() for p in pools}
    skip = {s.lower() for s in skip if s} | poolset | DEAD
    cands = recent_buyers(urls, token, pool)
    cands += [h.get("address", "").lower() for h in holders if str(h.get("is_contract")) != "1" and h.get("address")]
    seen, wallets = set(), []
    for a in cands:
        a = a.lower()
        if a in seen or a in skip or not a.startswith("0x") or len(a) != 42:
            continue
        seen.add(a)
        wallets.append(a)
    with ThreadPoolExecutor(6) as ex:
        eoa = list(ex.map(lambda a: _is_eoa(urls, a), wallets[:12]))
    wallets = [a for a, e in zip(wallets[:12], eoa) if e][:max_wallets]
    if not wallets:
        return None
    with ThreadPoolExecutor(6) as ex:
        res = list(ex.map(lambda a: _probe(urls, token, pool, a), wallets))
    tested, failed, taxes, rows = 0, 0, [], []
    for a, r in zip(wallets, res):
        if r.get("error"):
            ok = _plain(urls, token, pool, a, 1)  # node can't run the probe: plain does-it-revert check
            if ok is None:
                continue
            tested += 1
            failed += 0 if ok else 1
            rows.append({"wallet": a, "can_sell": ok})
            continue
        if not r["balance"] or not r["amount"]:
            continue
        tested += 1
        if not r["ok"]:
            failed += 1
            rows.append({"wallet": a, "can_sell": False})
            continue
        tax = max(0.0, 1 - r["received"] / r["amount"])
        taxes.append(tax)
        rows.append({"wallet": a, "can_sell": True, "tax": round(tax, 4)})
    if not tested:
        return None
    taxes.sort()
    med = taxes[len(taxes) // 2] if taxes else None
    out = {"ok": True, "source": "rugradar", "holders_tested": tested, "holders_failed": failed,
           "is_honeypot": (failed >= 2 and failed / tested >= 0.5) or (tested == 1 and failed == 1 and len(wallets) == 1 and False),
           "some_stuck": failed == 1 and tested >= 2, "sell_tax": round(med * 100, 2) if med is not None else None,
           "pool": pool, "wallets": rows, "ms": int((time.time() - t0) * 1000)}
    if trace is not None:
        trace.append({"tool": "sell_test", "found": True, "tested": tested, "failed": failed, "ms": out["ms"], "ts": time.time()})
    return out
