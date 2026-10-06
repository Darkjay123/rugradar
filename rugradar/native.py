"""Token-power reads for the networks GoPlus doesn't cover, straight from each network's own public data.

Every reader returns the same shape GoPlus does (so the one rulebook in scoring.py applies everywhere):
  token_name, token_symbol, holder_count, holders[{address, percent, is_contract}],
  is_mintable, owner_address, transfer_pausable, is_blacklisted, owner_change_balance,
  is_proxy, sell_tax, is_open_source, trust_list
plus RugRadar-only keys: code_replaceable, admin_can_change, listed_scam, transfer_hook, _source, _read.
'1' means we READ the power exists, '0' means we read it doesn't, a missing key means we couldn't tell.
No keys, no wallets, no writes: read-only public endpoints on an allowlist.
"""
from __future__ import annotations
import base64, json, re, time, random
from urllib.parse import urlparse, quote
import httpx

UA = {"User-Agent": "rugradar/0.4 (+https://github.com/Darkjay123/rugradar)"}
TIMEOUT = 7.0


class NativeError(Exception):
    pass


HOSTS = {
    "tonapi.io", "graphql.mainnet.sui.io", "api.mainnet.aptoslabs.com", "indexer.mainnet.movementnetwork.xyz",
    "mainnet.movementnetwork.xyz", "free.rpc.fastnear.com", "rpc.mainnet.near.org", "api.nearblocks.io",
    "mainnet-public.mirrornode.hedera.com", "xrplcluster.com", "s1.ripple.com", "s2.ripple.com", "api.koios.rest",
    "mainnet-idx.algonode.cloud", "starknet.drpc.org", "starknet-rpc.publicnode.com", "api.zan.top",
    "ic-api.internetcomputer.org", "api.hyperliquid.xyz", "api.multiversx.com", "api.hiro.so",
    "sentry.lcd.injective.network", "sentry.evm-rpc.injective.network",
    "polkadot-asset-hub-public-sidecar.parity-chains.parity.io",
}
# EVM networks: public RPCs (first that answers wins) + a Blockscout explorer where one exists (holders + verified source)
EVM = {
    "pulsechain": (["https://rpc.pulsechain.com", "https://rpc-pulsechain.g4mm4.io"], "https://api.scan.pulsechain.com"),
    "hyperevm": (["https://rpc.hyperliquid.xyz/evm", "https://hyperevm.rpc.sentio.xyz"], None),
    "ink": (["https://rpc-gel.inkonchain.com", "https://rpc-qnd.inkonchain.com"], "https://explorer.inkonchain.com"),
    "megaeth": (["https://megaeth.drpc.org", "https://rpc-megaeth-mainnet.globalstake.io"], "https://megaeth.blockscout.com"),
    "apechain": (["https://rpc.apechain.com", "https://apechain.drpc.org"], "https://apechain.calderaexplorer.xyz"),
    "fantom": (["https://rpcapi.fantom.network", "https://rpc.fantom.network"], None),
    "metis": (["https://andromeda.metis.io/?owner=1088", "https://metis-public.nodies.app"], "https://andromeda-explorer.metis.io"),
    "celo": (["https://forno.celo.org", "https://rpc.celocolombia.org"], "https://celo.blockscout.com"),
    "beam": (["https://build.onbeam.com/rpc", "https://subnets.avax.network/beam/mainnet/rpc"], None),
    "flowevm": (["https://mainnet.evm.nodes.onflow.org"], "https://evm.flowscan.io"),
    "kava": (["https://evm.kava.io", "https://kava-evm-rpc.publicnode.com"], None),
    "katana": (["https://katana.drpc.org", "https://rpc.swiftnodes.io/rpc/katana"], None),
    "flare": (["https://flare-api.flare.network/ext/C/rpc", "https://flare.drpc.org"], "https://flare-explorer.flare.network"),
    "fuse": (["https://rpc.fuse.io", "https://fuse.liquify.com"], "https://explorer.fuse.io"),
    "telos": (["https://rpc.telos.net", "https://telos.drpc.org"], "https://www.teloscan.io"),
    "seiv2": (["https://evm-rpc.sei-apis.com", "https://sei.drpc.org"], None),
    "injective": (["https://sentry.evm-rpc.injective.network/"], None),  # only for erc20:0x... Injective EVM tokens
}
for _r, _b in EVM.values():
    HOSTS.update(urlparse(u).hostname for u in _r)
    if _b:
        HOSTS.add(urlparse(_b).hostname)

DEAD_EVM = {"0x" + "0" * 40, "0x000000000000000000000000000000000000dead"}


def _host_ok(url: str):
    h = urlparse(url).hostname or ""
    if urlparse(url).scheme != "https" or h not in HOSTS:
        raise NativeError(f"blocked host {h}")


def _req(method: str, url: str, *, params=None, body=None, tries=2, ok404=False):
    _host_ok(url)
    last = None
    for i in range(tries):
        try:
            r = httpx.request(method, url, params=params, json=body, timeout=TIMEOUT, headers=UA)
            if ok404 and r.status_code in (400, 404):
                return None
            if r.status_code == 429 or r.status_code >= 500:
                raise NativeError(f"upstream {r.status_code}")
            r.raise_for_status()
            return r.json()
        except (httpx.HTTPError, NativeError, ValueError) as e:
            last = e
            time.sleep(0.3 * (i + 1) + random.random() * 0.2)
    raise NativeError(f"{urlparse(url).hostname} failed: {last}")


def G(url, ok404=False, **params):
    return _req("GET", url, params=params or None, ok404=ok404)


def P(url, body):
    return _req("POST", url, body=body)


def _yn(b):
    return None if b is None else ("1" if b else "0")


def _holders(rows, supply, addr_key="address", amt_key="amount", contract=None, limit=10):
    """rows -> GoPlus-style holders with percent of supply (largest first)."""
    try:
        supply = float(supply)
    except (TypeError, ValueError):
        return []
    if not supply:
        return []
    out = []
    for r in rows:
        try:
            amt = float(r[amt_key])
        except (TypeError, ValueError, KeyError):
            continue
        h = {"address": str(r.get(addr_key) or ""), "percent": str(amt / supply)}
        if contract:
            h["is_contract"] = "1" if contract(r) else "0"
        out.append(h)
    out.sort(key=lambda h: -float(h["percent"]))
    return out[:limit]


# ----------------------------------------------------------------------------------------------- EVM (17 networks)
SELECTORS = {
    "mint": {"40c10f19", "a0712d68", "449a52f8", "cc872b66", "94d008ef"},
    "pause": {"8456cb59", "16c38b3c", "c2e5ec04", "379ba1d9", "8f70ccf7", "1031e36e", "f275f64b"},
    "blacklist": {"f9f92be4", "44337ea1", "153b0d1e", "0ecb93c0", "9c0db5f3", "00b8cf2a", "342aa8b5", "9155e083",
                  "fe575a87", "d01dd6d2", "455a4396", "d34628cc", "fb2f3492"},
    "tax": {"69fe0e2d", "0b78f9c0", "c4081a4c", "061c82d0", "8b4cee08", "0cc835a3", "c647b20e", "6db79437", "8cd09d50",
            "dc1052e2", "c17b5b8c", "8095d564", "cec10c11", "ec28438a", "d543dbeb"},
    "balance": {"e30443bc", "f529d448", "b7e39b4f"},
}
SRC_PAT = {
    "mint": r"function\s+(mint|mintTo|issue)\s*\(",
    "pause": r"function\s+(pause|setPaused|setTrading\w*|pauseTrading|enableTrading)\s*\(",
    "blacklist": r"function\s+(\w*[Bb]lack[Ll]ist\w*|setBots?|blockBots|addBots?|\w*[Bb]lock[Ll]ist\w*)\s*\(",
    "tax": r"function\s+(set\w*(Fee|Tax)\w*|update\w*(Fee|Tax)\w*|setMaxTx\w*)\s*\(",
    "balance": r"function\s+(setBalance|changeBalance|setBalances)\s*\(",
}
IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
BEACON_SLOT = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"


def _selectors(code: str) -> set[str]:
    code = code[2:] if code.startswith("0x") else code
    return set(re.findall(r"63([0-9a-f]{8})", code.lower()))


def _rpc(urls, method, params):
    last = None
    for u in urls:
        try:
            j = P(u, {"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
            if "error" in j:
                raise NativeError(str(j["error"])[:80])
            return j.get("result")
        except NativeError as e:
            last = e
    raise NativeError(f"rpc {method}: {last}")


def _addr_word(w):
    if not w or w == "0x" or len(w) < 42:
        return None
    a = "0x" + w[-40:]
    return a.lower()


def _str_ret(h):
    try:
        b = bytes.fromhex(h[2:])
        if len(b) >= 96:
            n = int.from_bytes(b[32:64], "big")
            return b[64:64 + n].decode("utf-8", "ignore").strip("\x00") or None
        return b.rstrip(b"\x00").decode("utf-8", "ignore") or None
    except Exception:
        return None


def evm(chain: str, address: str) -> dict | None:
    rpcs, bs = EVM[chain]
    a = address.lower()
    code = _rpc(rpcs, "eth_getCode", [a, "latest"])
    if not code or code == "0x":
        return {"_source": "network node", "_read": ["no contract at this address"], "not_a_contract": "1"}
    out, read = {"_source": "network node" + (" + block explorer" if bs else "")}, ["contract code"]
    sels = _selectors(code)
    impl = None
    for slot in (IMPL_SLOT, BEACON_SLOT):
        try:
            w = _rpc(rpcs, "eth_getStorageAt", [a, slot, "latest"])
            if w and int(w, 16):
                impl = _addr_word(w)
                break
        except NativeError:
            pass
    if impl:
        out["is_proxy"] = "1"
        try:
            icode = _rpc(rpcs, "eth_getCode", [impl, "latest"])
            if icode and icode != "0x":
                sels |= _selectors(icode)
        except NativeError:
            pass
    else:
        out["is_proxy"] = "0"

    def call(sel):
        try:
            return _rpc(rpcs, "eth_call", [{"to": a, "data": "0x" + sel}, "latest"])
        except NativeError:
            return None
    owner = None
    for sel in ("8da5cb5b", "893d20e8"):
        r = call(sel)
        if r and r != "0x":
            owner = _addr_word(r)
            break
    if owner:
        out["owner_address"] = owner
        read.append("owner")
    out["token_name"], out["token_symbol"] = _str_ret(call("06fdde03") or "0x"), _str_ret(call("95d89b41") or "0x")
    ts = call("18160ddd")
    supply = int(ts, 16) if ts and ts != "0x" else None

    found = {k: bool(sels & v) for k, v in SELECTORS.items()}
    if bs:  # verified source beats the selector guess, and the explorer gives holders
        try:
            sc = G(f"{bs}/api/v2/smart-contracts/{address}", ok404=True) or {}
            if sc:
                out["is_open_source"] = "1" if sc.get("is_verified") or sc.get("is_partially_verified") else "0"
                srcs = [sc.get("source_code") or ""] + [f.get("source_code") or "" for f in sc.get("additional_sources") or []]
                if impl:
                    isc = G(f"{bs}/api/v2/smart-contracts/{impl}", ok404=True) or {}
                    srcs += [isc.get("source_code") or ""] + [f.get("source_code") or "" for f in isc.get("additional_sources") or []]
                src = "\n".join(srcs)
                if src.strip():
                    read.append("verified source")
                    for k, pat in SRC_PAT.items():
                        found[k] = found[k] or bool(re.search(pat, src))
            else:
                out["is_open_source"] = "0"
        except NativeError:
            pass
        try:
            tk = G(f"{bs}/api/v2/tokens/{address}", ok404=True) or {}
            if tk:
                hc = tk.get("holders_count") or tk.get("holders")
                if str(hc or "").isdigit():
                    out["holder_count"] = str(hc)
                supply = int(tk["total_supply"]) if str(tk.get("total_supply") or "").isdigit() else supply
                out["token_name"] = out.get("token_name") or tk.get("name")
                out["token_symbol"] = out.get("token_symbol") or tk.get("symbol")
                hs = (G(f"{bs}/api/v2/tokens/{address}/holders", ok404=True) or {}).get("items") or []
                rows = [{"address": (h.get("address") or {}).get("hash", "").lower(), "amount": h.get("value"),
                         "c": (h.get("address") or {}).get("is_contract")} for h in hs]
                out["holders"] = _holders(rows, supply, contract=lambda r: r.get("c"))
                read.append("top holders")
        except NativeError:
            pass

    renounced = owner in DEAD_EVM if owner else False
    live = not renounced or impl  # an upgradeable proxy can bring powers back whatever owner() says
    out["is_mintable"] = _yn(found["mint"])
    out["transfer_pausable"] = _yn(found["pause"] and live)
    out["is_blacklisted"] = _yn(found["blacklist"] and live)
    out["slippage_modifiable"] = _yn(found["tax"] and live)
    out["owner_change_balance"] = _yn(found["balance"] and live)
    if found["mint"] and not owner:
        out["owner_address"] = "unknown"  # mint exists, nobody visibly renounced it
    out["_read"] = read
    return out


# ----------------------------------------------------------------------------------------------- TON
def ton(address: str) -> dict | None:
    j = G(f"https://tonapi.io/v2/jettons/{quote(address, safe='')}", ok404=True)
    if not j:
        return None
    m, adm = j.get("metadata") or {}, (j.get("admin") or {}).get("address")
    out = {"_source": "TON network (tonapi)", "token_name": m.get("name"), "token_symbol": m.get("symbol"),
           "holder_count": str(j.get("holders_count") or ""), "is_mintable": _yn(bool(j.get("mintable"))),
           "owner_address": adm or "", "_read": ["jetton master", "mint switch", "admin"]}
    v = j.get("verification")
    if v == "whitelist":
        out["trust_list"] = "1"
    elif v == "blacklist":
        out["listed_scam"] = "1"
    out["admin_can_change"] = _yn(bool(adm))
    try:
        hs = (G(f"https://tonapi.io/v2/jettons/{quote(address, safe='')}/holders", limit=12) or {}).get("addresses") or []
        rows = [{"address": (h.get("owner") or {}).get("address", ""), "amount": h.get("balance"),
                 "w": (h.get("owner") or {}).get("is_wallet"), "scam": (h.get("owner") or {}).get("is_scam")} for h in hs]
        out["holders"] = _holders(rows, j.get("total_supply"), contract=lambda r: not r.get("w"))
        out["_read"].append("top holders")
    except NativeError:
        pass
    return out


# ----------------------------------------------------------------------------------------------- Sui
SUI_GQL = "https://graphql.mainnet.sui.io/graphql"


def sui(coin_type: str) -> dict | None:
    q = ('{coinMetadata(coinType:"%s"){name symbol supply} cap:objects(filter:{type:"0x2::coin::TreasuryCap<%s>"},first:2)'
         '{nodes{owner{__typename ... on AddressOwner{address{address}}}}} deny:objects(filter:{type:"0x2::coin::DenyCapV2<%s>"},first:1)'
         '{nodes{address}} deny1:objects(filter:{type:"0x2::coin::DenyCap<%s>"},first:1){nodes{address}}}') % ((coin_type,) * 4)
    j = (P(SUI_GQL, {"query": q}) or {}).get("data") or {}
    md = j.get("coinMetadata")
    if not md:
        return None
    out = {"_source": "Sui network", "token_name": md.get("name"), "token_symbol": md.get("symbol"), "_read": ["coin metadata"]}
    from .blocklists import sui_scam_coin
    if sui_scam_coin(coin_type):
        out["listed_scam"] = "1"
        out["_read"].append("Suiet scam-coin list")
    caps = (j.get("cap") or {}).get("nodes") or []
    if caps:
        o = caps[0].get("owner") or {}
        t = o.get("__typename")
        out["_read"].append("mint key (TreasuryCap)")
        if t == "AddressOwner":
            out["is_mintable"], out["owner_address"] = "1", ((o.get("address") or {}).get("address") or "unknown")
        elif t == "Immutable":
            out["is_mintable"] = "0"
        else:  # held inside another object or shared: a contract decides who can mint
            out["is_mintable"], out["owner_address"] = "1", "a contract"
    elif md.get("supply") is not None:
        out["is_mintable"] = "0"  # supply frozen into the metadata at creation
        out["_read"].append("fixed supply")
    if ((j.get("deny") or {}).get("nodes")) or ((j.get("deny1") or {}).get("nodes")):
        out["is_blacklisted"] = "1"
        out["_read"].append("deny list")
    else:
        out["is_blacklisted"] = "0"
    return out


# ----------------------------------------------------------------------------------------------- Aptos + Movement
MOVE = {"aptos": ("https://api.mainnet.aptoslabs.com/v1", "https://api.mainnet.aptoslabs.com/v1/graphql"),
        "movement": ("https://mainnet.movementnetwork.xyz/v1", "https://indexer.mainnet.movementnetwork.xyz/v1/graphql")}


def move(chain: str, asset: str) -> dict | None:
    node, gql = MOVE[chain]
    q = ('{m:fungible_asset_metadata(where:{asset_type:{_eq:"%s"}}){name symbol supply_v2 maximum_v2 creator_address token_standard}'
         ' b:current_fungible_asset_balances(where:{asset_type:{_eq:"%s"},amount:{_gt:"0"}},order_by:{amount:desc},limit:12){owner_address amount}}') % (asset, asset)
    j = (P(gql, {"query": q}) or {}).get("data") or {}
    if not j.get("m"):
        return None
    m = j["m"][0]
    out = {"_source": f"{'Aptos' if chain == 'aptos' else 'Movement'} network", "token_name": m.get("name"),
           "token_symbol": m.get("symbol"), "_read": ["token metadata", "top holders"]}
    sup = m.get("supply_v2")
    out["holders"] = _holders([{"address": b["owner_address"], "amount": b["amount"]} for b in j.get("b") or []], sup)
    creator = m.get("creator_address") or (asset.split("::")[0] if "::" in asset else None)
    if "::" in asset and creator:  # classic coin: whoever holds MintCapability<T> can print more
        try:
            res = G(f"{node}/accounts/{creator}/resources", ok404=True, limit=9999) or []
            blob = json.dumps([r.get("type") for r in res])
            short = asset.split("::", 1)[1]
            mint = any(("MintCapability" in t or "Capabilities<" in t or "MintCap" in t) and short in t for t in json.loads(blob))
            freeze = any("FreezeCapability" in t and short in t for t in json.loads(blob))
            out["is_mintable"], out["is_blacklisted"] = _yn(mint), _yn(freeze)
            if mint:
                out["owner_address"] = creator
            out["_read"].append("mint and freeze keys")
        except NativeError:
            pass
    else:  # fungible asset object: a dispatch hook can run custom code on every transfer (and block sells)
        try:
            res = G(f"{node}/accounts/{asset}/resources", ok404=True) or []
            types = [r.get("type", "") for r in res]
            out["transfer_hook"] = _yn(any("DispatchFunctionStore" in t for t in types))
            mx = m.get("maximum_v2")
            if mx is not None and sup is not None and float(mx) <= float(sup):
                out["is_mintable"] = "0"
            out["_read"].append("transfer hooks")
        except NativeError:
            pass
    return out


# ----------------------------------------------------------------------------------------------- NEAR
NEAR_RPC = ["https://free.rpc.fastnear.com", "https://rpc.mainnet.near.org"]


def _near(method, params):
    last = None
    for u in NEAR_RPC:
        try:
            j = P(u, {"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
            if j.get("error"):
                raise NativeError(str(j["error"])[:80])
            return j["result"]
        except NativeError as e:
            last = e
    raise NativeError(str(last))


def near(account: str) -> dict | None:
    if not re.fullmatch(r"[a-z0-9._\-]{2,64}", account):
        return None
    try:
        keys = _near("query", {"request_type": "view_access_key_list", "finality": "final", "account_id": account})["keys"]
    except NativeError:
        return None
    full = [k for k in keys if k.get("access_key", {}).get("permission") == "FullAccess"]
    out = {"_source": "NEAR network", "code_replaceable": _yn(bool(full)), "_read": ["who can redeploy the contract"]}
    try:
        r = _near("query", {"request_type": "call_function", "finality": "final", "account_id": account,
                            "method_name": "ft_metadata", "args_base64": "e30="})
        md = json.loads(bytes(r["result"]).decode())
        out["token_name"], out["token_symbol"] = md.get("name"), md.get("symbol")
        r = _near("query", {"request_type": "call_function", "finality": "final", "account_id": account,
                            "method_name": "ft_total_supply", "args_base64": "e30="})
        supply = json.loads(bytes(r["result"]).decode())
        hs = (G(f"https://api.nearblocks.io/v1/fts/{account}/holders", ok404=True, per_page=12) or {}).get("holders") or []
        out["holders"] = _holders(hs, supply, addr_key="account")
        out["_read"] += ["token metadata", "top holders"]
    except (NativeError, ValueError, KeyError, TypeError):
        pass
    return out


# ----------------------------------------------------------------------------------------------- Hedera
def hedera(token: str) -> dict | None:
    j = G(f"https://mainnet-public.mirrornode.hedera.com/api/v1/tokens/{token}", ok404=True)
    if not j or j.get("type") not in (None, "FUNGIBLE_COMMON"):
        return None
    has = lambda k: bool(j.get(k))
    out = {"_source": "Hedera network (mirror node)", "token_name": j.get("name"), "token_symbol": j.get("symbol"),
           "is_mintable": _yn(has("supply_key") and j.get("supply_type") != "FINITE" or (has("supply_key") and
                              float(j.get("max_supply") or 0) > float(j.get("total_supply") or 0))),
           "owner_address": j.get("treasury_account_id") or "", "is_blacklisted": _yn(has("freeze_key")),
           "owner_change_balance": _yn(has("wipe_key")), "transfer_pausable": _yn(has("pause_key")),
           "admin_can_change": _yn(has("admin_key")), "_read": ["token keys", "fees"]}
    if j.get("pause_status") == "PAUSED":
        out["paused_now"] = "1"
    fr = ((j.get("custom_fees") or {}).get("fractional_fees") or [])
    fee = 0.0
    for f in fr:
        a = f.get("amount") or {}
        if a.get("denominator"):
            fee += a["numerator"] / a["denominator"]
    out["sell_tax"] = out["buy_tax"] = str(fee)
    if has("kyc_key"):
        out["is_blacklisted"] = "1"  # every holder needs the issuer's approval
    try:
        tot = int(j.get("total_supply") or 0)
        if tot:
            b = G(f"https://mainnet-public.mirrornode.hedera.com/api/v1/tokens/{j['token_id']}/balances",
                  **{"account.balance": f"gte:{max(1, tot // 200)}", "limit": 100})
            out["holders"] = _holders(b.get("balances") or [], tot, addr_key="account", amt_key="balance")
            out["_read"].append("top holders")
    except NativeError:
        pass
    return out


# ----------------------------------------------------------------------------------------------- XRPL
XRPL = ["https://xrplcluster.com", "https://s1.ripple.com:51234", "https://s2.ripple.com:51234"]
BLACKHOLES = {"rrrrrrrrrrrrrrrrrrrrrhoLvTp", "rrrrrrrrrrrrrrrrrrrrBZbvji", "rrrrrrrrrrrrrrrrrNAMEtxvNvQ", "rrrrrrrrrrrrrrrrrrrn5RM1rHd"}


def _xrpl(method, params):
    last = None
    for u in XRPL:
        try:
            j = (P(u, {"method": method, "params": [params]}) or {}).get("result") or {}
            if j.get("status") == "error" or j.get("error"):
                raise NativeError(j.get("error") or "error")
            return j
        except NativeError as e:
            last = e
            if "actNotFound" in str(e) or "actMalformed" in str(e):
                break
    raise NativeError(str(last))


def _xrpl_cur(c):
    if len(c) == 40:
        try:
            return bytes.fromhex(c).rstrip(b"\x00").decode() or c
        except Exception:
            return c
    return c


def xrpl(token: str) -> dict | None:
    if "." not in token:
        return None
    cur, issuer = token.rsplit(".", 1)
    try:
        info = _xrpl("account_info", {"account": issuer, "ledger_index": "validated", "signer_lists": True})
    except NativeError:
        return None
    ad = info.get("account_data") or {}
    fl = int(ad.get("Flags") or 0)
    signers = (info.get("signer_lists") or ad.get("signer_lists") or [])
    master_off = bool(fl & 0x00100000)
    blackholed = master_off and (not ad.get("RegularKey") or ad.get("RegularKey") in BLACKHOLES) and not signers
    out = {"_source": "XRP Ledger", "token_symbol": _xrpl_cur(cur), "owner_address": issuer,
           # a blackholed issuer has no working keys left, so it can't mint, freeze or claw back anymore
           "is_mintable": _yn(not blackholed), "is_blacklisted": _yn(not blackholed and not (fl & 0x00200000)),
           "owner_change_balance": _yn(not blackholed and bool(fl & 0x80000000)),
           "transfer_pausable": _yn(not blackholed and not (fl & 0x00200000)),
           "_read": ["issuer account", "freeze and clawback flags", "transfer fee"]}
    if fl & 0x00400000:
        out["paused_now"] = "1"
    tr = int(ad.get("TransferRate") or 0)
    out["sell_tax"] = out["buy_tax"] = str(max(0, tr - 1_000_000_000) / 1_000_000_000 if tr else 0)
    try:
        rows, marker = [], None
        for _ in range(3):
            p = {"account": issuer, "ledger_index": "validated", "limit": 400}
            if marker:
                p["marker"] = marker
            r = _xrpl("account_lines", p)
            rows += [{"address": l["account"], "amount": -float(l["balance"])} for l in r.get("lines") or []
                     if l.get("currency") == cur and float(l["balance"]) < 0]
            marker = r.get("marker")
            if not marker:
                break
        supply = sum(x["amount"] for x in rows)
        out["holders"] = _holders(rows, supply)
        if not marker:
            out["holder_count"] = str(len(rows))
        out["_read"].append("top holders" + ("" if not marker else " (first 1,200 lines)"))
    except NativeError:
        pass
    return out


# ----------------------------------------------------------------------------------------------- Cardano
def cardano(unit: str) -> dict | None:
    if not re.fullmatch(r"[0-9a-f]{56}[0-9a-f]{0,64}", unit):
        return None
    pol, name = unit[:56], unit[56:]
    a = (P("https://api.koios.rest/api/v1/asset_info", {"_asset_list": [[pol, name]]}) or [None])[0]
    if not a:
        return None
    reg = a.get("token_registry_metadata") or {}
    out = {"_source": "Cardano network (Koios)", "token_name": reg.get("name") or a.get("asset_name_ascii"),
           "token_symbol": reg.get("ticker") or a.get("asset_name_ascii"), "_read": ["token info", "minting policy"]}
    try:
        s = (P("https://api.koios.rest/api/v1/script_info", {"_script_hashes": [pol]}) or [{}])[0]
        typ, val = s.get("type"), s.get("value")
        if typ in ("timelock", "multisig") and val:
            before = [x.get("slot") for x in _walk(val) if x.get("type") == "before"]
            tip = (G("https://api.koios.rest/api/v1/tip") or [{}])[0].get("abs_slot") or 0
            locked = bool(before) and max(before) < tip
            out["is_mintable"] = _yn(not locked)
            out["owner_address"] = "" if locked else "the policy key holder"
        elif typ and typ.startswith("plutus"):
            out["mint_rules_in_code"] = "1"  # a smart-contract policy decides; we can't prove it's closed
    except NativeError:
        pass
    try:
        hs = G("https://api.koios.rest/api/v1/asset_addresses", _asset_policy=pol, _asset_name=name, limit=1000) or []
        out["holders"] = _holders(hs, a.get("total_supply"), addr_key="payment_address", amt_key="quantity")
        if len(hs) < 1000:
            out["holder_count"] = str(len(hs))
        out["_read"].append("top holders")
    except NativeError:
        pass
    return out


def _walk(v):
    if isinstance(v, dict):
        yield v
        for x in v.values():
            yield from _walk(x)
    elif isinstance(v, list):
        for x in v:
            yield from _walk(x)


# ----------------------------------------------------------------------------------------------- Algorand
ALGO_ZERO = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"


def algorand(asset_id: str) -> dict | None:
    if not asset_id.isdigit() or asset_id == "0":
        return None
    j = (G(f"https://mainnet-idx.algonode.cloud/v2/assets/{asset_id}", ok404=True) or {}).get("asset")
    if not j:
        return None
    p = j.get("params") or {}
    live = lambda k: bool(p.get(k)) and p.get(k) != ALGO_ZERO
    out = {"_source": "Algorand network", "token_name": p.get("name"), "token_symbol": p.get("unit-name"),
           "is_mintable": "0",  # an Algorand asset's total is fixed at creation
           "owner_change_balance": _yn(live("clawback")), "is_blacklisted": _yn(live("freeze") or p.get("default-frozen")),
           "admin_can_change": _yn(live("manager")), "owner_address": p.get("manager") or "",
           "_read": ["asset settings (clawback, freeze, manager)"]}
    try:
        tot = int(p.get("total") or 0)
        b = G(f"https://mainnet-idx.algonode.cloud/v2/assets/{asset_id}/balances", **{"currency-greater-than": max(0, tot // 200), "limit": 200})
        out["holders"] = _holders(b.get("balances") or [], tot)
        out["_read"].append("top holders")
    except NativeError:
        pass
    return out


# ----------------------------------------------------------------------------------------------- Starknet
STARK = ["https://starknet-rpc.publicnode.com", "https://starknet.drpc.org", "https://api.zan.top/public/starknet-mainnet"]


def starknet(address: str) -> dict | None:
    if not re.fullmatch(r"0x[0-9a-fA-F]{1,64}", address):
        return None
    cls, last = None, None
    for u in STARK:
        try:
            j = P(u, {"jsonrpc": "2.0", "id": 1, "method": "starknet_getClassAt", "params": ["latest", address]})
            if j.get("result"):
                cls = j["result"]
                break
            last = j.get("error")
        except NativeError as e:
            last = e
    if not cls:
        return None
    abi = cls.get("abi")
    abi = json.loads(abi) if isinstance(abi, str) else (abi or [])
    names = set()
    for x in _walk(abi):
        if x.get("type") in ("function", "l1_handler") and x.get("name"):
            names.add(x["name"].lower())
    has = lambda *ws: any(any(w in n for w in ws) for n in names)
    out = {"_source": "Starknet network", "_read": ["contract functions"],
           "is_mintable": _yn(has("mint")), "is_proxy": _yn(has("upgrade", "replace_class")),
           "transfer_pausable": _yn(has("pause")), "is_blacklisted": _yn(has("blacklist", "blocklist", "freeze")),
           "slippage_modifiable": _yn(has("set_fee", "set_tax", "set_buy_fee", "set_sell_fee", "set_max_tx")),
           "owner_address": "unknown" if has("mint") else ""}
    return out


# ----------------------------------------------------------------------------------------------- ICP
ICP_BLACKHOLE = {"e3mmv-5qaaa-aaaah-aadma-cai"}


def icp(canister: str) -> dict | None:
    if not re.fullmatch(r"[a-z0-9]{5}(-[a-z0-9]{3,5}){4}", canister):
        return None
    j = G(f"https://ic-api.internetcomputer.org/api/v3/canisters/{canister}", ok404=True)
    if not j:
        return None
    ctrl = [c for c in (j.get("controllers") or []) if c not in ICP_BLACKHOLE]
    return {"_source": "Internet Computer", "code_replaceable": _yn(bool(ctrl)), "owner_address": ", ".join(ctrl[:2]),
            "_read": ["who controls the token canister"]}


# ----------------------------------------------------------------------------------------------- Hyperliquid (HyperCore spot)
def hyperliquid(token_id: str) -> dict | None:
    if not re.fullmatch(r"0x[0-9a-fA-F]{32}", token_id):
        return None
    j = P("https://api.hyperliquid.xyz/info", {"type": "tokenDetails", "tokenId": token_id})
    if not j or not j.get("name"):
        return None
    out = {"_source": "Hyperliquid", "token_name": j.get("name"), "token_symbol": j.get("name"),
           "is_mintable": "0",  # HyperCore spot supply is fixed when the token is deployed
           "_read": ["token details (fixed supply)"]}
    g = (j.get("genesis") or {}).get("userBalances") or []
    try:
        tot = float(j.get("totalSupply") or 0)
        rows = [{"address": u, "amount": b} for u, b in g]
        if rows and tot:
            out["holders"] = _holders(rows, tot)
            out["_read"].append("launch allocations")
    except (ValueError, TypeError):
        pass
    return out


# ----------------------------------------------------------------------------------------------- MultiversX
def multiversx(token: str) -> dict | None:
    if not re.fullmatch(r"[A-Z0-9]{3,10}-[0-9a-f]{6}", token):
        return None
    j = G(f"https://api.multiversx.com/tokens/{token}", ok404=True)
    if not j:
        return None
    out = {"_source": "MultiversX network", "token_name": j.get("name"), "token_symbol": j.get("ticker"),
           "owner_address": j.get("owner") or "", "owner_change_balance": _yn(bool(j.get("canWipe"))),
           "is_blacklisted": _yn(bool(j.get("canFreeze"))), "transfer_pausable": _yn(bool(j.get("canPause"))),
           "admin_can_change": _yn(bool(j.get("canUpgrade"))), "holder_count": str(j.get("accounts") or ""),
           "_read": ["token properties (wipe, freeze, pause, upgrade)"]}
    if j.get("isPaused"):
        out["paused_now"] = "1"
    try:
        roles = G(f"https://api.multiversx.com/tokens/{token}/roles", ok404=True) or []
        minters = [r.get("address") for r in roles if r.get("canLocalMint") and r.get("address")]
        out["is_mintable"] = _yn(bool(minters) or bool(j.get("canMint")))
        if minters:
            out["owner_address"] = minters[0]
        out["_read"].append("who can mint")
        hs = G(f"https://api.multiversx.com/tokens/{token}/accounts", size=12) or []
        sup = j.get("supply") or j.get("circulatingSupply")
        dec = int(j.get("decimals") or 0)
        rows = [{"address": h["address"], "amount": float(h["balance"]) / 10 ** dec,
                 "pool": "liquiditypool" in ((h.get("assets") or {}).get("tags") or [])} for h in hs]
        out["holders"] = [h for h in _holders(rows, sup, contract=lambda r: r["pool"]) if h.get("is_contract") != "1"]
        out["_read"].append("top holders")
    except (NativeError, ValueError, TypeError):
        pass
    return out


# ----------------------------------------------------------------------------------------------- Stacks
def stacks(contract: str) -> dict | None:
    m = re.fullmatch(r"(S[PM][0-9A-Z]{28,41})\.([a-zA-Z][\w\-]{0,127})", contract)
    if not m:
        return None
    addr, name = m.groups()
    src = (G(f"https://api.hiro.so/v2/contracts/source/{addr}/{name}", ok404=True) or {}).get("source")
    if not src:
        return None
    pub = re.findall(r"\(define-public\s+\(([\w\-]+)", src)
    has = lambda *ws: any(any(w in f for w in ws) for f in pub)
    out = {"_source": "Stacks network", "is_open_source": "1", "_read": ["contract source (Clarity, can't be upgraded)"],
           "is_mintable": _yn(has("mint")), "is_blacklisted": _yn(has("blacklist", "blocklist", "freeze", "block-")),
           "transfer_pausable": _yn(has("pause")), "slippage_modifiable": _yn(has("set-fee", "set-tax")),
           "owner_address": addr if has("mint") else "", "is_proxy": "0"}
    try:
        iface = G(f"https://api.hiro.so/v2/contracts/interface/{addr}/{name}") or {}
        ft = ((iface.get("fungible_tokens") or [{}])[0]).get("name")
        if ft:
            h = G(f"https://api.hiro.so/extended/v1/tokens/ft/{contract}::{ft}/holders", limit=12) or {}
            out["holders"] = _holders(h.get("results") or [], h.get("total_supply"), amt_key="balance")
            out["holder_count"] = str(h.get("total") or "")
            out["_read"].append("top holders")
    except NativeError:
        pass
    return out


# ----------------------------------------------------------------------------------------------- Injective
INJ_NULL = "inj1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqe2hm49"


def injective(denom: str) -> dict | None:
    if denom.startswith("erc20:0x"):
        return evm("injective", denom.split(":", 1)[1])
    m = re.fullmatch(r"factory[-/](inj1[0-9a-z]{38,58})[-/](.+)", denom)
    if m:
        creator, sub = m.groups()
        j = G(f"https://sentry.lcd.injective.network/injective/tokenfactory/v1beta1/denoms/{creator}/{quote(sub, safe='')}/authority_metadata", ok404=True)
        if not j:
            return None
        admin = (j.get("authority_metadata") or {}).get("admin") or ""
        live = bool(admin) and admin != INJ_NULL
        return {"_source": "Injective network", "is_mintable": _yn(live), "owner_address": admin if live else "",
                "owner_change_balance": _yn(live and (j.get("authority_metadata") or {}).get("admin_burn_allowed")),
                "_read": ["token admin (mint and burn rights)"]}
    if denom.startswith("peggy0x") or denom.startswith("ibc-") or denom == "inj":
        return {"_source": "Injective network", "bridged": "1", "_read": ["bridged or native asset"]}
    return None


# ----------------------------------------------------------------------------------------------- Polkadot Asset Hub
def polkadot(asset_id: str) -> dict | None:
    if not asset_id.isdigit():
        return None
    j = G(f"https://polkadot-asset-hub-public-sidecar.parity-chains.parity.io/pallets/assets/{asset_id}/asset-info", ok404=True)
    info = (j or {}).get("assetInfo")
    if not info:
        return None
    md = (j or {}).get("assetMetaData") or {}
    dec = lambda h: bytes.fromhex(h[2:]).decode("utf-8", "ignore") if isinstance(h, str) and h.startswith("0x") else h
    return {"_source": "Polkadot Asset Hub", "token_name": dec(md.get("name")), "token_symbol": dec(md.get("symbol")),
            "is_mintable": _yn(bool(info.get("issuer"))), "owner_address": info.get("issuer") or "",
            "owner_change_balance": _yn(bool(info.get("admin"))), "is_blacklisted": _yn(bool(info.get("freezer"))),
            "paused_now": "1" if info.get("status") == "Frozen" else None, "_read": ["asset roles (issuer, admin, freezer)"]}


READERS = {
    "ton": ton, "sui": sui, "aptos": lambda a: move("aptos", a), "movement": lambda a: move("movement", a), "near": near,
    "hedera": hedera, "xrpl": xrpl, "cardano": cardano, "algorand": algorand, "starknet": starknet, "icp": icp,
    "hyperliquid": hyperliquid, "multiversx": multiversx, "stacks": stacks, "injective": injective, "polkadot": polkadot,
    **{c: (lambda a, c=c: evm(c, a)) for c in EVM if c != "injective"},
}
ORDERBOOK = {"hyperliquid", "injective"}  # DexScreener shows $0 'liquidity' for order-book markets: not a thin pool


def read(chain: str, address: str) -> dict | None:
    fn = READERS.get(chain)
    if not fn:
        return None
    out = fn(address)
    if out:
        out = {k: v for k, v in out.items() if v is not None}
    return out or None
