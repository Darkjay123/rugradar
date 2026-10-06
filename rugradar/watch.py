"""Watch mode: check a token once, and RugRadar re-checks it every ~15 minutes and messages you on Telegram when
it turns: the pool money gets pulled, the creator dumps their bag, holders can no longer sell, or the verdict gets
worse. Nothing about you is stored beyond your Telegram chat id and the tokens you asked to watch.
"""
from __future__ import annotations
import time
from concurrent.futures import ThreadPoolExecutor
from . import store

IDX = "watch:idx"            # set of watched tokens ("chain:address")
OLD = "watch:all"            # the first version kept everything in one key; migrated on first use
PER_CHAT = 10          # tokens one chat can watch
TOTAL = 300            # tokens watched across everyone
PER_RUN = 4            # tokens re-checked per run (keeps a run inside the server's time limit)
EXPIRE_S = 14 * 24 * 3600   # a watch lapses after two weeks; /watch again to renew
RANK = {"LOW_RISK": 0, "CAUTION": 1, "HIGH_RISK": 2}
BAD_CODES = {"HONEYPOT": "Holders can't sell it any more", "HOLDERS_STUCK": "Many holders can't sell",
             "SOME_STUCK": "A holder's test sale just failed", "LIQUIDITY_PULLED": "Pool money was pulled",
             "CANNOT_SELL_ALL": "You can't sell your whole bag", "OWNER_CHANGES_BALANCES": "The owner can change balances"}


# Each piece lives in its own key and every membership change is an atomic set operation, so a sweep that runs
# while someone sends /watch can never wipe out their watch (the first version rewrote one shared blob).
def _c(k): return f"watch:c:{k}"        # chats watching this token
def _m(chat): return f"watch:m:{chat}"  # tokens this chat watches
def _s(k): return f"watch:s:{k}"        # last snapshot + when we checked (written by the sweep)
def _u(k): return f"watch:u:{k}"        # watch expiry (written only by /watch)


def _migrate():
    old = store.safe(store.get, OLD)
    if not old:
        return
    for k, v in old.items():
        for chat in v.get("chats", []):
            store.safe(store.sadd, _c(k), str(chat))
            store.safe(store.sadd, _m(chat), k)
        store.safe(store.put, _s(k), {"snap": v["snap"], "checked": v.get("checked", 0)})
        store.safe(store.put, _u(k), v.get("until", 0))
        store.safe(store.sadd, IDX, k)
    store.safe(store.delete, OLD)


def _drop(k):
    for chat in store.safe(store.smembers, _c(k), default=[]) or []:
        store.safe(store.srem, _m(chat), k)
    for key in (_c(k), _s(k), _u(k)):
        store.safe(store.delete, key)
    store.safe(store.srem, IDX, k)


def snapshot(rep: dict) -> dict:
    m = rep.get("market") or {}
    return {"verdict": rep["verdict"], "score": rep["score"], "liq": m.get("liquidity_usd"), "creator": m.get("creator_pct"),
            "codes": sorted({f["code"] for f in rep.get("findings", []) if f.get("points")}),
            "name": " ".join(x for x in [rep.get("name") or "", f"${rep['symbol']}" if rep.get("symbol") else ""] if x),
            "chain_name": rep.get("chain_name") or rep["chain"], "url": rep.get("share_url")}


def changes(old: dict, new: dict) -> list[str]:
    """What got worse since the last look, in plain words. Empty list = nothing worth a message."""
    out = []
    if new["verdict"] in RANK and old.get("verdict") in RANK and RANK[new["verdict"]] > RANK[old["verdict"]]:
        lbl = {"CAUTION": "Be careful", "HIGH_RISK": "HIGH RISK"}[new["verdict"]]
        out.append(f"Verdict went from {old['verdict'].replace('_', ' ').lower()} to {lbl} ({old.get('score')} → {new['score']}/100)")
    ol, nl = old.get("liq"), new.get("liq")
    if ol and ol >= 1_000 and nl is not None and nl < ol * 0.5:
        out.append(f"Pool money fell {1 - nl / ol:.0%}: ${ol:,.0f} → ${nl:,.0f}")
    oc, nc = old.get("creator"), new.get("creator")
    if oc and oc >= 0.02 and nc is not None and nc < oc * 0.5:
        out.append(f"The creator sold most of their bag: held {oc:.1%}, now {nc:.1%}")
    for code in sorted(set(new.get("codes", [])) - set(old.get("codes", []))):
        if code in BAD_CODES:
            out.append(BAD_CODES[code])
    return out


def add(chat_id, rep: dict) -> str:
    _migrate()
    k, chat = f"{rep['chain']}:{rep['address']}", str(chat_id)
    mine = store.safe(store.smembers, _m(chat), default=[]) or []
    if k not in mine and len(mine) >= PER_CHAT:
        return f"You're already watching {PER_CHAT} tokens. Send /unwatch <address> to drop one."
    allk = store.safe(store.smembers, IDX, default=[]) or []
    if k not in allk and len(allk) >= TOTAL:
        return "Watch list is full right now, try again later."
    snap = snapshot(rep)
    if not store.safe(store.get, _s(k)):
        store.safe(store.put, _s(k), {"snap": snap, "checked": time.time()})
    store.safe(store.put, _u(k), time.time() + EXPIRE_S)
    store.safe(store.sadd, _c(k), chat)
    store.safe(store.sadd, _m(chat), k)
    store.safe(store.sadd, IDX, k)
    return (f"👀 Watching {snap['name'] or 'this token'} on {snap['chain_name']} for 14 days. I re-check it about "
            "every 15 minutes and message you here if the pool money gets pulled, the creator dumps, holders can't sell, "
            "or the verdict gets worse. /unwatch to stop.")


def remove(chat_id, address: str | None) -> str:
    _migrate()
    chat = str(chat_id)
    mine = store.safe(store.smembers, _m(chat), default=[]) or []
    hit = [k for k in mine if not address or k.split(":", 1)[1].lower() == address.lower()]
    for k in hit:
        store.safe(store.srem, _c(k), chat)
        store.safe(store.srem, _m(chat), k)
        if not store.safe(store.smembers, _c(k), default=[]):
            _drop(k)
    return f"Stopped watching {len(hit)} token{'s' if len(hit) != 1 else ''}." if hit else "You weren't watching that."


def listing(chat_id) -> str:
    _migrate()
    mine = store.safe(store.smembers, _m(str(chat_id)), default=[]) or []
    states = store.safe(store.mget, [_s(k) for k in mine], default=[]) or []
    rows = [(k, st["snap"]) for k, st in zip(mine, states) if st]
    if not rows:
        return "You're not watching anything. Check a token, then send /watch <address>."
    return "Watching:\n" + "\n".join(f"• {v['name'] or k.split(':', 1)[1][:10] + '…'} ({v['chain_name']}): "
                                     f"last {v['verdict'].replace('_', ' ').lower()} {v['score']}/100" for k, v in rows)


def run(check, send, now: float | None = None) -> dict:
    """One sweep. `check(chain, address) -> report dict`, `send(chat_id, text)`. A shared lock lets only one
    sweep run per 10 minutes however often it's called."""
    now = now or time.time()
    if store.safe(store.hit, "watch:lock", 600, default=1) != 1:
        return {"ran": False, "why": "another sweep ran in the last 10 minutes"}
    _migrate()
    keys = store.safe(store.smembers, IDX, default=[]) or []
    untils = store.safe(store.mget, [_u(k) for k in keys], default=None)
    if untils is None and keys:            # couldn't read expiries: never delete watches on a failed read
        return {"ran": False, "why": "store read failed"}
    live = []
    for k, u in zip(keys, untils or []):
        if u is not None and u < now:
            _drop(k)
        else:
            live.append(k)
    states = dict(zip(live, store.safe(store.mget, [_s(k) for k in live], default=[]) or [None] * len(live)))
    due = sorted((k for k in live if states.get(k)), key=lambda k: states[k].get("checked", 0))[:PER_RUN]

    def one(k):
        chain, addr = k.split(":", 1)
        try:
            return k, check(chain, addr)
        except Exception:
            return k, None
    with ThreadPoolExecutor(max(1, PER_RUN)) as ex:
        results = list(ex.map(one, due))
    alerts = 0
    for k, rep in results:
        st = states[k]
        if not rep or rep.get("verdict") == "UNKNOWN":
            store.safe(store.put, _s(k), {"snap": st["snap"], "checked": now})   # never alert on a failed check
            continue
        new = snapshot(rep)
        diff = changes(st["snap"], new)
        if diff:
            msg = "\n".join([f"🚨 RugRadar alert: {new['name'] or 'a token you watch'} on {new['chain_name']}", ""] +
                            [f"• {d}" for d in diff] + ["", f"Now: {new['verdict'].replace('_', ' ').lower()} {new['score']}/100",
                                                         f"Full check: {new['url'] or ''}".strip()])
            for chat in store.safe(store.smembers, _c(k), default=[]) or []:
                try:
                    send(int(chat) if chat.lstrip("-").isdigit() else chat, msg)
                    alerts += 1
                except Exception:
                    pass
        store.safe(store.put, _s(k), {"snap": new, "checked": now})
    return {"ran": True, "checked": len(results), "alerts": alerts, "watching": len(live)}
