"""Watch mode: check a token once, and RugRadar re-checks it every ~15 minutes and messages you on Telegram when
it turns: the pool money gets pulled, the creator dumps their bag, holders can no longer sell, or the verdict gets
worse. Nothing about you is stored beyond your Telegram chat id and the tokens you asked to watch.
"""
from __future__ import annotations
import time
from concurrent.futures import ThreadPoolExecutor
from . import store

KEY = "watch:all"
PER_CHAT = 10          # tokens one chat can watch
TOTAL = 300            # tokens watched across everyone
PER_RUN = 4            # tokens re-checked per run (keeps a run inside the server's time limit)
EXPIRE_S = 14 * 24 * 3600   # a watch lapses after two weeks; /watch again to renew
RANK = {"LOW_RISK": 0, "CAUTION": 1, "HIGH_RISK": 2}
BAD_CODES = {"HONEYPOT": "Holders can't sell it any more", "HOLDERS_STUCK": "Many holders can't sell",
             "SOME_STUCK": "A holder's test sale just failed", "LIQUIDITY_PULLED": "Pool money was pulled",
             "CANNOT_SELL_ALL": "You can't sell your whole bag", "OWNER_CHANGES_BALANCES": "The owner can change balances"}


def _load() -> dict:
    return store.safe(store.get, KEY, default=None) or {}


def _save(w: dict):
    store.safe(store.put, KEY, w)


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
    w = _load()
    k = f"{rep['chain']}:{rep['address']}"
    mine = [t for t, v in w.items() if chat_id in v.get("chats", [])]
    if k not in mine and len(mine) >= PER_CHAT:
        return f"You're already watching {PER_CHAT} tokens. Send /unwatch <address> to drop one."
    if k not in w and len(w) >= TOTAL:
        return "Watch list is full right now, try again later."
    e = w.get(k) or {"chats": [], "snap": snapshot(rep), "checked": time.time()}
    if chat_id not in e["chats"]:
        e["chats"].append(chat_id)
    e["until"] = time.time() + EXPIRE_S
    w[k] = e
    _save(w)
    return (f"👀 Watching {e['snap']['name'] or 'this token'} on {e['snap']['chain_name']} for 14 days. I re-check it about "
            "every 15 minutes and message you here if the pool money gets pulled, the creator dumps, holders can't sell, "
            "or the verdict gets worse. /unwatch to stop.")


def remove(chat_id, address: str | None) -> str:
    w = _load()
    hit = [k for k, v in w.items() if chat_id in v.get("chats", []) and (not address or k.split(":", 1)[1].lower() == address.lower())]
    for k in hit:
        w[k]["chats"].remove(chat_id)
        if not w[k]["chats"]:
            del w[k]
    _save(w)
    return f"Stopped watching {len(hit)} token{'s' if len(hit) != 1 else ''}." if hit else "You weren't watching that."


def listing(chat_id) -> str:
    mine = [(k, v) for k, v in _load().items() if chat_id in v.get("chats", [])]
    if not mine:
        return "You're not watching anything. Check a token, then send /watch <address>."
    return "Watching:\n" + "\n".join(f"• {v['snap']['name'] or k.split(':', 1)[1][:10] + '…'} ({v['snap']['chain_name']}): "
                                     f"last {v['snap']['verdict'].replace('_', ' ').lower()} {v['snap']['score']}/100" for k, v in mine)


def run(check, send, now: float | None = None) -> dict:
    """One sweep. `check(chain, address) -> report dict`, `send(chat_id, text)`. Safe to call from many places:
    a shared lock lets only one sweep run per 10 minutes."""
    now = now or time.time()
    if store.safe(store.hit, "watch:lock", 600, default=1) != 1:
        return {"ran": False, "why": "another sweep ran in the last 10 minutes"}
    w = _load()
    for k in [k for k, v in w.items() if v.get("until", 0) < now]:
        del w[k]
    due = sorted(w, key=lambda k: w[k].get("checked", 0))[:PER_RUN]

    def one(k):
        chain, addr = k.split(":", 1)
        try:
            return k, check(chain, addr)
        except Exception:
            return k, None
    with ThreadPoolExecutor(PER_RUN) as ex:
        results = list(ex.map(one, due))
    alerts = 0
    for k, rep in results:
        if not rep or rep.get("verdict") == "UNKNOWN":
            w[k]["checked"] = now          # try again next round; never alert or overwrite on a failed check
            continue
        new = snapshot(rep)
        diff = changes(w[k]["snap"], new)
        if diff:
            msg = "\n".join([f"🚨 RugRadar alert: {new['name'] or 'a token you watch'} on {new['chain_name']}", ""] +
                            [f"• {d}" for d in diff] + ["", f"Now: {new['verdict'].replace('_', ' ').lower()} {new['score']}/100",
                                                         f"Full check: {new['url'] or ''}".strip()])
            for chat in w[k]["chats"]:
                try:
                    send(chat, msg)
                    alerts += 1
                except Exception:
                    pass
        w[k].update(snap=new, checked=now)
    _save(w)
    return {"ran": True, "checked": len(results), "alerts": alerts, "watching": len(w)}
