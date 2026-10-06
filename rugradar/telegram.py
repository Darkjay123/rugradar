"""Telegram bot: forward a gem message, an address or a link to the bot (or /check in a group) and get the verdict back.

Setup is one step for the owner: put TELEGRAM_BOT_TOKEN (from @BotFather) in the Vercel env, redeploy, then open
/api/telegram/setup once. The webhook secret is derived from the token, so there is no second secret to manage.
"""
from __future__ import annotations
import hashlib, os, re
import httpx
from .agent import check_text, prepare, InputError, SHARE_BASE
from . import watch, memory, store

TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
DOT = {"LOW_RISK": "🟢", "CAUTION": "🟠", "HIGH_RISK": "🔴", "UNKNOWN": "⚪"}
LBL = {"LOW_RISK": "Low risk (not a promise)", "CAUTION": "Be careful", "HIGH_RISK": "HIGH RISK, don't buy", "UNKNOWN": "Couldn't check it"}
PCM = re.compile(r"\b(abeg|wetin|dey|una|wahala|oya|sabi|shey|abi|na im|e go)\b", re.I)
HELP = ("Send me a token address, a DexScreener or pump.fun link, or forward the whole 'gem' message. "
        "I'll tell you if it looks like a scam, what you'd get back in naira, and send a link you can share.\n\n"
        "Send /watch <address> and I'll keep checking it and message you if the pool money gets pulled, the creator dumps "
        "or holders can't sell. /watching lists them, /unwatch stops.\n\n"
        "In groups: reply to the message with /check. Add 'pidgin' for Pidgin. I never need your wallet or seed phrase.")


def bot_username() -> str | None:
    """The bot's @username (for t.me deep links), cached a day. None when Telegram isn't configured."""
    if not TOKEN:
        return None
    hit = store.safe(store.get, "tg:me")
    if hit:
        return hit
    try:
        u = httpx.get(f"https://api.telegram.org/bot{TOKEN}/getMe", timeout=5).json()["result"]["username"]
    except Exception:
        return None
    store.safe(store.put, "tg:me", u, ttl=24 * 3600)
    return u


def watch_link(trace_id: str) -> str | None:
    u = bot_username()
    return f"https://t.me/{u}?start=w{trace_id}" if u and trace_id and trace_id.isalnum() else None


def secret() -> str:
    return hashlib.sha256(("rugradar:" + TOKEN).encode()).hexdigest()[:48] if TOKEN else ""


def _send(chat_id, text, reply_to=None):
    if not TOKEN:
        return
    body = {"chat_id": chat_id, "text": text[:4000], "disable_web_page_preview": False}
    if reply_to:
        body["reply_parameters"] = {"message_id": reply_to, "allow_sending_without_reply": True}
    httpx.post(f"https://api.telegram.org/bot{TOKEN}/sendMessage", json=body, timeout=10)


def format_report(r) -> str:
    j = r.model_dump(mode="json") if hasattr(r, "model_dump") else r
    tok = " ".join(x for x in [j.get("name") or "", f"${j['symbol']}" if j.get("symbol") else ""] if x) or "This token"
    lines = [f"{DOT[j['verdict']]} {LBL[j['verdict']]}: {j['score']}/100", f"{tok} on {j.get('chain_name') or j['chain']}", ""]
    for f in j.get("message_flags", [])[:3]:
        lines.append(f"⚠️ {f['plain']}")
    for f in [f for f in j.get("findings", []) if f.get("points")][:3]:
        lines.append(f"• {f['plain']}")
    if j.get("money"):
        m = j["money"]
        lines += ["", f"Put in ₦{m['amount_ngn']:,} → get back about ₦{m['get_back_ngn']:,}. {m['note']}"]
    if (j.get("coverage") or {}).get("missing"):
        lines.append("Couldn't read: " + ", ".join(j["coverage"]["missing"]))
    lines += ["", f"Full check: {j.get('share_url') or SHARE_BASE}"]
    return "\n".join(lines)


def handle(update: dict) -> str | None:
    """Returns the reply text (also sent). Pure enough to test without Telegram."""
    msg = update.get("message") or update.get("channel_post") or {}
    text = (msg.get("text") or msg.get("caption") or "").strip()
    if not text:
        return None
    chat = msg.get("chat", {})
    group = chat.get("type") in ("group", "supergroup")
    cmd = text.split()[0].split("@")[0].lower() if text.startswith("/") else ""
    arg = text.split(None, 1)[1].strip() if len(text.split(None, 1)) > 1 else ""
    if cmd == "/start" and arg.startswith("w") and arg[1:].isalnum():
        # deep link from a web check: t.me/<bot>?start=w<trace_id> -> watch that token
        saved = memory.get_report(arg[1:33])
        if not saved:
            out = "That check has expired. Send /watch with the token address instead."
        else:
            try:
                rep = check_text(saved["address"], saved["chain"], "en", 50_000)
                j = rep.model_dump(mode="json")
                out = (format_report(rep) + "\n\n" + watch.add(chat.get("id"), j)) if j["verdict"] != "UNKNOWN" else \
                    "I couldn't re-check that token right now. Try /watch with the address in a minute."
            except (InputError, ValueError):
                out = "Send /watch with the token address to start watching."
    elif cmd in ("/start", "/help"):
        out = HELP
    elif cmd == "/watching":
        out = watch.listing(chat.get("id"))
    elif cmd == "/unwatch":
        out = watch.remove(chat.get("id"), arg or None)
    elif cmd == "/watch":
        if not arg:
            out = "Send /watch followed by the token address or link."
        else:
            try:
                rep = check_text(arg[:2000], "auto", "en", 50_000)
                j = rep.model_dump(mode="json")
                out = (format_report(rep) + "\n\n" + watch.add(chat.get("id"), j)) if j["verdict"] != "UNKNOWN" else \
                    "I couldn't check that token right now, so I can't start watching it. Try again in a minute."
            except (InputError, ValueError):
                out = "I couldn't find a token address in that. Send /watch with the contract address or a DexScreener / pump.fun link."
    else:
        if group and cmd != "/check":
            return None  # in groups only answer when asked
        if cmd == "/check":
            text = text.split(None, 1)[1] if len(text.split(None, 1)) > 1 else ""
            rep = msg.get("reply_to_message") or {}
            text = (text + " " + (rep.get("text") or rep.get("caption") or "")).strip()
        lang = "pcm" if (PCM.search(text) or "pidgin" in text.lower()) else "en"
        text = re.sub(r"\bpidgin\b", "", text, flags=re.I).strip()
        if not text:
            out = HELP
        else:
            try:
                out = format_report(check_text(text[:2000], "auto", lang, 50_000))
            except (InputError, ValueError):
                _, flags, _ = prepare(text[:4000])
                out = ("I couldn't find a token address in that. " +
                       ("But the message itself has red flags:\n" + "\n".join(f"⚠️ {f['plain']}" for f in flags) if flags
                        else "Send the contract address or a DexScreener / pump.fun link."))
    _send(chat.get("id"), out, msg.get("message_id"))
    return out


def setup(base: str) -> dict:
    if not TOKEN:
        return {"ok": False, "error": "TELEGRAM_BOT_TOKEN is not set in the environment"}
    r = httpx.post(f"https://api.telegram.org/bot{TOKEN}/setWebhook", timeout=10,
                   json={"url": f"{base}/api/telegram", "secret_token": secret(), "allowed_updates": ["message", "channel_post"]})
    httpx.post(f"https://api.telegram.org/bot{TOKEN}/setMyCommands", timeout=10,
               json={"commands": [{"command": "check", "description": "Check a token (reply to a message, or add an address)"},
                                  {"command": "watch", "description": "Watch a token and get alerts if it turns"},
                                  {"command": "watching", "description": "Tokens you're watching"},
                                  {"command": "unwatch", "description": "Stop watching (all, or add an address)"},
                                  {"command": "help", "description": "How to use RugRadar"}]})
    return {"ok": r.json().get("ok", False), "description": r.json().get("description")}


def sweep() -> dict:
    """Re-check watched tokens and message anyone whose token turned."""
    def check(chain, address):
        return check_text(address, chain, "en", 50_000).model_dump(mode="json")
    return watch.run(check, lambda chat, text: _send(chat, text))
