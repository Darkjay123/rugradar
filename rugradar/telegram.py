"""Telegram bot: forward a gem message, an address or a link to the bot (or /check in a group) and get the verdict back.

Setup is one step for the owner: put TELEGRAM_BOT_TOKEN (from @BotFather) in the Vercel env, redeploy, then open
/api/telegram/setup once. The webhook secret is derived from the token, so there is no second secret to manage.
"""
from __future__ import annotations
import hashlib, os, re
import httpx
from .agent import check_text, prepare, InputError, SHARE_BASE

TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
DOT = {"LOW_RISK": "🟢", "CAUTION": "🟠", "HIGH_RISK": "🔴", "UNKNOWN": "⚪"}
LBL = {"LOW_RISK": "Low risk (not a promise)", "CAUTION": "Be careful", "HIGH_RISK": "HIGH RISK, don't buy", "UNKNOWN": "Couldn't check it"}
PCM = re.compile(r"\b(abeg|wetin|dey|una|wahala|oya|sabi|shey|abi|na im|e go)\b", re.I)
HELP = ("Send me a token address, a DexScreener or pump.fun link, or forward the whole 'gem' message. "
        "I'll tell you if it looks like a scam, what you'd get back in naira, and send a link you can share.\n\n"
        "In groups: reply to the message with /check. Add 'pidgin' for Pidgin. I never need your wallet or seed phrase.")


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
    if cmd in ("/start", "/help"):
        out = HELP
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
                                  {"command": "help", "description": "How to use RugRadar"}]})
    return {"ok": r.json().get("ok", False), "description": r.json().get("description")}
