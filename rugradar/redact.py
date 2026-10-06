"""Pasted text is untrusted and often personal. Before anything is logged, stored or sent anywhere:
  - recovery phrases, private keys, emails and phone numbers are stripped
  - scam-pitch patterns in the message itself are flagged (separately from the token verdict)
Nothing a user pastes is ever put in a model prompt; contains_sensitive() is the last-line check.
"""
from __future__ import annotations
import re
from pathlib import Path

WORDS = set((Path(__file__).parent / "data" / "bip39_english.txt").read_text().split())
EVM = re.compile(r"0x[a-fA-F0-9]{40}\b")
# a 64-hex string is treated as a private key and removed, unless it is clearly a token id: inside a link path
# (dexscreener.com/starknet/0x...) or a Move coin type (0x...::coin::COIN)
EVM_KEY = re.compile(r"(?<![0-9a-fA-Fx/])(?:0x)?[0-9a-fA-F]{64}(?![0-9a-fA-F])(?!::)")
SOL_KEY = re.compile(r"\b[1-9A-HJ-NP-Za-km-z]{85,90}\b")
EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
PHONE = re.compile(r"(?<![\w])(?:\+?234|0)[789][01]\d[\s-]?\d{3}[\s-]?\d{4}(?!\d)|(?<![\w])\+\d{1,3}[\s-]?\d{3}[\s-]?\d{3}[\s-]?\d{3,4}(?!\d)")

FLAGS = {
    "SEED_PHRASE_SHARED": (r"", "This message contains a wallet recovery phrase. Anyone who has those words can empty that wallet. Move the funds to a new wallet now and never share the words again.",
                           "Recovery phrase dey inside this message. Anybody wey get those words fit carry all the money for that wallet. Move the money to new wallet now, and no ever share those words again."),
    "ASKS_FOR_SEED": (r"(seed|recovery|secret|backup)\s*phrase|private\s*key|12[\s-]*words?|24[\s-]*words?|mnemonic",
                      "It asks about a recovery phrase or private key. No real project, admin or support team will ever ask for these.",
                      "E dey ask for recovery phrase or private key. No real project, admin or support go ever ask you for am."),
    "WALLET_DRAIN_LINK": (r"(connect|sync|validate|verify|link)\s+(your\s+)?wallet|claim\s+(your\s+)?(airdrop|reward|tokens)|wallet\s*(validation|rectification)",
                          "It pushes you to connect your wallet to claim or verify something. That is how wallet-drainer sites steal funds.",
                          "E dey push you make you connect wallet to claim or verify something. Na so wallet-drainer sites dey take steal money."),
    "GUARANTEED_RETURNS": (r"guarantee|risk[\s-]*free|\b\d{2,5}\s*x\b|\bx\s*\d{2,5}\b|double\s+your|100%\s*(profit|returns?)|can'?t\s+lose",
                           "It promises guaranteed or huge returns. Real investments never guarantee profit.",
                           "E dey promise sure profit or big returns. No real investment dey guarantee profit."),
    "URGENCY": (r"last\s+chance|ends?\s+(today|tonight|in\s+\d+)|only\s+\d+\s+(spots|slots|left)|hurry|don'?t\s+miss|before\s+it'?s\s+too\s+late|launching\s+in\s+\d+",
                "It rushes you. Pressure to buy fast is a classic scam move.",
                "E dey rush you. To pressure person make e buy quick na old scam style."),
    "SEND_TO_RECEIVE": (r"send\s+[\d.,]+\s*\w*\s+(and|to)\s+(get|receive)|(get|receive)\s+(it\s+)?(back\s+)?double",
                        "It asks you to send money first to receive more back. That is always a scam.",
                        "E dey tell you make you send money first to collect more. Na scam be that, every time."),
}


def find_seed(text: str) -> list[tuple[int, int]]:
    """Spans of 12+ consecutive BIP39 words (a recovery phrase)."""
    spans, run = [], []
    for m in re.finditer(r"[A-Za-z]+", text):
        if m.group().lower() in WORDS:
            run.append(m)
            continue
        if len(run) >= 12:
            spans.append((run[0].start(), run[-1].end()))
        run = []
    if len(run) >= 12:
        spans.append((run[0].start(), run[-1].end()))
    return spans


def redact(text: str) -> tuple[str, list[str]]:
    """Returns (safe_text, kinds_removed). Token addresses are kept: they are public and needed."""
    kinds, out = [], text
    for a, b in reversed(find_seed(out)):
        out = out[:a] + "[recovery phrase removed]" + out[b:]
        kinds.append("seed_phrase")
    keep = {m.group() for m in EVM.finditer(out)}
    for name, rx, repl in (("private_key", EVM_KEY, "[key removed]"), ("private_key", SOL_KEY, "[key removed]"),
                           ("email", EMAIL, "[email removed]"), ("phone", PHONE, "[phone removed]")):
        def sub(m):
            if m.group() in keep:
                return m.group()
            kinds.append(name)
            return repl
        out = rx.sub(sub, out)
    return out, sorted(set(kinds))


def message_flags(text: str, lang: str = "en") -> list[dict]:
    """Red flags in the pitch itself. Separate from the token verdict on purpose: the message can't make a token look safer."""
    li = 1 if lang == "en" else 2
    found = []
    if find_seed(text):
        found.append({"code": "SEED_PHRASE_SHARED", "plain": FLAGS["SEED_PHRASE_SHARED"][li]})
    low = text.lower()
    for code, spec in FLAGS.items():
        if spec[0] and re.search(spec[0], low):
            found.append({"code": code, "plain": spec[li]})
    return found


def contains_sensitive(s: str) -> bool:
    return bool(find_seed(s) or EVM_KEY.search(s) or SOL_KEY.search(s) or EMAIL.search(s) or PHONE.search(s) or EVM.search(s))
