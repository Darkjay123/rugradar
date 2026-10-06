"""Newcomers don't have 'a contract address'. They have a link, a forwarded Telegram/WhatsApp 'gem'
message, or an explorer page. Pull the token out of whatever they paste, on any of the 64 networks.

Returns {"address", "chain" (or None = ask DexScreener where it trades), "is_pair", "fallback" (chain to
assume if DexScreener has never seen it)}."""
from __future__ import annotations
import re
from .chains import NAMES, canon

B58 = "1-9A-HJ-NP-Za-km-z"
EVM = re.compile(r"0x[a-fA-F0-9]{40}(?![a-fA-F0-9])")
SOL = re.compile(rf"(?<![{B58}])[{B58}]{{32,44}}(?![{B58}])")

EXPLORERS = {  # host -> chain
    "etherscan.io": "ethereum", "bscscan.com": "bsc", "basescan.org": "base", "polygonscan.com": "polygon",
    "arbiscan.io": "arbitrum", "solscan.io": "solana", "snowtrace.io": "avalanche", "optimistic.etherscan.io": "optimism",
    "lineascan.build": "linea", "blastscan.io": "blast", "mantlescan.xyz": "mantle", "scrollscan.com": "scroll",
    "sonicscan.org": "sonic", "celoscan.io": "celo", "cronoscan.com": "cronos", "berascan.com": "berachain",
    "abscan.org": "abstract", "uniscan.xyz": "unichain", "era.zksync.network": "zksync", "ftmscan.com": "fantom",
    "opbnb.bscscan.com": "opbnb", "worldscan.org": "worldchain", "apescan.io": "apechain", "hyperevmscan.io": "hyperevm",
    "monadscan.com": "monad", "tronscan.org": "tron", "tonviewer.com": "ton", "tonscan.org": "ton",
    "suiscan.xyz": "sui", "suivision.xyz": "sui", "explorer.aptoslabs.com": "aptos", "starkscan.co": "starknet",
    "voyager.online": "starknet", "hashscan.io": "hedera", "nearblocks.io": "near", "explorer.multiversx.com": "multiversx",
    "xrpscan.com": "xrpl", "explorer.hiro.so": "stacks", "seitrace.com": "seiv2", "kavascan.com": "kava",
}
TOKEN_ID = r"[A-Za-z0-9:._\-]{2,200}"
PATTERNS = [  # (regex, chain or None, fallback) checked in order, most specific first
    (re.compile(r"0x[a-fA-F0-9]{1,64}::[A-Za-z_][A-Za-z0-9_]*::[A-Za-z_][A-Za-z0-9_]*"), None, "sui"),   # Move coin type: Sui/Aptos/Movement
    (re.compile(r"(?:factory/inj1[a-z0-9]{38}/[A-Za-z0-9]+|peggy0x[a-fA-F0-9]{40}|inj1[a-z0-9]{38})"), "injective", None),
    (re.compile(r"\b[a-z0-9]{5}-[a-z0-9]{5}-[a-z0-9]{5}-[a-z0-9]{5}-cai\b"), "icp", None),
    (re.compile(r"\bS[PM][0-9A-Z]{28,41}\.[A-Za-z0-9\-_]+"), "stacks", None),
    (re.compile(r"\b[A-Za-z0-9]{3,40}\.r[1-9A-HJ-NP-Za-km-z]{24,34}\b"), "xrpl", None),
    (re.compile(r"0x[a-fA-F0-9]{50,64}(?![a-fA-F0-9])"), None, "starknet"),
    (EVM, None, None),
    (re.compile(r"(?<![A-Za-z0-9_\-])(?:EQ|UQ)[A-Za-z0-9_\-]{46}(?![A-Za-z0-9_\-])"), "ton", None),
    (re.compile(r"\b0\.0\.\d{3,10}\b"), "hedera", None),
    (re.compile(r"\b[A-Z0-9]{3,10}-[a-f0-9]{6}\b"), "multiversx", None),
    (re.compile(r"\b(?:[a-z0-9_\-]+\.)+(?:near|tg)\b"), "near", None),
    (re.compile(r"\b[a-f0-9]{56}(?:[a-f0-9]{2,64})?\b"), "cardano", None),
]


def extract(text: str) -> dict:
    t = (text or "").strip()
    out = lambda a, c, pair=False, fb=None: {"address": a, "chain": c, "is_pair": pair, "fallback": fb}
    m = re.search(r"dexscreener\.com/([a-z0-9]+)/(" + TOKEN_ID + ")", t)
    if m and canon(m.group(1)) in NAMES:
        return out(m.group(2).rstrip("."), canon(m.group(1)), True)
    m = re.search(rf"pump\.fun/(?:coin/)?([{B58}]{{32,44}})", t)
    if m:
        return out(m.group(1), "solana")
    for host, chain in sorted(EXPLORERS.items(), key=lambda kv: -len(kv[0])):
        m = re.search(re.escape(host) + r"/(?:[#a-z/]*?)(?:token20|token|tokens|address|account|coin|jetton|asset|fungible|contract)/(" + TOKEN_ID + ")", t)
        if m:
            return out(m.group(1).rstrip("."), chain)
    for rx, chain, fb in PATTERNS:
        m = rx.search(t)
        if m:
            return out(m.group(0), chain, fb=fb)
    sols = [s for s in SOL.findall(t) if not s.isdigit()]
    if sols:
        sols.sort(key=lambda s: (not s.endswith("pump"), -len(s)))  # pump.fun mints end in 'pump'
        a = sols[0]
        if a.startswith("T") and len(a) == 34:  # Tron and Solana share base58: let DexScreener decide, Tron if unseen
            return out(a, None, fb="tron")
        return out(a, "solana")
    if re.fullmatch(r"\d{5,12}", t):
        return out(t, "algorand")  # a bare number is only ever an Algorand asset id
    return out(None, None)
