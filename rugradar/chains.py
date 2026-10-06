"""Every network DexScreener lists (64). What we can read differs by network, and the report says so:

  full       contract scan + a second independent check (Solana: RugCheck + Jupiter sell quote;
             Ethereum/BNB/Base: Honeypot.is live test trade)
  contract   GoPlus contract scan + market data
  market     market data only (DexScreener: pools, liquidity, age, buys vs sells, price).
             The contract can't be read on these networks, so a check there can never come back
             'Low risk': at best 'Be careful', with the reason stated.
"""
from __future__ import annotations
import re

# key (= DexScreener chainId), display name, GoPlus id or None, address family
_R = [
    ("solana", "Solana", "solana", "solana"), ("robinhood", "Robinhood", "4663", "evm"), ("bsc", "BNB Chain", "56", "evm"),
    ("ethereum", "Ethereum", "1", "evm"), ("base", "Base", "8453", "evm"), ("polygon", "Polygon", "137", "evm"),
    ("pulsechain", "PulseChain", None, "evm"), ("arc", "Arc", "5042", "evm"), ("near", "NEAR", None, "other"),
    ("ton", "TON", None, "other"), ("cronos", "Cronos", "25", "evm"), ("sui", "Sui", None, "other"),
    ("avalanche", "Avalanche", "43114", "evm"), ("hyperevm", "HyperEVM", None, "evm"), ("monad", "Monad", "143", "evm"),
    ("arbitrum", "Arbitrum", "42161", "evm"), ("xrpl", "XRPL", None, "other"), ("ink", "Ink", None, "evm"),
    ("sonic", "Sonic", "146", "evm"), ("hyperliquid", "Hyperliquid", None, "other"), ("worldchain", "World Chain", "480", "evm"),
    ("tron", "Tron", "tron", "other"), ("hedera", "Hedera", None, "other"), ("abstract", "Abstract", "2741", "evm"),
    ("multiversx", "MultiversX", None, "other"), ("optimism", "Optimism", "10", "evm"), ("stable", "Stable", "988", "evm"),
    ("cardano", "Cardano", None, "other"), ("starknet", "Starknet", None, "other"), ("icp", "ICP", None, "other"),
    ("plasma", "Plasma", "9745", "evm"), ("aptos", "Aptos", None, "other"), ("seiv2", "Sei V2", None, "other"),
    ("megaeth", "MegaETH", None, "evm"), ("linea", "Linea", "59144", "evm"), ("algorand", "Algorand", None, "other"),
    ("mantle", "Mantle", "5000", "evm"), ("blast", "Blast", "81457", "evm"), ("berachain", "Berachain", "80094", "evm"),
    ("opbnb", "opBNB", "204", "evm"), ("zksync", "zkSync", "324", "evm"), ("apechain", "ApeChain", None, "evm"),
    ("fantom", "Fantom", None, "evm"), ("metis", "Metis", None, "evm"), ("stacks", "Stacks", None, "other"),
    ("injective", "Injective", None, "other"), ("unichain", "Unichain", "130", "evm"), ("celo", "Celo", None, "evm"),
    ("beam", "Beam", None, "evm"), ("soneium", "Soneium", "1868", "evm"), ("conflux", "Conflux", "1030", "evm"),
    ("flowevm", "Flow EVM", None, "evm"), ("merlinchain", "Merlin Chain", "4200", "evm"), ("scroll", "Scroll", "534352", "evm"),
    ("kava", "Kava", None, "evm"), ("katana", "Katana", None, "evm"), ("flare", "Flare", None, "evm"),
    ("fuse", "Fuse", None, "evm"), ("story", "Story", "1514", "evm"), ("movement", "Movement", None, "other"),
    ("manta", "Manta", "169", "evm"), ("telos", "Telos", None, "evm"), ("polkadot", "Polkadot", None, "other"),
    ("stepnetwork", "Step Network", None, "evm"),
]
NAMES = {k: n for k, n, _, _ in _R}
GOPLUS = {k: g for k, _, g, _ in _R if g}
FAMILY = {k: f for k, _, _, f in _R}
HONEYPOT = {"ethereum": "1", "bsc": "56", "base": "8453"}
ALIASES = {"eth": "ethereum", "bnb": "bsc", "binance": "bsc", "avax": "avalanche", "arb": "arbitrum", "matic": "polygon",
           "sei": "seiv2", "op": "optimism", "zk": "zksync", "world": "worldchain", "flow": "flowevm", "merlin": "merlinchain"}
EVM_ADDR = re.compile(r"^0x[a-fA-F0-9]{40}$")
SOL_ADDR = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")
ANY_ADDR = re.compile(r"^[A-Za-z0-9:._\-/]{1,200}$")


def canon(chain: str | None) -> str | None:
    c = (chain or "").lower().strip().replace(" ", "")
    return ALIASES.get(c, c) or None


def tier(chain: str) -> str:
    if chain == "solana" or chain in HONEYPOT:
        return "full"
    return "contract" if chain in GOPLUS else "market"


def norm(chain: str, address: str) -> str:
    """Only plain 0x EVM addresses are case-insensitive; everything else (Solana, Tron, TON, Sui types...) keeps its case."""
    a = address.strip()
    return a.lower() if EVM_ADDR.match(a) else a


def coverage_doc() -> str:
    rows = {"full": [], "contract": [], "market": []}
    for k, n, _, _ in _R:
        rows[tier(k)].append(n)
    return "\n".join(f"- {t}: {', '.join(v)}" for t, v in rows.items())
