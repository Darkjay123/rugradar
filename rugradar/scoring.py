"""Deterministic risk rules. The verdict never comes from a language model:
models only explain, rules decide. That keeps verdicts testable and un-injectable.

What each block borrows from the competitor research:
  honeypot / taxes / owner powers ...... GoPlus, Token Sniffer, De.Fi
  live test trade + stuck holders ...... Honeypot.is
  deployer history ..................... ChainAware (behaviour, not just code)
  LP lock, pool age, depth ............. DEXTools, De.Fi, DexScreener
  mint / freeze / balance authority .... RugCheck (Solana)
  fake copies of famous tokens ......... GoPlus trust list + our own official-address list
"""
from __future__ import annotations
from .models import Finding, Severity, TokenFacts, Verdict
from .i18n import t

DEAD = {"0x000000000000000000000000000000000000dead", "0x0000000000000000000000000000000000000000"}

# Real addresses of the tokens scammers copy most. A token using one of these symbols anywhere else is a fake.
OFFICIAL = {
    "ethereum": {"USDT": "0xdac17f958d2ee523a2206206994597c13d831ec7", "USDC": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
                 "WETH": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", "DAI": "0x6b175474e89094c44da98b954eedeac495271d0f",
                 "WBTC": "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599"},
    "bsc": {"USDT": "0x55d398326f99059ff775485246999027b3197955", "USDC": "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d",
            "WBNB": "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c", "ETH": "0x2170ed0880ac9a755fd29b2688956bd959f933f8",
            "BTCB": "0x7130d2a12b9bcbfae4f2634d864a1ee1ce3ead9c"},
    "base": {"USDC": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", "WETH": "0x4200000000000000000000000000000000000006"},
    "polygon": {"USDC": "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359", "USDT": "0xc2132d05d31c914a87c6611c10748aeb04b58e8f"},
    "arbitrum": {"USDC": "0xaf88d065e77c8cc2239327c5edb3a432268e5831", "USDT": "0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9"},
    "solana": {"USDC": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "USDT": "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB",
               "SOL": "So11111111111111111111111111111111111111112"},
}
COPIED = {"USDT", "USDC", "WETH", "WBNB", "DAI", "WBTC", "BTCB", "ETH", "BTC", "BNB", "SOL"}
CREATOR_FLAGS = {"phishing_activities": "phishing", "stealing_attack": "stealing funds", "honeypot_related_address": "honeypot scams",
                 "cybercrime": "cybercrime", "money_laundering": "money laundering", "sanctioned": "sanctions",
                 "fake_token": "fake tokens", "financial_crime": "financial crime", "blackmail_activities": "blackmail"}


def _flag(d: dict, key: str) -> bool:
    return str((d or {}).get(key, "")).strip() == "1"


def _status(d: dict, key: str) -> bool:
    v = (d or {}).get(key)
    return isinstance(v, dict) and str(v.get("status")) == "1"


def _pct(v) -> float | None:
    try:
        return float(v) if v not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _money_ngn(usd: float, rate: float | None) -> str:
    if rate:
        n = usd * rate
        return f"₦{n/1e6:,.1f} million" if n >= 1e6 else f"₦{n:,.0f}"
    return f"${usd:,.0f}"


def assess(f: TokenFacts, address: str = "", lang: str = "en") -> tuple[Verdict, int, list[Finding], TokenFacts]:
    s, out = f.security, []
    young = f.pair_age_hours is None or f.pair_age_hours < 24 * 30

    def add(code, sev, pts, key=None, **kw):
        out.append(Finding(code=code, severity=sev, points=pts, plain=t(key or code, lang, **kw)))

    if not f.has_security_data and not f.has_market_data:
        return Verdict.unknown, 0, [Finding(code="NO_DATA", severity=Severity.info, points=0, plain=t("NO_DATA", lang))], f

    # --- Fake copies of famous tokens (checked first: the most common newcomer trap)
    sym = (f.symbol or "").strip().upper()
    official = OFFICIAL.get(f.chain, {})
    addr_cmp = address if f.chain == "solana" else address.lower()
    if sym in COPIED and official.get(sym) != addr_cmp and str(s.get("trust_list")) != "1":
        add("IMPERSONATION", Severity.critical, 90, sym=sym)
    if str(s.get("trust_list")) == "1" or str(s.get("trusted_token")) == "1":
        add("TRUSTED", Severity.info, 0)

    # --- Can you get out? Two independent sources: static scan + live simulation
    sim = f.sim or {}
    static_hp, sim_hp = _flag(s, "is_honeypot"), bool(sim.get("is_honeypot"))
    if static_hp or sim_hp:
        add("HONEYPOT", Severity.critical, 100, how=t("HOW_SIM" if sim_hp else "HOW_CODE", lang))
    if sim.get("ok") and static_hp != sim_hp:
        add("SOURCES_DISAGREE", Severity.medium, 10)
    tested, failed = sim.get("holders_tested") or 0, (sim.get("holders_failed") or 0) + (sim.get("holders_siphoned") or 0)
    if tested >= 10 and failed / tested >= 0.1:
        add("HOLDERS_STUCK", Severity.critical, 70, failed=failed, n=tested)
    for k, attr in (("sell_tax", "sell_tax"), ("buy_tax", "buy_tax")):
        v = _pct(sim.get(k))
        if v is not None and (getattr(f, attr) is None or v / 100 > getattr(f, attr)):
            f = f.model_copy(update={attr: v / 100})

    if _flag(s, "cannot_sell_all"):
        add("CANNOT_SELL_ALL", Severity.critical, 60)
    if _flag(s, "owner_change_balance"):
        add("OWNER_CHANGES_BALANCES", Severity.critical, 70)
    if _flag(s, "selfdestruct"):
        add("SELFDESTRUCT", Severity.critical, 60)

    sell, buy = f.sell_tax, f.buy_tax
    if sell is not None and sell >= 0.5:
        add("SELL_TAX_EXTREME", Severity.critical, 80, pct=f"{sell:.0%}")
    elif sell is not None and sell >= 0.1:
        add("SELL_TAX_HIGH", Severity.high, 30, pct=f"{sell:.0%}")
    if buy is not None and buy >= 0.1:
        add("BUY_TAX_HIGH", Severity.high, 20, pct=f"{buy:.0%}")

    # --- EVM owner powers
    if f.chain != "solana":
        if str(s.get("is_open_source", "")) == "0":
            add("CLOSED_SOURCE", Severity.high, 35)
        if _flag(s, "hidden_owner"):
            add("HIDDEN_OWNER", Severity.high, 40)
        if _flag(s, "can_take_back_ownership"):
            add("RECLAIM_OWNERSHIP", Severity.high, 35)
        if _flag(s, "is_mintable") and s.get("owner_address") not in (None, "", *DEAD):
            add("MINTABLE", Severity.medium, 15)
        if _flag(s, "transfer_pausable"):
            add("PAUSABLE", Severity.medium, 15)
        if _flag(s, "is_blacklisted"):
            add("BLACKLIST", Severity.medium, 15)
        if _flag(s, "slippage_modifiable"):
            add("TAX_CHANGEABLE", Severity.high, 25)
        if _flag(s, "is_proxy"):
            add("UPGRADEABLE", Severity.info, 5)

    # --- Solana authorities (RugCheck-style)
    else:
        if _status(s, "mintable"):
            add("SOL_MINT_AUTHORITY", Severity.high, 35)
        if _status(s, "freezable"):
            add("SOL_FREEZE", Severity.critical, 60)
        if _status(s, "balance_mutable_authority"):
            add("SOL_BALANCE_MUTABLE", Severity.critical, 70)
        if _status(s, "closable"):
            add("SOL_CLOSABLE", Severity.high, 30)
        if str(s.get("non_transferable")) == "1":
            add("SOL_NON_TRANSFERABLE", Severity.critical, 80)
        if s.get("transfer_hook"):
            add("SOL_TRANSFER_HOOK", Severity.medium, 15)
        fee = _pct(((s.get("transfer_fee") or {}).get("current_fee_rate") or {}).get("fee_rate")) if isinstance(s.get("transfer_fee"), dict) else None
        if fee is not None:
            fee = fee / 10000 if fee > 1 else fee  # basis points -> fraction
            if fee >= 0.1:
                add("SELL_TAX_HIGH", Severity.high, 30, pct=f"{fee:.0%}")
        if _status(s, "metadata_mutable"):
            add("SOL_METADATA_MUTABLE", Severity.info, 5)
        rc = f.rugcheck or {}
        danger = [r["name"] for r in rc.get("risks", []) if r.get("level") == "danger" and r.get("name")]
        if danger:
            add("RUGCHECK_DANGER", Severity.high, 25, what=", ".join(danger[:3]).lower())

    # --- Who's behind it (ChainAware-style behaviour check)
    if _flag(s, "honeypot_with_same_creator") or int(_pct((f.creator or {}).get("number_of_malicious_contracts_created")) or 0) > 0:
        add("SCAMMER_DEPLOYER", Severity.critical, 80)
    flagged = [label for k, label in CREATOR_FLAGS.items() if _flag(f.creator or {}, k)]
    if flagged:
        add("CREATOR_FLAGGED", Severity.critical, 70, what=", ".join(flagged[:3]))
    cp = _pct(s.get("creator_percent"))
    if cp is not None and cp >= 0.2 and young:
        add("CREATOR_HOLDS_LOTS", Severity.high, 20, pct=f"{cp:.0%}")

    # --- Market reality
    if f.has_market_data:
        if f.liquidity_usd is not None and f.liquidity_usd < 10_000:
            add("THIN_LIQUIDITY", Severity.high, 30, money=_money_ngn(f.liquidity_usd, f.ngn_per_usd))
        if f.pair_age_hours is not None and f.pair_age_hours < 72:
            add("BRAND_NEW", Severity.medium, 15, h=f"{f.pair_age_hours:.0f}")
    elif f.has_security_data:
        add("NO_MARKET", Severity.high, 25)

    # Rug-pull classic: pool money not locked on a young token
    if young and f.has_market_data:
        lp = s.get("lp_holders") or []
        if lp:
            unlocked = sum(_pct(h.get("percent")) or 0 for h in lp
                           if not h.get("is_locked") and (h.get("address") or "").lower() not in DEAD)
            if unlocked > 0.5:
                add("LP_UNLOCKED", Severity.high, 30)
        elif f.chain == "solana" and (f.rugcheck or {}).get("lp_locked_pct") is not None and f.rugcheck["lp_locked_pct"] < 50:
            add("LP_UNLOCKED", Severity.high, 30)

    holders = s.get("holders") or []
    top_unlocked = sum(_pct(h.get("percent")) or 0 for h in holders[:10]
                       if not h.get("is_locked") and (h.get("address") or h.get("account") or "").lower() not in DEAD)
    if top_unlocked > 0.5 and (f.chain != "solana" or young):
        add("WHALE_CONCENTRATION", Severity.high, 25, pct=f"{top_unlocked:.0%}")

    if sim.get("ok") and not sim_hp and (f.sell_tax or 0) < 0.1 and not any(x.code == "HOLDERS_STUCK" for x in out):
        add("TEST_SALE_OK", Severity.info, 0)

    score = min(100, sum(x.points for x in out))
    if any(x.severity == Severity.critical for x in out) or score >= 60:
        v = Verdict.high
    elif score >= 25:
        v = Verdict.caution
    else:
        v = Verdict.low
    out.sort(key=lambda x: -x.points)
    return v, score, out, f
