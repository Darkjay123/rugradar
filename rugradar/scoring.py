"""Deterministic risk rules. The verdict never comes from a language model:
models only explain, rules decide. That keeps verdicts testable and un-injectable."""
from __future__ import annotations
from .models import Finding, Severity, TokenFacts, Verdict


def _flag(sec: dict, key: str) -> bool:
    return str(sec.get(key, "")).strip() == "1"


def _pct(v) -> float | None:
    try:
        return float(v) if v not in (None, "") else None
    except (TypeError, ValueError):
        return None


def assess(f: TokenFacts) -> tuple[Verdict, int, list[Finding]]:
    s, out = f.security, []

    def add(code, sev, pts, plain):
        out.append(Finding(code=code, severity=sev, points=pts, plain=plain))

    if not f.has_security_data and not f.has_market_data:
        return Verdict.unknown, 0, [Finding(code="NO_DATA", severity=Severity.info, points=0,
                                            plain="We couldn't find this token on this chain. Double-check the chain and address before you send money.")]

    # Critical: you can buy but can't get out
    if _flag(s, "is_honeypot"):
        add("HONEYPOT", Severity.critical, 100, "This looks like a honeypot: people can buy it but can't sell it.")
    if _flag(s, "cannot_sell_all"):
        add("CANNOT_SELL_ALL", Severity.critical, 60, "The contract stops holders from selling everything they own.")
    if _flag(s, "owner_change_balance"):
        add("OWNER_CHANGES_BALANCES", Severity.critical, 70, "The owner can change anyone's balance, including yours.")
    if _flag(s, "selfdestruct"):
        add("SELFDESTRUCT", Severity.critical, 60, "The contract can delete itself, which would wipe out the token.")

    sell, buy = f.sell_tax, f.buy_tax
    if sell is not None and sell >= 0.5:
        add("SELL_TAX_EXTREME", Severity.critical, 80, f"Selling costs {sell:.0%} in tax, so most of your money stays behind.")
    elif sell is not None and sell >= 0.1:
        add("SELL_TAX_HIGH", Severity.high, 30, f"Selling costs {sell:.0%} in tax, far above normal.")
    if buy is not None and buy >= 0.1:
        add("BUY_TAX_HIGH", Severity.high, 20, f"Buying costs {buy:.0%} in tax before you even start.")

    if str(s.get("is_open_source", "")) == "0":
        add("CLOSED_SOURCE", Severity.high, 35, "The code is not published, so nobody can check what it really does.")
    if _flag(s, "hidden_owner"):
        add("HIDDEN_OWNER", Severity.high, 40, "There is a hidden owner who can still control the contract.")
    if _flag(s, "can_take_back_ownership"):
        add("RECLAIM_OWNERSHIP", Severity.high, 35, "Ownership looks given up but can be taken back.")
    if _flag(s, "is_mintable") and s.get("owner_address") not in (None, "", "0x0000000000000000000000000000000000000000"):
        add("MINTABLE", Severity.medium, 15, "The owner can print new tokens, which can crash the price.")
    if _flag(s, "transfer_pausable"):
        add("PAUSABLE", Severity.medium, 15, "Trading can be paused by the owner at any time.")
    if _flag(s, "is_blacklisted"):
        add("BLACKLIST", Severity.medium, 15, "The owner can block specific wallets from trading.")
    if _flag(s, "slippage_modifiable"):
        add("TAX_CHANGEABLE", Severity.high, 25, "The owner can raise the tax later, even after you buy.")
    if _flag(s, "is_proxy"):
        add("UPGRADEABLE", Severity.info, 5, "The code can be upgraded, so it may behave differently tomorrow.")

    # Market reality
    if f.has_market_data:
        if f.liquidity_usd is not None and f.liquidity_usd < 10_000:
            add("THIN_LIQUIDITY", Severity.high, 30, f"Only about ${f.liquidity_usd:,.0f} is available to trade against, so selling even a little moves the price hard.")
        if f.pair_age_hours is not None and f.pair_age_hours < 72:
            add("BRAND_NEW", Severity.medium, 15, f"Trading only started about {f.pair_age_hours:.0f} hours ago. Most rug pulls happen in the first days.")
    elif f.has_security_data:
        add("NO_MARKET", Severity.high, 25, "We found no live trading pool, so you may not be able to sell at all.")

    holders = s.get("holders") or []
    top_unlocked = sum(_pct(h.get("percent")) or 0 for h in holders[:10]
                       if not h.get("is_locked") and h.get("address", "").lower() != "0x000000000000000000000000000000000000dead")
    if top_unlocked > 0.5:
        add("WHALE_CONCENTRATION", Severity.high, 25, f"The top 10 wallets hold about {top_unlocked:.0%} of the supply and could dump at once.")

    score = min(100, sum(x.points for x in out))
    if any(x.severity == Severity.critical for x in out) or score >= 60:
        v = Verdict.high
    elif score >= 25:
        v = Verdict.caution
    else:
        v = Verdict.low
    out.sort(key=lambda x: -x.points)
    return v, score, out
