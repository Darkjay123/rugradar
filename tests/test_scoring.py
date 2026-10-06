import pytest
from pydantic import ValidationError
from rugradar.models import CheckRequest, TokenFacts, Verdict
from rugradar.scoring import assess


def test_rejects_bad_address():
    with pytest.raises(ValidationError):
        CheckRequest(chain="bsc", address="0x123")


def test_rejects_unknown_chain():
    with pytest.raises(ValidationError):
        CheckRequest(chain="tron", address="0x" + "a" * 40)


def test_solana_address_keeps_case():
    r = CheckRequest(chain="solana", address="DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263")
    assert r.address == "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263"


def test_honeypot_is_high_even_with_good_market():
    f = TokenFacts(security={"is_honeypot": "1"}, has_security_data=True, has_market_data=True, liquidity_usd=1e6, pair_age_hours=5000)
    v, _, findings, _ = assess(f, "0x" + "1" * 40)
    assert v == Verdict.high and findings[0].code == "HONEYPOT"


def test_clean_token_is_low():
    f = TokenFacts(security={"is_open_source": "1"}, has_security_data=True, has_market_data=True, liquidity_usd=5e5, pair_age_hours=5000)
    assert assess(f, "0x" + "1" * 40)[0] == Verdict.low


def test_pidgin_never_changes_verdict():
    f = TokenFacts(security={"is_open_source": "0"}, has_security_data=True, has_market_data=True, liquidity_usd=5e3, pair_age_hours=5)
    en, pcm = assess(f, "0x" + "1" * 40, "en"), assess(f, "0x" + "1" * 40, "pcm")
    assert en[0] == pcm[0] and en[1] == pcm[1] and en[2][0].plain != pcm[2][0].plain


def test_thin_exit_and_no_sell_route_from_live_quote():
    from rugradar.models import TokenFacts
    from rugradar.scoring import assess
    base = dict(chain="solana", has_market_data=True, has_security_data=True, liquidity_usd=50_000, pair_age_hours=2000)
    v, s, out, _ = assess(TokenFacts(**base, exit={"ratio": 0.8, "sell_route": True, "ngn": 50000}), "x")
    assert any(f.code == "THIN_EXIT" and f.severity.value == "high" for f in out)
    v, s, out, _ = assess(TokenFacts(**base, exit={"ratio": 0.0, "sell_route": False, "ngn": 50000}), "x")
    assert any(f.code == "NO_SELL_ROUTE" for f in out)
    v, s, out, _ = assess(TokenFacts(**base, exit={"ratio": 0.99, "sell_route": True, "ngn": 50000}), "x")
    assert not any(f.code in ("THIN_EXIT", "NO_SELL_ROUTE") for f in out)


def test_whale_exit_estimate_needs_real_pool_numbers():
    from rugradar.models import TokenFacts
    from rugradar.scoring import assess
    rc = {"top_wallet_pct": 0.3, "risks": []}
    f = TokenFacts(chain="solana", has_market_data=True, has_security_data=True, liquidity_usd=50_000, pair_age_hours=100,
                   rugcheck=rc, pool_tokens=10_000_000, supply=100_000_000)
    v, s, out, _ = assess(f, "x")
    assert any(f2.code == "WHALE_EXIT" for f2 in out)
    v, s, out, _ = assess(f.model_copy(update={"pool_tokens": None}), "x")
    assert not any(f2.code == "WHALE_EXIT" for f2 in out)
    assert not any(f2.code == "WHALE_EXIT" for f2 in assess(f.model_copy(update={"pair_age_hours": 5000}), "x")[2])  # old tokens: exchange wallets, many pools


def test_graduated_pumpfun_token_is_not_new_and_pools_are_not_whales():
    """Alpenglow, 6 Oct 2026: old pump.fun token that just moved to PumpSwap. GoPlus still listed the old
    bonding curve as a 66% holder, so it read as 'top 10 hold 94%' and 'trading started 3 minutes ago'."""
    from rugradar.agent import build_facts
    from rugradar import scoring
    now = 1791309000000
    pairs = [{"pairAddress": "DZwSnciSb5Vat6HgyzCPhLszmAtvC9giS1s1CpM6mAUg", "dexId": "pumpswap", "pairCreatedAt": now - 3 * 60_000,
              "liquidity": {"usd": 11224, "base": 321860120}, "fdv": 20744, "priceUsd": "0.0000207",
              "baseToken": {"name": "Alpenglow", "symbol": "ALPENGLOW"}},
             {"pairAddress": "6SbqxApnTaVS73ZnKRULwWRYcdf7RKf6maaJEiyXjszC", "dexId": "pumpfun", "pairCreatedAt": 1747670197000}]
    sec = {"holder_count": "54", "holders": [{"account": "6SbqxApnTaVS73ZnKRULwWRYcdf7RKf6maaJEiyXjszC", "percent": "0.6653"}] +
           [{"account": f"W{i}", "percent": "0.03"} for i in range(9)]}
    f = build_facts("solana", sec, pairs, now)
    assert f.pair_age_hours > 24 * 365
    _, _, findings, _ = scoring.assess(f, "DNq98kymaw7GxhvLDTtrpUTBzi3L2KvnSedutZMyVhbm", "en")
    codes = [x.code for x in findings]
    assert "BRAND_NEW" not in codes and "WHALE_CONCENTRATION" not in codes, codes
    # RugCheck's pool-excluded top 10 wins when present
    f2 = build_facts("solana", sec, pairs[:1], now, rc={"top10_pct": 0.72, "pools": ["6SbqxApnTaVS73ZnKRULwWRYcdf7RKf6maaJEiyXjszC"]})
    _, _, findings2, _ = scoring.assess(f2, "DNq98kymaw7GxhvLDTtrpUTBzi3L2KvnSedutZMyVhbm", "en")
    assert "WHALE_CONCENTRATION" in [x.code for x in findings2]
