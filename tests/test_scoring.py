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
    f = TokenFacts(chain="solana", has_market_data=True, has_security_data=True, liquidity_usd=50_000, pair_age_hours=2000,
                   rugcheck=rc, pool_tokens=10_000_000, supply=100_000_000)
    v, s, out, _ = assess(f, "x")
    assert any(f2.code == "WHALE_EXIT" for f2 in out)
    v, s, out, _ = assess(f.model_copy(update={"pool_tokens": None}), "x")
    assert not any(f2.code == "WHALE_EXIT" for f2 in out)
