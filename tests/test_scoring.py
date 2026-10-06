import pytest
from pydantic import ValidationError
from rugradar.models import CheckRequest, TokenFacts, Verdict
from rugradar.scoring import assess


def test_rejects_bad_address():
    with pytest.raises(ValidationError):
        CheckRequest(chain="bsc", address="0x123")


def test_rejects_unknown_chain():
    with pytest.raises(ValidationError):
        CheckRequest(chain="solana", address="0x" + "a" * 40)


def test_honeypot_is_high_even_with_good_market():
    f = TokenFacts(security={"is_honeypot": "1"}, has_security_data=True, has_market_data=True, liquidity_usd=1e6, pair_age_hours=5000)
    v, _, findings = assess(f)
    assert v == Verdict.high and findings[0].code == "HONEYPOT"


def test_clean_token_is_low():
    f = TokenFacts(security={"is_open_source": "1"}, has_security_data=True, has_market_data=True, liquidity_usd=5e5, pair_age_hours=5000)
    assert assess(f)[0] == Verdict.low
