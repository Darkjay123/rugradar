import pytest
from pydantic import ValidationError
from rugradar.models import CheckRequest, TokenFacts, Verdict
from rugradar.scoring import assess


def test_rejects_bad_address():
    with pytest.raises(ValidationError):
        CheckRequest(chain="bsc", address="0x123")


def test_rejects_unknown_chain():
    with pytest.raises(ValidationError):
        CheckRequest(chain="notachain", address="0x" + "a" * 40)


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


def test_rugcheck_read_is_credited_as_a_source():
    from rugradar import tools
    import inspect
    assert '_cached("rugcheck",' in inspect.getsource(tools.rugcheck)


def test_all_64_networks_are_supported():
    from rugradar.chains import NAMES, tier
    assert len(NAMES) == 64
    for c in ("ton", "sui", "tron", "near", "hedera", "xrpl", "cardano", "polkadot", "stepnetwork", "hyperliquid"):
        assert c in NAMES
    assert tier("solana") == "full" and tier("arbitrum") == "contract" and tier("ton") == "contract" and tier("stepnetwork") == "market"


def test_extracts_tokens_on_non_evm_networks():
    from rugradar.parse import extract
    assert extract("EQAmbbXQG6ECkRX2YmJwi8AzubLS9Sp-V6EUUNhNVEdWc2i-")["chain"] == "ton"
    assert extract("0x2::sui::SUI")["fallback"] == "sui"
    assert extract("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t")["fallback"] == "tron"
    sk = extract("0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d")
    assert sk["fallback"] == "starknet" and len(sk["address"]) == 66  # never cut down to a fake 40-hex EVM address
    assert extract("0.0.456858")["chain"] == "hedera"
    assert extract("https://dexscreener.com/hyperevm/0x5555555555555555555555555555555555555555")["chain"] == "hyperevm"
    assert extract("DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263")["chain"] == "solana"


def test_market_only_network_never_reads_low_risk():
    from rugradar.agent import build_facts
    from rugradar import scoring
    from rugradar.models import Verdict
    now = 1791309000000
    pairs = [{"pairAddress": "EQpool", "pairCreatedAt": now - 400 * 86_400_000, "liquidity": {"usd": 2_000_000},
              "txns": {"h24": {"buys": 900, "sells": 850}}, "priceChange": {"h24": 1.2}, "baseToken": {"symbol": "XYZ"}}]
    f = build_facts("ton", None, pairs, now)
    v, score, findings, _ = scoring.assess(f, "EQAmbbXQG6ECkRX2YmJwi8AzubLS9Sp-V6EUUNhNVEdWc2i-", "en")
    assert v == Verdict.caution and "CONTRACT_NOT_SCANNED" in [x.code for x in findings]


def test_buys_but_no_sells_flags_on_any_network():
    from rugradar.agent import build_facts
    from rugradar import scoring
    now = 1791309000000
    pairs = [{"pairAddress": "p", "pairCreatedAt": now - 5 * 3_600_000, "liquidity": {"usd": 40_000},
              "txns": {"h24": {"buys": 120, "sells": 0}}, "priceChange": {"h24": -85}, "baseToken": {"symbol": "XYZ"}}]
    f = build_facts("sui", None, pairs, now)
    codes = [x.code for x in scoring.assess(f, "0xabc::xyz::XYZ", "en")[2]]
    assert "NO_SELLS" in codes and "PRICE_CRASHED" in codes


def test_official_stablecoin_issuer_powers_are_not_a_scam_sign():
    from rugradar.agent import build_facts
    from rugradar import scoring
    from rugradar.models import Verdict
    now = 1791309000000
    pairs = [{"pairAddress": "p", "pairCreatedAt": now - 900 * 86_400_000, "liquidity": {"usd": 9_000_000}, "baseToken": {"symbol": "USDT"}}]
    sec = {"token_symbol": "USDT", "owner_change_balance": "1", "transfer_pausable": "1", "is_blacklisted": "1", "is_open_source": "1"}
    f = build_facts("tron", sec, pairs, now)
    v, _, findings, _ = scoring.assess(f, "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", "en")
    assert v == Verdict.low and "ISSUER_CONTROLLED" in [x.code for x in findings]
    # the same powers on a copy are still flagged
    v2, _, f2, _ = scoring.assess(f, "TXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", "en")
    assert v2 == Verdict.high and "IMPERSONATION" in [x.code for x in f2]


def test_64_hex_key_still_removed_but_token_links_survive():
    from rugradar.redact import redact
    k = "0x" + "ab" * 32
    assert k not in redact(f"my key {k}")[0]
    link = "https://dexscreener.com/starknet/0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d"
    assert link in redact(link)[0]
    assert ("0x" + "ab" * 32 + "::coin::COIN") in redact("0x" + "ab" * 32 + "::coin::COIN")[0]


def test_gemini_key_alias(monkeypatch):
    import importlib, rugradar
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setenv("Gemini_key", "abc123")
    importlib.reload(rugradar)
    import os
    assert os.environ["GEMINI_API_KEY"] == "abc123"


def test_native_powers_are_scored():
    from rugradar.agent import build_facts
    from rugradar import scoring
    pairs = [{"liquidity": {"usd": 50_000}, "pairCreatedAt": 0, "baseToken": {"symbol": "MEME"}}]
    sec = {"_source": "Hedera network", "owner_change_balance": "1", "is_mintable": "1", "owner_address": "0.0.123",
           "is_blacklisted": "1", "paused_now": "1"}
    f = build_facts("hedera", sec, pairs, 10 * 24 * 3600 * 1000)
    v, score, out, _ = scoring.assess(f, "0.0.999")
    codes = {x.code for x in out}
    assert v.value == "HIGH_RISK" and {"OWNER_CHANGES_BALANCES", "FROZEN_NOW", "MINTABLE"} <= codes
    assert "CONTRACT_NOT_SCANNED" not in codes


def test_real_stablecoin_on_new_network_is_not_a_fake():
    from rugradar.agent import build_facts
    from rugradar import scoring
    pairs = [{"liquidity": {"usd": 500_000}, "pairCreatedAt": 0, "baseToken": {"symbol": "USDC"}}]
    f = build_facts("hedera", {"is_mintable": "1", "owner_address": "0.0.1", "is_blacklisted": "1"}, pairs, 400 * 24 * 3600 * 1000)
    v, _, out, _ = scoring.assess(f, "0.0.456858")
    assert "IMPERSONATION" not in {x.code for x in out} and v.value == "LOW_RISK"


def test_orderbook_zero_liquidity_is_not_thin():
    from rugradar.agent import build_facts
    pairs = [{"liquidity": {"usd": 0}, "pairCreatedAt": 0, "baseToken": {"symbol": "PURR"}}]
    assert build_facts("hyperliquid", {"is_mintable": "0"}, pairs, 1).liquidity_usd is None
