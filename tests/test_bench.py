import os, time
os.environ["RUGRADAR_STORE"] = "/tmp/rugradar_bench_test.sqlite"
from rugradar import bench, store


def test_outcome_rules():
    rec = {"liq0": 20_000, "price0": 1.0}
    assert bench.outcome(rec, None) == "rugged"
    assert bench.outcome(rec, {"liquidity": {"usd": 900}, "priceUsd": "0.9"}) == "rugged"
    assert bench.outcome(rec, {"liquidity": {"usd": 15_000}, "priceUsd": "0.05"}) == "dumped"
    assert bench.outcome(rec, {"liquidity": {"usd": 15_000}, "priceUsd": "0.8"}) == "alive"
    assert bench.outcome(rec, {"liquidity": {"usd": 15_000}, "priceUsd": "0.8"}, rugcheck_rugged=True) == "rugged"


def test_stats_math(monkeypatch):
    if os.path.exists(store._DB):
        os.remove(store._DB)
    rows = [("HIGH_RISK", "rugged"), ("HIGH_RISK", "alive"), ("CAUTION", "dumped"), ("LOW_RISK", "rugged"),
            ("LOW_RISK", "alive"), ("LOW_RISK", None)]
    for i, (v, o) in enumerate(rows):
        k = f"bench:solana:T{i}"
        store.put(k, {"chain": "solana", "addr": f"T{i}", "ts": 0, "verdict": v, "outcome": o, "liq0": 1, "price0": 1})
        store.push(bench.INDEX, k)
    s = bench.stats()
    assert s["resolved"] == 5 and s["waiting_24h"] == 1 and s["went_bad"] == 3
    assert s["caught_at_launch_pct"] == 66.7          # HIGH + CAUTION caught 2 of the 3 that went bad
    assert s["high_risk_that_went_bad_pct"] == 50.0
    assert s["healthy_called_high_risk_pct"] == 50.0
