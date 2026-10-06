import os, time
os.environ["RUGRADAR_STORE"] = "/tmp/rugradar_watch_test.sqlite"
from rugradar import watch, store


def rep(verdict="LOW_RISK", score=5, liq=50_000, creator=0.10, codes=()):
    return {"chain": "solana", "address": "Mint111", "name": "Test", "symbol": "TST", "chain_name": "Solana",
            "verdict": verdict, "score": score, "share_url": "https://x/r/1",
            "findings": [{"code": c, "points": 30} for c in codes],
            "market": {"liquidity_usd": liq, "creator_pct": creator}}


def fresh():
    if os.path.exists(store._DB):
        os.remove(store._DB)


def test_quiet_when_nothing_changed():
    assert watch.changes(watch.snapshot(rep()), watch.snapshot(rep())) == []


def test_pool_pulled_creator_dump_and_worse_verdict_all_alert():
    d = watch.changes(watch.snapshot(rep()), watch.snapshot(rep("HIGH_RISK", 80, liq=4_000, creator=0.01, codes=["SOME_STUCK"])))
    text = " | ".join(d)
    assert "HIGH RISK" in text and "Pool money fell 92%" in text and "creator sold" in text and "test sale just failed" in text


def test_add_list_remove_and_per_chat_cap():
    fresh()
    assert "Watching" in watch.add(1, rep())
    assert "Test" in watch.listing(1)
    assert "Stopped watching 1" in watch.remove(1, "Mint111")
    assert "not watching" in watch.listing(1)
    for i in range(watch.PER_CHAT):
        watch.add(1, dict(rep(), address=f"M{i}"))
    assert "already watching" in watch.add(1, dict(rep(), address="one-too-many"))


def test_sweep_alerts_once_then_stays_quiet_and_skips_failed_checks():
    fresh()
    watch.add(7, rep())
    sent = []
    r = watch.run(lambda c, a: rep("HIGH_RISK", 90, liq=1_000), lambda chat, t: sent.append((chat, t)))
    assert r["ran"] and r["alerts"] == 1 and sent[0][0] == 7 and "Pool money fell" in sent[0][1]
    assert watch.run(lambda c, a: rep(), lambda *a: None)["ran"] is False      # lock: one sweep per 10 minutes
    store.put("watch:lock", 0, ttl=1); time.sleep(1.1)
    n = len(sent)
    watch.run(lambda c, a: {"verdict": "UNKNOWN"}, lambda chat, t: sent.append(t))
    assert len(sent) == n                                                     # a failed check never alerts


def test_watches_expire():
    fresh()
    watch.add(9, rep())
    r = watch.run(lambda c, a: rep(), lambda *a: None, now=time.time() + watch.EXPIRE_S + 5)
    assert r["watching"] == 0
