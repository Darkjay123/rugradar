import os, time, importlib
import pytest
from rugradar import store, tools, explain as ex, agent, memory
from rugradar.models import CheckRequest, Finding, Severity, Verdict, TokenFacts
from rugradar.scoring import assess
from rugradar.redact import redact, message_flags, contains_sensitive

ADDR = "0x" + "1" * 40
SEC = {"is_open_source": "1"}
PAIRS = [{"liquidity": {"usd": 500000}, "pairCreatedAt": 1, "baseToken": {}}]


@pytest.fixture(autouse=True)
def tmp_store(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "_DB", str(tmp_path / "s.sqlite"))
    monkeypatch.setattr(store, "_URL", None)
    for k in ("GEMINI_API_KEY", "FALLBACK_API_KEY", "RUGRADAR_AB"):
        monkeypatch.delenv(k, raising=False)


def test_allowlist_blocks_unknown_hosts():
    with pytest.raises(tools.NotAllowed):
        tools._get_json("https://evil.example.com/steal")
    with pytest.raises(tools.NotAllowed):
        tools._get_json("http://api.gopluslabs.io/x")  # https only


def test_redaction_keeps_addresses_strips_private_data():
    clean, kinds = redact(f"buy {ADDR} call 08129536338 or x@y.com")
    assert ADDR in clean and "8129536338" not in clean and "x@y.com" not in clean
    assert set(kinds) == {"phone", "email"}


def test_prompt_never_carries_addresses_or_pasted_text():
    f = [Finding(code="THIN_LIQUIDITY", severity=Severity.high, points=30, plain="The pool is small.")]
    prompt, _ = ex.build_prompt("small", Verdict.caution, f)
    assert not contains_sensitive(prompt)
    assert contains_sensitive(prompt + " " + ADDR)


def test_routing_small_vs_reasoning(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "k")
    mixed = [Finding(code=c, severity=Severity.medium, points=10, plain="x") for c in ("A", "B", "C")]
    assert ex.route(Verdict.caution, mixed, "en") == "small"
    hard = mixed + [Finding(code="SOURCES_DISAGREE", severity=Severity.medium, points=10, plain="x")]
    assert ex.route(Verdict.high, hard, "en") == "reasoning"
    assert ex.route(Verdict.high, hard, "pcm") == "template"
    assert ex.route(Verdict.low, [], "en") == "template"


def test_ab_split_is_deterministic_and_roughly_sized(monkeypatch):
    monkeypatch.setenv("RUGRADAR_AB", "challenger-model:20")
    arms = [ex.ab_arm(f"t{i}", "small")[1] for i in range(2000)]
    assert arms == [ex.ab_arm(f"t{i}", "small")[1] for i in range(2000)]
    assert 0.15 < arms.count("B") / len(arms) < 0.25
    assert ex.ab_arm("t1", "reasoning")[1] == "A"  # only the small route is experimented on


def _mixed():
    return [Finding(code=c, severity=Severity.medium, points=10, plain=f"Finding {c} is a concern.") for c in ("A", "B", "C")]


def test_fallback_model_when_primary_is_down(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "k"); monkeypatch.setenv("FALLBACK_API_KEY", "k")
    monkeypatch.setattr(ex, "_gemini", lambda *a: (_ for _ in ()).throw(RuntimeError("down")))
    monkeypatch.setattr(ex, "_fallback", lambda p, rt: ('{"summary": "Several warning signs here, so go slowly and only risk a little."}', 0.0001, "llama"))
    trace = []
    summary, by, cost = ex.explain(Verdict.caution, _mixed(), trace, "en", "t")
    assert by.startswith("llama") and [s.get("provider") for s in trace] == ["primary", "fallback"]


def test_all_models_down_degrades_to_template(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "k")
    monkeypatch.setattr(ex, "_gemini", lambda *a: (_ for _ in ()).throw(RuntimeError("down")))
    summary, by, _ = ex.explain(Verdict.caution, _mixed(), [], "en", "t")
    assert by == "template(fallback)" and summary


def test_guardrails_reject_unsafe_or_over_budget_output(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "k")
    monkeypatch.setattr(ex, "_gemini", lambda *a: ('{"summary": "This token is guaranteed safe to buy, go all in now."}', 0.0001))
    assert ex.explain(Verdict.caution, _mixed(), [], "en", "t")[1] == "template(fallback)"
    monkeypatch.setattr(ex, "_gemini", lambda *a: ('{"summary": "Several warning signs here, go slowly and carefully."}', 0.5))
    assert ex.explain(Verdict.caution, _mixed(), [], "en", "t")[1] == "template(fallback)"


def test_resume_skips_sources_that_already_answered(monkeypatch):
    calls = {"goplus": 0}
    def gp(*a):
        calls["goplus"] += 1
        return SEC
    monkeypatch.setattr(tools, "goplus_security", gp)
    monkeypatch.setattr(tools, "dexscreener_pairs", lambda *a: PAIRS)
    monkeypatch.setattr(tools, "honeypot_sim", lambda *a: None)
    monkeypatch.setattr(tools, "ngn_per_usd", lambda *a: 1500.0)
    monkeypatch.setattr(tools, "creator_check", lambda *a: None)
    req = CheckRequest(chain="bsc", address=ADDR)
    memory.start_run("crashed1", req.model_dump())
    memory.save_step("crashed1", "goplus", SEC)        # this source answered before the crash
    rep = agent.resume("crashed1")
    assert calls["goplus"] == 0 and rep.verdict == Verdict.low and rep.trace_id == "crashed1"


def test_time_budget_never_returns_low_risk_on_partial_evidence(monkeypatch):
    monkeypatch.setattr(agent, "RUN_BUDGET_S", 1.0)
    monkeypatch.setattr(tools, "goplus_security", lambda *a: SEC)
    monkeypatch.setattr(tools, "dexscreener_pairs", lambda *a: PAIRS)
    monkeypatch.setattr(tools, "honeypot_sim", lambda *a: time.sleep(3) or {"ok": True})
    monkeypatch.setattr(tools, "ngn_per_usd", lambda *a: 1500.0)
    monkeypatch.setattr(tools, "creator_check", lambda *a: None)
    rep = agent.check(CheckRequest(chain="bsc", address=ADDR))
    assert "honeypot_sim" in rep.timed_out and rep.verdict != Verdict.low and rep.latency_ms < 2500


def test_stream_yields_steps_then_one_report(monkeypatch):
    evs = list(agent.run(CheckRequest(chain="bsc", address=ADDR), sec=SEC, pairs=PAIRS, fx=1500.0, offline=True))
    assert evs[-1]["type"] == "report" and sum(e["type"] == "report" for e in evs) == 1


def test_memory_reports_change_and_feeds_rug_rule():
    memory.remember("bsc", ADDR, "LOW_RISK", 0, 100000, 500)
    prev = memory.last("bsc", ADDR)
    assert prev and prev["liquidity_usd"] == 100000
    f = TokenFacts(security=SEC, has_security_data=True, has_market_data=True, liquidity_usd=10000, pair_age_hours=900, previous=prev)
    v, _, findings, _ = assess(f, ADDR)
    assert v == Verdict.high and findings[0].code == "LIQUIDITY_PULLED"


def test_message_flags_never_change_the_token_verdict():
    a = agent.check(CheckRequest(chain="bsc", address=ADDR), sec=SEC, pairs=PAIRS, fx=1500.0, offline=True)
    b = agent.check(CheckRequest(chain="bsc", address=ADDR), sec=SEC, pairs=PAIRS, fx=1500.0, offline=True,
                    flags=message_flags("100x guaranteed, presale ends tonight"))
    assert (a.verdict, a.score) == (b.verdict, b.score) and b.message_flags


def test_store_outage_does_not_break_checks(monkeypatch):
    monkeypatch.setattr(store, "_DB", "/nonexistent/dir/x.sqlite")
    assert memory.last("bsc", ADDR) is None
    memory.remember("bsc", ADDR, "LOW_RISK", 0, 1, 1)  # must not raise


def test_saved_report_drops_private_fields_and_page_escapes():
    from rugradar import memory
    from rugradar.page import render
    rep = {"chain": "solana", "address": "So11111111111111111111111111111111111111112", "name": "<script>alert(1)</script>",
           "symbol": "EVIL", "verdict": "HIGH_RISK", "score": 90, "summary": "Do not buy.", "lang": "en",
           "findings": [{"code": "HONEYPOT", "severity": "critical", "points": 60, "plain": "You can't sell it."}],
           "money": {"amount_ngn": 50000, "get_back_ngn": 0, "note": "nothing"}, "sources": ["GoPlus"],
           "trace_id": "abc123def456", "checked_at": "2026-10-06T17:00:00Z",
           "message_flags": [{"code": "SEND_TO_RECEIVE"}], "removed": ["phone"], "cost_usd": 0.001, "route": "small"}
    memory.save_report("abc123def456", rep)
    got = memory.get_report("abc123def456")
    assert got and "message_flags" not in got and "removed" not in got and "cost_usd" not in got
    html = render(got, "https://x.test")
    assert "<script>alert(1)" not in html and "&lt;script&gt;" in html
    assert 'name="robots" content="noindex"' in html and "og:title" in html and "₦50,000" in html


def test_report_routes():
    from fastapi.testclient import TestClient
    from rugradar.api import app
    from rugradar import memory
    memory.save_report("feedbeef0001", {"chain": "bsc", "address": "0x" + "1" * 40, "verdict": "CAUTION", "score": 40,
                                         "summary": "s", "findings": [], "lang": "pcm", "trace_id": "feedbeef0001"})
    c = TestClient(app)
    assert c.get("/r/feedbeef0001").status_code == 200
    assert "Shine your eye" in c.get("/r/feedbeef0001").text
    assert c.get("/api/report/feedbeef0001").json()["score"] == 40
    assert c.get("/r/not-a-valid-id!").status_code == 404
    assert c.get("/api/report/000000000000").status_code == 404
