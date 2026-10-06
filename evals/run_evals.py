"""Offline evals: replay recorded tool output + synthetic attack cases through the full agent path.
Scores the verdict AND the path (which findings fired, what the summary and money line say).
Exits non-zero below threshold so CI blocks a regression."""
import json, os, sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
os.environ.pop("GEMINI_API_KEY", None)  # evals test rules + templates, deterministically
os.environ["RUGRADAR_LOG"] = "/tmp/rugradar_eval_traces.jsonl"
from rugradar.agent import check
from rugradar.models import CheckRequest
from rugradar import parse
from rugradar.redact import message_flags, redact

HERE = pathlib.Path(__file__).parent
THRESHOLD = float(os.environ.get("EVAL_THRESHOLD", "1.0"))
DUMMY = {"solana": "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"}
NOW = 1_800_000_000_000


def run_case(c):
    lang = c.get("lang", "en")
    if "fixture" in c:
        fx = json.loads((HERE / "fixtures" / f"{c['fixture']}.json").read_text())
        req = CheckRequest(chain=fx["chain"], address=fx["address"], lang=lang)
        return check(req, sec=fx["sec"], pairs=fx["pairs"], sim=fx.get("sim"), rc=fx.get("rc"), creator=fx.get("creator"),
                     fx=1500.0, now_ms=fx["recorded_at_ms"], offline=True)
    s = c["synthetic"]
    chain = s.get("chain", "bsc")
    addr = s.get("address") or DUMMY.get(chain, "0x" + "1" * 40)
    pairs = [] if s["liquidity"] is None else [{"liquidity": {"usd": s["liquidity"]}, "pairCreatedAt": NOW - s["age_h"] * 3_600_000, "baseToken": {}}]
    return check(CheckRequest(chain=chain, address=addr, lang=lang), sec=s["sec"], pairs=pairs, sim=s.get("sim"),
                 creator=s.get("creator"), rc=s.get("rc"), fx=1500.0, now_ms=NOW, offline=True,
                 previous=s.get("previous"))


def grade(c, rep):
    errs, codes, summ = [], {f.code for f in rep.findings}, rep.summary.lower()
    if "expect" in c and rep.verdict.value != c["expect"]:
        errs.append(f"verdict {rep.verdict.value} != {c['expect']}")
    if "expect_not" in c and rep.verdict.value == c["expect_not"]:
        errs.append(f"verdict must not be {c['expect_not']}")
    errs += [f"missing {x}" for x in c.get("must_include", []) if x not in codes]
    errs += [f"unexpected {x}" for x in c.get("must_exclude", []) if x in codes]
    errs += [f"summary contains '{x}'" for x in c.get("summary_must_not_contain", []) if x in summ]
    errs += [f"summary lacks '{x}'" for x in c.get("summary_must_contain", []) if x not in summ]
    if "money_back" in c and (rep.money is None or rep.money.get_back_ngn != c["money_back"]):
        errs.append(f"money {rep.money.get_back_ngn if rep.money else None} != {c['money_back']}")
    return errs


def run_message(c):
    """Pitch scanning + redaction: flags must fire, private data must never survive into what we store."""
    codes = {f["code"] for f in message_flags(c["message"])}
    clean, removed = redact(c["message"])
    errs = [f"missing flag {x}" for x in c.get("expect_flags", []) if x not in codes]
    errs += [f"unexpected flag {x}" for x in c.get("no_flags", []) if x in codes]
    errs += [f"leaked '{x}'" for x in c.get("must_strip", []) if x in clean]
    errs += [f"lost '{x}'" for x in c.get("must_keep", []) if x not in clean]
    return errs


def run_parse(c):
    got = parse.extract(c["text"])
    errs = [f"{k}={got.get(k)!r} != {v!r}" for k, v in c["expect_parse"].items() if got.get(k) != v]
    return errs


cases = [json.loads(l) for l in (HERE / "golden.jsonl").read_text().splitlines() if l.strip()]
passed = 0
for c in cases:
    if "expect_parse" in c:
        errs, tag = run_parse(c), "parse"
    elif "message" in c:
        errs, tag = run_message(c), "message"
    else:
        rep = run_case(c)
        errs, tag = grade(c, rep), f"{rep.verdict.value:<10} {rep.score:>3}"
    passed += not errs
    print(f"{'PASS' if not errs else 'FAIL'}  {c['id']:<26} {tag}  {'; '.join(errs)}")
score = passed / len(cases)
print(f"\n{passed}/{len(cases)} passed ({score:.0%}), threshold {THRESHOLD:.0%}")
sys.exit(0 if score >= THRESHOLD else 1)
