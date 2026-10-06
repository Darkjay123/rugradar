"""Offline evals: replay recorded tool output + synthetic attack cases through the full agent path.
Scores the verdict AND the path (which findings fired, what the summary says).
Exits non-zero below threshold so CI blocks a regression."""
import json, os, sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
os.environ.pop("GEMINI_API_KEY", None)  # evals test rules + template, deterministically
os.environ["RUGRADAR_LOG"] = "/tmp/rugradar_eval_traces.jsonl"
from rugradar.agent import check
from rugradar.models import CheckRequest

HERE = pathlib.Path(__file__).parent
THRESHOLD = float(os.environ.get("EVAL_THRESHOLD", "1.0"))
DUMMY = "0x" + "1" * 40


def run_case(c):
    if "fixture" in c:
        fx = json.loads((HERE / "fixtures" / f"{c['fixture']}.json").read_text())
        req = CheckRequest(chain=fx["chain"], address=fx["address"])
        return check(req, sec=fx["sec"], pairs=fx["pairs"], now_ms=fx["recorded_at_ms"])
    s = c["synthetic"]
    now = 1_800_000_000_000
    pairs = [] if s["liquidity"] is None else [{"liquidity": {"usd": s["liquidity"]}, "pairCreatedAt": now - s["age_h"] * 3_600_000, "baseToken": {}}]
    return check(CheckRequest(chain="bsc", address=DUMMY), sec=s["sec"], pairs=pairs, now_ms=now)


def grade(c, rep):
    errs, codes, summ = [], {f.code for f in rep.findings}, rep.summary.lower()
    if "expect" in c and rep.verdict.value != c["expect"]:
        errs.append(f"verdict {rep.verdict.value} != {c['expect']}")
    if "expect_not" in c and rep.verdict.value == c["expect_not"]:
        errs.append(f"verdict must not be {c['expect_not']}")
    errs += [f"missing {x}" for x in c.get("must_include", []) if x not in codes]
    errs += [f"unexpected {x}" for x in c.get("must_exclude", []) if x in codes]
    errs += [f"summary contains '{x}'" for x in c.get("summary_must_not_contain", []) if x in summ]
    return errs


cases = [json.loads(l) for l in (HERE / "golden.jsonl").read_text().splitlines() if l.strip()]
passed = 0
for c in cases:
    rep = run_case(c)
    errs = grade(c, rep)
    passed += not errs
    print(f"{'PASS' if not errs else 'FAIL'}  {c['id']:<22} {rep.verdict.value:<10} {rep.score:>3}  {'; '.join(errs)}")
score = passed / len(cases)
print(f"\n{passed}/{len(cases)} passed ({score:.0%}), threshold {THRESHOLD:.0%}")
sys.exit(0 if score >= THRESHOLD else 1)
