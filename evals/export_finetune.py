"""Build a fine-tuning set from our best production explanations.

Keeps only runs where a model wrote the summary, it passed every guardrail, and the user gave a thumbs-up.
Output is chat-format JSONL (works for Gemini tuning and OpenAI-compatible tuners). The goal is a small
tuned model that writes like our best outputs at a fraction of the cost. It needs a few hundred approved
examples before a tune is worth running, so this is the pipeline, waiting on traffic.

  python evals/export_finetune.py --local --out finetune.jsonl
"""
import argparse, json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from rugradar import store
from rugradar.explain import build_prompt
from rugradar.models import Finding, Severity, Verdict
from rugradar.i18n import T

ap = argparse.ArgumentParser(); ap.add_argument("--local", action="store_true"); ap.add_argument("--out", default="finetune.jsonl")
a = ap.parse_args()
n = 0
with open(a.out, "w") as out:
    for r in store.items("feedback", 5000):
        by = r.get("explained_by") or ""
        if r["vote"] != "up" or by.startswith("template") or not r.get("summary"):
            continue
        findings = [Finding(code=c, severity=Severity.medium, points=1, plain=T[c][0] if c in T else c) for c in r.get("codes") or []]
        rt = "reasoning" if "v2_hard" in by else "small"
        prompt, _ = build_prompt(rt, Verdict(r["got"]), findings)
        out.write(json.dumps({"messages": [{"role": "user", "content": prompt},
                                           {"role": "assistant", "content": json.dumps({"summary": r["summary"]})}]}) + "\n")
        n += 1
print(f"wrote {n} approved examples to {a.out}")
