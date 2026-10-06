"""Turn every thumbs-down into an eval case.

Each feedback row carries the exact source outputs of that run, so the failure replays offline forever.
New cases land in evals/candidates.jsonl with status "needs_label": a human confirms the right verdict,
then moves the line into golden.jsonl. Nothing auto-edits the golden set (a wrong label would teach the wrong rule).

  ADMIN_TOKEN=... python evals/promote_feedback.py --url https://rugradar-dun.vercel.app
  python evals/promote_feedback.py --local          # read the local store
"""
import argparse, json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import httpx

HERE = pathlib.Path(__file__).parent
ap = argparse.ArgumentParser()
ap.add_argument("--url"); ap.add_argument("--local", action="store_true"); ap.add_argument("--token")
a = ap.parse_args()
if a.local:
    from rugradar import store
    rows = store.items("feedback", 5000)
else:
    import os
    tok = a.token or os.environ["ADMIN_TOKEN"]
    rows = httpx.get(f"{a.url}/api/feedback/export", headers={"Authorization": f"Bearer {tok}"}, timeout=30).json()

existing = {json.loads(l)["id"] for f in ("golden.jsonl", "candidates.jsonl") if (HERE / f).exists()
            for l in (HERE / f).read_text().splitlines() if l.strip()}
added = 0
with open(HERE / "candidates.jsonl", "a") as out:
    for r in rows:
        cid = f"fb_{r['trace_id']}"
        if r["vote"] != "down" or not r.get("fixture") or cid in existing:
            continue
        fx = dict(r["fixture"]); fx["fx"] = fx.get("fx") or 1500.0
        (HERE / "fixtures" / f"{cid}.json").write_text(json.dumps(fx, indent=1))
        case = {"id": cid, "fixture": cid, "status": "needs_label", "got": r["got"], "codes": r.get("codes"),
                "user_expected": r.get("expected"), "user_note": r.get("note", "")}
        if r.get("expected"):
            case["expect"] = r["expected"]
        out.write(json.dumps(case) + "\n"); existing.add(cid); added += 1
print(f"{added} new candidate case(s) from {len(rows)} feedback rows -> evals/candidates.jsonl")
