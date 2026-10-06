"""Compare model arms on real traffic before promoting a challenger.

  python evals/ab_report.py --url https://rugradar-dun.vercel.app
Promote B only if its guardrail-rejection rate and latency are no worse than A's and thumbs-down didn't rise.
"""
import argparse, httpx
ap = argparse.ArgumentParser(); ap.add_argument("--url", default="https://rugradar-dun.vercel.app")
s = httpx.get(f"{ap.parse_args().url}/api/stats", timeout=30).json()
print(f"checks={s['checks']} cost/check=${s['cost_per_check_usd']} p50={s['p50_ms']}ms thumbs={s['thumbs']}")
for arm, m in sorted(s["ab"].items()):
    print(f"  {arm:<36} n={m['n']:<5} cost/check=${m['cost_per_check_usd']:<9} p50={m['p50_ms']}ms rejected={m['rejected_rate']:.1%}")
if not s["ab"]:
    print("  no model-routed traffic yet (set GEMINI_API_KEY and RUGRADAR_AB=model:percent)")
