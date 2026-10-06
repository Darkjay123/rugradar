#!/usr/bin/env python3
"""Check a crypto token with RugRadar. Standard library only.

  python check.py "<address | DexScreener/pump.fun link | whole forwarded message>" [--chain auto] [--lang en|pcm] [--amount 50000]
  python check.py --scan "<message>"     # scam tactics in a pitch, no network lookups of the token
"""
import argparse, json, sys, urllib.error, urllib.parse, urllib.request

BASE = "https://rugradar-dun.vercel.app"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("text")
    ap.add_argument("--chain", default="auto")
    ap.add_argument("--lang", default="en", choices=["en", "pcm"])
    ap.add_argument("--amount", type=int, default=50_000, help="naira you're thinking of putting in")
    ap.add_argument("--scan", action="store_true", help="only scan the message for scam tactics")
    ap.add_argument("--base", default=BASE)
    a = ap.parse_args()
    if a.scan:
        url = f"{a.base}/mcp/"
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                           "params": {"name": "scan_message", "arguments": {"text": a.text, "lang": a.lang}}}).encode()
        req = urllib.request.Request(url, body, {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"})
    else:
        q = urllib.parse.urlencode({"q": a.text[:2000], "chain": a.chain, "lang": a.lang, "amount": a.amount})
        req = urllib.request.Request(f"{a.base}/api/check?{q}")
    try:
        with urllib.request.urlopen(req, timeout=40) as r:
            out = json.load(r)
    except urllib.error.HTTPError as e:
        print(json.dumps({"error": e.read().decode()[:300], "status": e.code}))
        sys.exit(1)
    if a.scan:
        out = json.loads(out["result"]["content"][0]["text"])
    keep = ("verdict", "score", "name", "symbol", "chain", "address", "summary", "findings", "money",
            "message_flags", "coverage", "checked_at", "share_url", "error", "flags")
    print(json.dumps({k: out[k] for k in keep if k in out}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
