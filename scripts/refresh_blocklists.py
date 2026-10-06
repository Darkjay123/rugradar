"""Rebuild RugRadar's scam lists from public, community-maintained sources (run weekly by CI).

  phishing domains : MetaMask eth-phishing-detect (blacklist), ScamSniffer scam-database, Phantom blocklist,
                     polkadot-js/phishing (deny)
  allowed domains  : MetaMask whitelist + polkadot-js allow (so a real site is never called a scam)
  scam addresses   : ScamSniffer (wallet drainers and scam contracts, EVM)
  Sui scam coins   : Suiet guardians coin blocklist
"""
import gzip, json, re, sys
from pathlib import Path
import httpx

D = Path(__file__).resolve().parents[1] / "rugradar" / "data"
get = lambda u: httpx.get(u, timeout=60, follow_redirects=True)


def clean(d):
    d = (d or "").strip().lower().strip(".")
    d = re.sub(r"^https?://", "", d).split("/")[0].split(":")[0]
    return d[4:] if d.startswith("www.") else d


def main():
    mm = get("https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/main/src/config.json").json()
    ss = get("https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/domains.json").json()
    ph = re.findall(r"url:\s*(\S+)", get("https://raw.githubusercontent.com/phantom/blocklist/master/blocklist.yaml").text)
    pd = get("https://raw.githubusercontent.com/polkadot-js/phishing/master/all.json").json()
    allow = {clean(x) for x in (mm.get("whitelist") or []) + (pd.get("allow") or []) if x and "*" not in x}
    deny = {clean(x) for x in (mm.get("blacklist") or []) + ss + ph + (pd.get("deny") or []) if x and "*" not in x}
    deny = sorted(d for d in deny - allow if "." in d and len(d) < 120)
    addrs = sorted({a.lower() for a in get("https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/address.json").json()
                    if re.fullmatch(r"0x[0-9a-fA-F]{40}", a or "")})
    sui = sorted(set(get("https://raw.githubusercontent.com/suiet/guardians/main/dist/coin-list.json").json().get("blocklist") or []))
    for name, rows in (("phish_domains", deny), ("allow_domains", sorted(allow)), ("scam_addresses", addrs), ("sui_blocklist", sui)):
        with gzip.open(D / f"{name}.txt.gz", "wt") as f:
            f.write("\n".join(rows))
        print(name, len(rows))


if __name__ == "__main__":
    sys.exit(main())
