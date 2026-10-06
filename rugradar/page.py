"""Server-rendered page for a saved check, so a WhatsApp share link opens a real report with a preview card.

Everything that came from the token (name, symbol) is untrusted and escaped. Pages are noindex:
we don't want scam token names ranking in search because someone shared a warning about them.
"""
from __future__ import annotations
from html import escape as e

LABEL = {"en": {"LOW_RISK": "Low risk", "CAUTION": "Be careful", "HIGH_RISK": "HIGH RISK", "UNKNOWN": "Couldn't check"},
         "pcm": {"LOW_RISK": "Risk small", "CAUTION": "Shine your eye", "HIGH_RISK": "DANGER", "UNKNOWN": "We no fit check am"}}
TXT = {"en": {"checked": "Checked", "stale": "Tokens change fast. Check again before you put money in.", "again": "Check it again now",
              "own": "Check your own token", "why": "Why", "back": "If you put in", "get": "you'd get back about",
              "src": "Sources read", "low": "Low risk is not a promise. It means we found no big red flags in the sources we could read."},
       "pcm": {"checked": "We check am", "stale": "Token dey change sharp sharp. Check am again before you put money.", "again": "Check am again now",
               "own": "Check your own token", "why": "Why", "back": "If you put", "get": "you go collect back like",
               "src": "Where we check", "low": "Risk small no mean say e safe. E mean say we no see big wahala for the places we fit check."}}
COLOR = {"LOW_RISK": "#15803d", "CAUTION": "#b45309", "HIGH_RISK": "#b91c1c", "UNKNOWN": "#475569"}


def render(r: dict, base: str) -> str:
    lang = r.get("lang") if r.get("lang") in TXT else "en"
    t, v = TXT[lang], r["verdict"]
    label = LABEL[lang][v]
    tok = " ".join(x for x in [r.get("name") or "", f"${r['symbol']}" if r.get("symbol") else ""] if x).strip() or "this token"
    top = next((f["plain"] for f in r.get("findings", []) if f.get("points")), r.get("summary", ""))
    title = f"RugRadar: {label} ({r['score']}/100) for {tok}"
    url = f"{base}/r/{r['trace_id']}"
    again = f"{base}/?q={e(r['address'])}&chain={e(r['chain'])}&lang={lang}"
    finds = "".join(f'<li class="{e(f["severity"])}">{e(f["plain"])}</li>' for f in r.get("findings", []))
    m = r.get("money")
    money = (f'<p class="money">{t["back"]} ₦{m["amount_ngn"]:,}, {t["get"]} <b>₦{m["get_back_ngn"]:,}</b>. {e(m["note"])}</p>' if m else "")
    low = f'<p class="note">{t["low"]}</p>' if v == "LOW_RISK" else ""
    when = (r.get("checked_at") or "").replace("T", " ").replace("Z", " UTC")
    src = ", ".join(e(s) for s in r.get("sources", []))
    return f"""<!doctype html><html lang="{'en' if lang == 'en' else 'pcm'}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title>{e(title)}</title><meta property="og:title" content="{e(title)}"><meta property="og:description" content="{e(top)}">
<meta property="og:url" content="{e(url)}"><meta property="og:type" content="website"><meta property="og:image" content="{e(url)}.png"><meta property="og:image:width" content="1200"><meta property="og:image:height" content="630"><meta name="twitter:card" content="summary_large_image"><meta name="twitter:image" content="{e(url)}.png">
<style>body{{font-family:system-ui,-apple-system,sans-serif;margin:0;background:#f8fafc;color:#0f172a}}main{{max-width:560px;margin:auto;padding:20px 16px 40px}}
.badge{{background:{COLOR[v]};color:#fff;border-radius:14px;padding:18px}}.badge h1{{margin:0;font-size:26px}}.badge p{{margin:6px 0 0;opacity:.95}}
ul{{padding-left:20px}}li{{margin:8px 0}}li.critical,li.high{{font-weight:600}}.money{{background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:12px}}
.note,.meta{{color:#475569;font-size:14px}}a.btn{{display:block;text-align:center;text-decoration:none;padding:13px;border-radius:10px;font-weight:700;margin-top:10px}}
.a{{background:#0f172a;color:#fff}}.b{{border:2px solid #0f172a;color:#0f172a}}code{{word-break:break-all;font-size:12px}}</style></head>
<body><main><div class="badge"><h1>{e(label)} · {r['score']}/100</h1><p>{e(tok)} on {e(r.get('chain_name') or r['chain'])}</p></div>
<p>{e(r.get('summary', ''))}</p>{money}<h3>{t['why']}</h3><ul>{finds}</ul>{low}
<p class="meta">{t['checked']}: {e(when)}. {t['stale']}</p><p class="meta">{t['src']}: {src}</p><p class="meta"><code>{e(r['address'])}</code></p>
<a class="btn a" href="{again}">{t['again']}</a><a class="btn b" href="{base}/">{t['own']}</a></main></body></html>"""
