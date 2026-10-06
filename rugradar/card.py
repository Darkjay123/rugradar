"""1200x630 preview image for a saved check, so a WhatsApp/X share shows the verdict before anyone taps."""
from __future__ import annotations
import io, textwrap
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont
from .page import LABEL

D = Path(__file__).resolve().parent / "data"
BG = {"LOW_RISK": (21, 128, 61), "CAUTION": (180, 83, 9), "HIGH_RISK": (185, 28, 28), "UNKNOWN": (71, 85, 105)}


def _f(size, bold=True):
    return ImageFont.truetype(str(D / ("DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf")), size)


def png(r: dict) -> bytes:
    lang = r.get("lang") if r.get("lang") in LABEL else "en"
    v = r["verdict"]
    im = Image.new("RGB", (1200, 630), BG[v])
    d = ImageDraw.Draw(im)
    d.rectangle([0, 470, 1200, 630], fill=(15, 23, 42))
    d.text((60, 50), "RugRadar", font=_f(40), fill=(255, 255, 255))
    d.text((60, 120), f"{LABEL[lang][v]}  {r['score']}/100", font=_f(84), fill=(255, 255, 255))
    tok = " ".join(x for x in [(r.get("name") or "")[:28], f"${r['symbol'][:12]}" if r.get("symbol") else ""] if x) or "this token"
    d.text((60, 235), f"{tok} on {r['chain']}", font=_f(40, False), fill=(255, 255, 255))
    top = next((f["plain"] for f in r.get("findings", []) if f.get("points")), r.get("summary", ""))
    for i, line in enumerate(textwrap.wrap(top, 52)[:3]):
        d.text((60, 310 + i * 46), line, font=_f(34, False), fill=(255, 255, 255))
    m = r.get("money")
    foot = (f"Put in ₦{m['amount_ngn']:,}, get back about ₦{m['get_back_ngn']:,}" if m else "Check any token before you buy")
    d.text((60, 505), foot, font=_f(38), fill=(255, 255, 255))
    d.text((60, 565), f"Checked {(r.get('checked_at') or '')[:16].replace('T', ' ')} UTC  ·  rugradar-dun.vercel.app",
           font=_f(26, False), fill=(203, 213, 225))
    b = io.BytesIO()
    im.save(b, "PNG", optimize=True)
    return b.getvalue()
