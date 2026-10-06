from pathlib import Path
from collections import defaultdict
import time
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import ValidationError
from .models import Report
from .agent import check_text, InputError

app = FastAPI(title="RugRadar", version="0.2.0")
_hits: dict[str, list[float]] = defaultdict(list)
WEB = Path(__file__).resolve().parent.parent / "web" / "index.html"


@app.get("/", response_class=HTMLResponse)
def home():
    return WEB.read_text()


@app.get("/api/check", response_model=Report)
def api_check(request: Request, q: str = "", address: str = "", chain: str = "auto", lang: str = "en", amount: int = 50_000):
    ip = request.client.host if request.client else "?"
    now = time.time()
    _hits[ip] = [t for t in _hits[ip] if now - t < 60]
    if len(_hits[ip]) >= 20:
        raise HTTPException(429, "Too many checks. Try again in a minute.")
    _hits[ip].append(now)
    text = (q or address)[:2000]  # pasted messages can be long; cap it
    try:
        return check_text(text, chain, lang, max(100, min(amount, 1_000_000_000)))
    except InputError as e:
        raise HTTPException(422, str(e))
    except ValidationError as e:
        raise HTTPException(422, e.errors()[0]["msg"].replace("Value error, ", ""))


@app.get("/api/health")
def health():
    return {"ok": True, "version": app.version}
