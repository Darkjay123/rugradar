from pathlib import Path
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import ValidationError
from collections import defaultdict
import time
from .models import CheckRequest, Report
from .agent import check

app = FastAPI(title="RugRadar", version="0.1.0")
_hits: dict[str, list[float]] = defaultdict(list)
WEB = Path(__file__).resolve().parent.parent / "web" / "index.html"


@app.get("/", response_class=HTMLResponse)
def home():
    return WEB.read_text()


@app.get("/api/check", response_model=Report)
def api_check(chain: str, address: str, request: Request):
    ip = request.client.host if request.client else "?"
    now = time.time()
    _hits[ip] = [t for t in _hits[ip] if now - t < 60]
    if len(_hits[ip]) >= 20:
        raise HTTPException(429, "Too many checks. Try again in a minute.")
    _hits[ip].append(now)
    try:
        req = CheckRequest(chain=chain, address=address)
    except ValidationError as e:
        raise HTTPException(422, e.errors()[0]["msg"])
    return check(req)


@app.get("/api/health")
def health():
    return {"ok": True}
