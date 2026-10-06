"""RugRadar: plain-English token scam checks for crypto newcomers."""
__version__ = "0.1.0"

# Accept the Gemini key under whatever name it was saved as in the host
# (GEMINI_API_KEY, GEMINI_KEY, Gemini_key, GOOGLE_API_KEY, any casing).
import os as _os
if not _os.environ.get("GEMINI_API_KEY"):
    for _k, _v in list(_os.environ.items()):
        if _k.upper() in ("GEMINI_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY", "GOOGLE_GEMINI_API_KEY") and _v.strip():
            _os.environ["GEMINI_API_KEY"] = _v.strip()
            break
