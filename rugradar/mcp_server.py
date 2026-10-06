"""RugRadar as an MCP server, so any AI assistant (Claude Desktop, Cursor, an agent framework) can call it as a tool.

Local:   uvx --from git+https://github.com/Darkjay123/rugradar rugradar-mcp   (stdio)
         python -m rugradar.mcp_server            (stdio, from a checkout)
Remote:  https://rugradar-dun.vercel.app/mcp      (streamable HTTP, stateless)
"""
from __future__ import annotations
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from .agent import check_text, InputError, prepare
from .chains import norm
from . import memory
from .i18n import T

# Public, read-only, no cookies or auth: DNS-rebinding protection guards nothing here and would block the Vercel host.
mcp = FastMCP("rugradar", stateless_http=True, json_response=True, streamable_http_path="/",
              transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False))


@mcp.tool()
def check_token(text: str, chain: str = "auto", lang: str = "en", amount_ngn: int = 50_000) -> dict:
    """Check if a crypto token is a scam before buying. `text` can be a contract address, a DexScreener or
    pump.fun link, or a whole forwarded "gem" message, on any of 64 networks (chain "auto" detects it; or pass a
    DexScreener chain id like "ton", "sui", "tron", "hyperevm"). Returns a rule-based verdict (LOW_RISK, CAUTION,
    HIGH_RISK, UNKNOWN), a 0-100 risk score, plain-language findings (lang "en" or "pcm" for Nigerian Pidgin),
    what you'd get back in naira, and red flags in the message itself."""
    try:
        return check_text(text[:2000], chain, lang, max(100, min(amount_ngn, 1_000_000_000))).model_dump()
    except (InputError, ValueError) as e:
        return {"error": str(e)}


@mcp.tool()
def scan_message(text: str, lang: str = "en") -> dict:
    """Scan a crypto pitch message for scam tactics (seed phrase requests, wallet-drainer links,
    guaranteed returns, urgency, send-to-receive) without touching the network. Private data is stripped."""
    clean, flags, removed = prepare(text[:4000])
    return {"flags": flags, "removed": removed, "clean_text": clean}


@mcp.tool()
def token_history(chain: str, address: str) -> dict:
    """What RugRadar saw the last time this token was checked (verdict, score, pool size, how long ago)."""
    return memory.last(chain.lower(), norm(chain.lower(), address)) or {"seen": False}


@mcp.tool()
def explain_finding(code: str, lang: str = "en") -> dict:
    """Plain-language meaning of a RugRadar finding code such as HONEYPOT or LP_UNLOCKED."""
    if code not in T:
        return {"error": f"unknown code; known: {sorted(T)}"}
    en, pcm = T[code]
    return {"code": code, "text": pcm if lang == "pcm" else en}


@mcp.tool()
def get_report(trace_id: str) -> dict:
    """Fetch a saved RugRadar check by its id (the code at the end of a rugradar-dun.vercel.app/r/... link).
    Saved checks last 30 days. Re-run check_token before relying on an old one: tokens change fast."""
    rep = memory.get_report(trace_id[:32]) if trace_id.isalnum() else None
    return rep or {"error": "no saved check with that id (they expire after 30 days)"}


def main() -> None:
    """Console entry point: `rugradar-mcp` (stdio)."""
    mcp.run()


if __name__ == "__main__":
    main()
