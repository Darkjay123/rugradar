"""RugRadar as an MCP server, so any AI assistant (Claude Desktop, Cursor, an agent framework) can call it as a tool.

Local:   python -m rugradar.mcp_server            (stdio)
Remote:  https://rugradar-dun.vercel.app/mcp      (streamable HTTP, stateless)
"""
from __future__ import annotations
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from .agent import check_text, InputError, prepare
from . import memory
from .i18n import T

# Public, read-only, no cookies or auth: DNS-rebinding protection guards nothing here and would block the Vercel host.
mcp = FastMCP("rugradar", stateless_http=True, json_response=True, streamable_http_path="/",
              transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False))


@mcp.tool()
def check_token(text: str, chain: str = "auto", lang: str = "en", amount_ngn: int = 50_000) -> dict:
    """Check if a crypto token is a scam before buying. `text` can be a contract address, a DexScreener or
    pump.fun link, or a whole forwarded "gem" message. Returns a rule-based verdict (LOW_RISK, CAUTION,
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
    return memory.last(chain.lower(), address if chain.lower() == "solana" else address.lower()) or {"seen": False}


@mcp.tool()
def explain_finding(code: str, lang: str = "en") -> dict:
    """Plain-language meaning of a RugRadar finding code such as HONEYPOT or LP_UNLOCKED."""
    if code not in T:
        return {"error": f"unknown code; known: {sorted(T)}"}
    en, pcm = T[code]
    return {"code": code, "text": pcm if lang == "pcm" else en}


if __name__ == "__main__":
    mcp.run()
