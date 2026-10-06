# RugRadar quickstart

Free, read-only, no wallet, no sign-up, no API key. Base URL: `https://rugradar-dun.vercel.app`

## 1. In a browser
Open the site, paste an address, a DexScreener or pump.fun link, or a whole forwarded "gem" message. Each check gets a link (`/r/<id>`) you can forward on WhatsApp. Saved checks last 30 days.

## 2. Over HTTP
```bash
curl "https://rugradar-dun.vercel.app/api/check?q=DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263&amount=50000"
curl -N "https://rugradar-dun.vercel.app/api/stream?q=<text>"      # each source as it answers (server-sent events)
curl "https://rugradar-dun.vercel.app/api/report/<id>"              # a saved check
```
`verdict` is one of `LOW_RISK`, `CAUTION`, `HIGH_RISK`, `UNKNOWN`. It comes from fixed rules, never a model. `lang=pcm` returns Nigerian Pidgin. 20 checks per minute per IP.

## 3. As an MCP server (Claude Code, Cursor, Windsurf, any MCP client)
Remote, stateless, streamable HTTP: `https://rugradar-dun.vercel.app/mcp/`

Claude Code:
```bash
claude mcp add --transport http rugradar https://rugradar-dun.vercel.app/mcp/
```
Cursor (`~/.cursor/mcp.json`):
```json
{ "mcpServers": { "rugradar": { "url": "https://rugradar-dun.vercel.app/mcp/" } } }
```
Local over stdio: `pip install -r requirements.txt && python -m rugradar.mcp_server`

Tools: `check_token`, `scan_message`, `token_history`, `explain_finding`, `get_report`. All read-only.

## 4. As an Agent Skill
Copy `skills/rugradar/` into your agent's skills folder (for Claude Code: `~/.claude/skills/rugradar/`). The skill tells the agent when to check, how to word the answer (never "safe"), and falls back to `scripts/check.py` (standard library only) when the MCP server isn't connected.

## Verify it yourself
```bash
python skills/rugradar/scripts/check.py DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263     # BONK: expect LOW_RISK
python skills/rugradar/scripts/check.py R2fVoMU9rHmC6tbeeeeowkpRPYdccmJGXpjyqoQpump       # one wallet holds most of it: expect HIGH_RISK
python skills/rugradar/scripts/check.py --scan "send 0.1 SOL to receive 1 SOL, guaranteed 10x"
python evals/run_evals.py        # the golden cases CI runs before every deploy
```
Live verdicts can change as tokens change; the eval cases replay saved data, so they don't.
