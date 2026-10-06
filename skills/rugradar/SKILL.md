---
name: rugradar
description: Use when someone asks whether a crypto token is a scam or safe to buy, shares a contract address, a DexScreener or pump.fun link, or forwards a "gem" / "100x" message. Do not use for price predictions, trading or investment advice, wallet balances, or explaining a transaction.
---

# RugRadar: check a token before buying

RugRadar reads live on-chain sources (GoPlus, honeypot.is, DexScreener, RugCheck, Jupiter) and applies fixed safety rules. The verdict comes from rules, never from a model, so you can relay it without second-guessing it.

## How to run a check

Pick whichever is available, in this order:

1. The `check_token` MCP tool, if the `rugradar` MCP server is connected (`https://rugradar-dun.vercel.app/mcp`).
2. `python scripts/check.py "<address, link or whole message>" [--lang pcm] [--amount 50000]` from this skill folder. Standard library only, no install.
3. `curl "https://rugradar-dun.vercel.app/api/check?q=<url-encoded text>"`.

Pass the user's text as it is: RugRadar finds the address and chain itself. It strips phone numbers, emails, keys and recovery phrases before anything is stored.

If the user only pasted a pitch with no address, use `scan_message` (MCP) or `--scan` for the scam-tactic check.

## How to answer

- Lead with the verdict and score, then the top two or three findings in the tool's own words.
- `LOW_RISK` means no big red flags in the sources RugRadar could read. Never say "safe", "legit" or "guaranteed". Say "low risk, not a promise".
- `HIGH_RISK`: say plainly not to buy, and why.
- `UNKNOWN`: say RugRadar couldn't check it, and that not being able to check is itself a reason to wait.
- If `money` is present, give the naira line: what they'd put in and roughly what they'd get back.
- If `coverage.missing` is not empty, name the sources that couldn't be read.
- Include `share_url` so they can forward the full check on WhatsApp.
- If `message_flags` came back (seed phrase ask, send-to-receive, guaranteed returns), lead with those: they matter more than the token.
- Answer in Nigerian Pidgin when the user writes in Pidgin (`lang=pcm`).

## Never

- Never ask for a seed phrase, private key or wallet connection. RugRadar needs none, and anyone who asks is the scam.
- Never override or soften the verdict with your own opinion of the project.
- Never present an old check as current: re-run it. Tokens change in minutes.
