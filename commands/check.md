---
description: Check a crypto token, link or forwarded "gem" message for scams before buying
argument-hint: <address, DexScreener/pump.fun link, or whole message> [pidgin]
---

Run a RugRadar check on: $ARGUMENTS

Use the `check_token` tool from the rugradar MCP server, passing the text exactly as given (it finds the address and network itself). If the text ends with "pidgin", pass lang "pcm" and drop that word. If there is no address at all, use `scan_message` instead.

Then answer in a few plain sentences:
- Lead with the verdict (LOW_RISK, CAUTION, HIGH_RISK or UNKNOWN) and the one or two findings that drove it.
- If HIGH_RISK, say clearly not to buy and why, in everyday words.
- Never call a token "safe" or give price or investment advice. LOW_RISK means no known traps were found, not that it will go up.
- End with the shareable report link if the result has one.
