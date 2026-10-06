# Networks RugRadar checks (64)

Every network DexScreener lists. What we can read differs, and every report says which.

- full: Solana, BNB Chain, Ethereum, Base
- contract: Robinhood, Polygon, Arc, Cronos, Avalanche, Monad, Arbitrum, Sonic, World Chain, Tron, Abstract, Optimism, Stable, Plasma, Linea, Mantle, Blast, Berachain, opBNB, zkSync, Unichain, Soneium, Conflux, Merlin Chain, Scroll, Story, Manta
- market: PulseChain, NEAR, TON, Sui, HyperEVM, XRPL, Ink, Hyperliquid, Hedera, MultiversX, Cardano, Starknet, ICP, Aptos, Sei V2, MegaETH, Algorand, ApeChain, Fantom, Metis, Stacks, Injective, Celo, Beam, Flow EVM, Kava, Katana, Flare, Fuse, Movement, Telos, Polkadot, Step Network

full = contract scan plus a second independent check (Solana: RugCheck and a live Jupiter sell quote; Ethereum, BNB Chain, Base: a Honeypot.is test trade).
contract = GoPlus contract scan plus market data.
market = market data only (pools, liquidity, age, buys vs sells, price). The contract can't be read there, so a result on these networks is never 'Low risk'; at best 'Be careful', with the reason stated.

On every network: buys with zero sells in 24 hours (a honeypot signature) and a price crash of 80%+ are flagged.
