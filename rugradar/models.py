from __future__ import annotations
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field, field_validator, model_validator
import re

# chain -> GoPlus chain id ("solana" uses GoPlus's separate Solana endpoint)
CHAINS = {"ethereum": "1", "bsc": "56", "base": "8453", "polygon": "137", "arbitrum": "42161", "solana": "solana"}
EVM_ADDR = re.compile(r"^0x[a-fA-F0-9]{40}$")
SOL_ADDR = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")


class CheckRequest(BaseModel):
    chain: str
    address: str
    lang: str = "en"
    amount_ngn: int = Field(default=50_000, ge=100, le=1_000_000_000)

    @field_validator("chain")
    @classmethod
    def known_chain(cls, v: str) -> str:
        v = v.lower().strip()
        if v not in CHAINS:
            raise ValueError(f"chain must be one of {sorted(CHAINS)}")
        return v

    @field_validator("lang")
    @classmethod
    def known_lang(cls, v: str) -> str:
        v = (v or "en").lower()
        return v if v in ("en", "pcm") else "en"

    @model_validator(mode="after")
    def address_matches_chain(self):
        a = self.address.strip()
        if self.chain == "solana":
            if not SOL_ADDR.match(a):
                raise ValueError("that doesn't look like a Solana token address")
            self.address = a  # base58 is case-sensitive
        else:
            if not EVM_ADDR.match(a):
                raise ValueError("address must be a 0x-prefixed 40-hex-character contract address")
            self.address = a.lower()
        return self


class Severity(str, Enum):
    info = "info"
    medium = "medium"
    high = "high"
    critical = "critical"


class Finding(BaseModel):
    code: str
    severity: Severity
    points: int = Field(ge=0, le=100)
    plain: str  # one sentence a newcomer understands, in the requested language


class Verdict(str, Enum):
    low = "LOW_RISK"
    caution = "CAUTION"
    high = "HIGH_RISK"
    unknown = "UNKNOWN"


class TokenFacts(BaseModel):
    """Validated subset of what the tools returned. Untrusted strings (name/symbol) never reach a model prompt."""
    chain: str = "bsc"
    name: Optional[str] = None
    symbol: Optional[str] = None
    holder_count: Optional[int] = None
    liquidity_usd: Optional[float] = None
    pair_age_hours: Optional[float] = None
    buy_tax: Optional[float] = None
    sell_tax: Optional[float] = None
    security: dict = Field(default_factory=dict)
    has_security_data: bool = False
    has_market_data: bool = False
    sim: Optional[dict] = None        # honeypot.is buy/sell simulation (EVM)
    creator: Optional[dict] = None    # GoPlus address-security flags for the deployer wallet
    rugcheck: Optional[dict] = None   # RugCheck summary (Solana)
    ngn_per_usd: Optional[float] = None
    previous: Optional[dict] = None   # last time we checked this token (memory)


class Money(BaseModel):
    amount_ngn: int
    get_back_ngn: int
    note: str


class Report(BaseModel):
    chain: str
    address: str
    name: Optional[str] = None
    symbol: Optional[str] = None
    verdict: Verdict
    score: int = Field(ge=0, le=100)
    findings: list[Finding]
    summary: str
    money: Optional[Money] = None
    sources: list[str] = Field(default_factory=list)
    lang: str = "en"
    share_text: str = ""
    explained_by: str
    trace_id: str
    cost_usd: float = 0.0
    latency_ms: int = 0
    message_flags: list[dict] = Field(default_factory=list)   # red flags in the pasted pitch itself
    removed: list[str] = Field(default_factory=list)          # private data we stripped before logging
    memory: Optional[dict] = None                              # what changed since this token was last checked
    route: str = "rules"                                       # which explanation path ran
    prompt_version: Optional[str] = None
    timed_out: list[str] = Field(default_factory=list)        # sources that missed the time budget
