from __future__ import annotations
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field, field_validator
import re

CHAINS = {"ethereum": "1", "bsc": "56", "base": "8453", "polygon": "137", "arbitrum": "42161"}
ADDR = re.compile(r"^0x[a-fA-F0-9]{40}$")


class CheckRequest(BaseModel):
    chain: str
    address: str

    @field_validator("chain")
    @classmethod
    def known_chain(cls, v: str) -> str:
        v = v.lower().strip()
        if v not in CHAINS:
            raise ValueError(f"chain must be one of {sorted(CHAINS)}")
        return v

    @field_validator("address")
    @classmethod
    def evm_address(cls, v: str) -> str:
        v = v.strip()
        if not ADDR.match(v):
            raise ValueError("address must be a 0x-prefixed 40-hex-character contract address")
        return v.lower()


class Severity(str, Enum):
    info = "info"
    medium = "medium"
    high = "high"
    critical = "critical"


class Finding(BaseModel):
    code: str
    severity: Severity
    points: int = Field(ge=0, le=100)
    plain: str  # one sentence a newcomer understands


class Verdict(str, Enum):
    low = "LOW_RISK"
    caution = "CAUTION"
    high = "HIGH_RISK"
    unknown = "UNKNOWN"


class TokenFacts(BaseModel):
    """Validated subset of what the tools returned. Untrusted strings are kept separate."""
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


class Report(BaseModel):
    chain: str
    address: str
    verdict: Verdict
    score: int = Field(ge=0, le=100)
    findings: list[Finding]
    summary: str
    explained_by: str  # "template" or model id
    trace_id: str
    cost_usd: float = 0.0
    latency_ms: int = 0
