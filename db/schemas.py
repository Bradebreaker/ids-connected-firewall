"""
db/schemas.py — Pydantic v2 models for request / response validation.

Every API endpoint uses these for strict typing — no raw dicts anywhere.
"""

from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
from enum import Enum


# ══════════════════════════════════════════════════════════════════════
#  Enums
# ══════════════════════════════════════════════════════════════════════

class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"


class AlertType(str, Enum):
    signature   = "signature"
    port_scan   = "port_scan"
    brute_force = "brute_force"
    syn_flood   = "syn_flood"


class RuleAction(str, Enum):
    DROP   = "DROP"
    ACCEPT = "ACCEPT"


class RuleType(str, Enum):
    auto   = "auto"
    manual = "manual"


# ══════════════════════════════════════════════════════════════════════
#  Alert schemas
# ══════════════════════════════════════════════════════════════════════

class AlertOut(BaseModel):
    """Alert as returned to the dashboard."""
    id: int
    timestamp: datetime
    source_ip: str
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = None
    alert_type: str
    severity: str
    description: str
    raw_packet: Optional[str] = None
    resolved: bool
    auto_blocked: bool

    model_config = {"from_attributes": True}


class AlertEvent(BaseModel):
    """Internal event passed from detector → decision engine → WebSocket."""
    source_ip: str
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = None
    alert_type: str
    severity: str
    description: str
    raw_packet: Optional[str] = None


# ══════════════════════════════════════════════════════════════════════
#  Firewall rule schemas
# ══════════════════════════════════════════════════════════════════════

class FirewallRuleCreate(BaseModel):
    """Body for POST /api/rules — create a new manual rule."""
    source_ip: str = Field(..., description="IPv4/IPv6 address to match")
    dest_port: Optional[int] = Field(None, ge=1, le=65535)
    protocol: Optional[str] = Field(None, pattern="^(tcp|udp|icmp)$")
    action: RuleAction = RuleAction.DROP
    priority: int = Field(100, ge=1, le=9999)
    is_temporary: bool = False
    ttl_seconds: Optional[int] = Field(None, ge=60, description="TTL in seconds for temporary rules")


class FirewallRuleUpdate(BaseModel):
    """Body for PUT /api/rules/{id}."""
    priority: Optional[int] = Field(None, ge=1, le=9999)
    action: Optional[RuleAction] = None
    is_temporary: Optional[bool] = None
    ttl_seconds: Optional[int] = Field(None, ge=60)


class FirewallRuleOut(BaseModel):
    """Rule as returned to the dashboard."""
    id: int
    priority: int
    source_ip: str
    dest_port: Optional[int] = None
    protocol: Optional[str] = None
    action: str
    rule_type: str
    is_temporary: bool
    ttl_seconds: Optional[int] = None
    created_at: datetime
    expires_at: Optional[datetime] = None
    is_active: bool

    model_config = {"from_attributes": True}


# ══════════════════════════════════════════════════════════════════════
#  Block / Unblock schemas
# ══════════════════════════════════════════════════════════════════════

class BlockIPRequest(BaseModel):
    """Body for POST /api/block."""
    ip_address: str
    reason: str = "Manual block from dashboard"
    is_permanent: bool = True
    ttl_seconds: Optional[int] = Field(None, ge=60)


class UnblockIPRequest(BaseModel):
    """Body for POST /api/unblock."""
    ip_address: str


class BlockedIPOut(BaseModel):
    """Blocked IP as returned to the dashboard."""
    id: int
    ip_address: str
    reason: str
    blocked_at: datetime
    expires_at: Optional[datetime] = None
    is_permanent: bool
    rule_id: Optional[int] = None

    model_config = {"from_attributes": True}


# ══════════════════════════════════════════════════════════════════════
#  Auth schemas
# ══════════════════════════════════════════════════════════════════════

class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserOut(BaseModel):
    id: int
    username: str
    is_admin: bool
    created_at: datetime

    model_config = {"from_attributes": True}


# ══════════════════════════════════════════════════════════════════════
#  Stats schema
# ══════════════════════════════════════════════════════════════════════

class StatsResponse(BaseModel):
    """Dashboard statistics snapshot."""
    total_alerts: int
    alerts_today: int
    alerts_by_severity: dict          # {"low": N, "medium": N, "high": N}
    alerts_by_type: dict              # {"signature": N, "port_scan": N, ...}
    active_blocks: int
    top_attacker: Optional[str] = None
    alerts_per_hour: List[dict]       # [{"hour": "2024-01-01T12:00", "count": N}, ...]
    threat_level: str                 # "low" / "medium" / "high" / "critical"
