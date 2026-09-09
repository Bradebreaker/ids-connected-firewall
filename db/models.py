"""
db/models.py — SQLAlchemy ORM models for the IDS-Connected Firewall.

Tables:
    - alerts          : every detection event logged by the IDS
    - firewall_rules  : ordered rule table synced to iptables
    - blocked_ips     : convenience view of currently blocked IPs
    - users           : JWT-authenticated dashboard users
"""

from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Boolean, Float, DateTime, Text,
    ForeignKey, Index,
)
from sqlalchemy.orm import relationship
from db.database import Base


class Alert(Base):
    """An intrusion detection alert raised by one of the detector modules."""

    __tablename__ = "alerts"

    id          = Column(Integer, primary_key=True, autoincrement=True)
    timestamp   = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    source_ip   = Column(String(45), nullable=False, index=True)   # IPv4 or IPv6
    dest_ip     = Column(String(45), nullable=True)
    dest_port   = Column(Integer, nullable=True)
    protocol    = Column(String(10), nullable=True)                 # TCP / UDP / ICMP
    alert_type  = Column(
        String(30), nullable=False, index=True,
        # signature | port_scan | brute_force | syn_flood
    )
    severity    = Column(String(10), nullable=False, index=True)    # low / medium / high
    description = Column(Text, nullable=False)
    raw_packet  = Column(Text, nullable=True)                       # summary of the packet
    resolved    = Column(Boolean, default=False)
    auto_blocked = Column(Boolean, default=False)                   # did this alert trigger a block?

    # Helpful composite index for the dashboard query pattern
    __table_args__ = (
        Index("ix_alerts_ts_sev", "timestamp", "severity"),
    )

    def __repr__(self):
        return f"<Alert {self.id} {self.alert_type}/{self.severity} from {self.source_ip}>"


class FirewallRule(Base):
    """
    A firewall rule that maps to an iptables entry.

    Rules are applied in `priority` order (lower number = higher priority,
    first-match wins — just like a real firewall ACL).
    """

    __tablename__ = "firewall_rules"

    id            = Column(Integer, primary_key=True, autoincrement=True)
    priority      = Column(Integer, nullable=False, default=100, index=True)
    source_ip     = Column(String(45), nullable=False, index=True)
    dest_port     = Column(Integer, nullable=True)                 # NULL = any port
    protocol      = Column(String(10), nullable=True)              # NULL = any protocol
    action        = Column(String(10), nullable=False, default="DROP")  # DROP / ACCEPT
    rule_type     = Column(String(10), nullable=False, default="manual") # auto / manual
    is_temporary  = Column(Boolean, default=False)
    ttl_seconds   = Column(Integer, nullable=True)                 # for temporary rules
    created_at    = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at    = Column(DateTime, nullable=True)                # NULL = permanent
    is_active     = Column(Boolean, default=True, index=True)

    # Relationship to blocked_ips
    blocked_ip = relationship("BlockedIP", back_populates="rule", uselist=False)

    def __repr__(self):
        return (f"<FirewallRule {self.id} pri={self.priority} "
                f"{self.action} {self.source_ip} ({'temp' if self.is_temporary else 'perm'})>")


class BlockedIP(Base):
    """
    Quick-lookup table of currently blocked IP addresses.

    Every auto-block or manual block creates an entry here, linked
    back to the firewall rule that enforces it.
    """

    __tablename__ = "blocked_ips"

    id          = Column(Integer, primary_key=True, autoincrement=True)
    ip_address  = Column(String(45), nullable=False, unique=True, index=True)
    reason      = Column(Text, nullable=False)
    blocked_at  = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at  = Column(DateTime, nullable=True)
    is_permanent = Column(Boolean, default=True)
    rule_id     = Column(Integer, ForeignKey("firewall_rules.id"), nullable=True)

    rule = relationship("FirewallRule", back_populates="blocked_ip")

    def __repr__(self):
        return f"<BlockedIP {self.ip_address} ({'perm' if self.is_permanent else 'temp'})>"


class User(Base):
    """Dashboard user with hashed password for JWT authentication."""

    __tablename__ = "users"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    username        = Column(String(50), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    is_admin        = Column(Boolean, default=False)
    created_at      = Column(DateTime, default=datetime.utcnow, nullable=False)

    def __repr__(self):
        return f"<User {self.username} admin={self.is_admin}>"
