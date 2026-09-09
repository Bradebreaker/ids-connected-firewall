"""
decision/engine.py — Decision Engine: the critical link between detection and enforcement.

This module sits between the IDS detectors and the firewall manager.
For every alert raised by a detector, the decision engine:
    1. Checks the whitelist — never block localhost or the management IP.
    2. Evaluates severity — only auto-block above the configured threshold.
    3. Determines block duration — high severity = permanent, medium = temporary.
    4. Stores the alert in the database.
    5. Triggers a firewall block if warranted.
    6. Broadcasts the event via WebSocket to connected dashboards.

This separation ensures we can log ALL detections (even from whitelisted IPs)
while only enforcing blocks when safe and appropriate.
"""

import logging
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from db.models import Alert, FirewallRule, BlockedIP
from db.schemas import AlertEvent
from config import settings

logger = logging.getLogger("ids.decision")

# Severity ordering for comparison
_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}


class DecisionEngine:
    """
    Evaluates alerts and decides whether to trigger firewall enforcement.

    The engine enforces two critical safety invariants:
        1. Whitelisted IPs are NEVER blocked (logged but not enforced).
        2. Only alerts at or above the configured minimum severity trigger blocks.
    """

    def __init__(self, firewall_manager, ws_manager):
        """
        Args:
            firewall_manager: firewall.manager.FirewallManager instance
            ws_manager: api.websocket_manager.WebSocketManager instance
        """
        self.firewall = firewall_manager
        self.ws = ws_manager
        self.whitelist = set(settings.WHITELIST_IPS)
        self.min_severity = settings.AUTO_BLOCK_MIN_SEVERITY
        self.temp_ttl = settings.TEMP_BLOCK_TTL_SECONDS
        logger.info(
            "DecisionEngine ready — whitelist=%s, min_severity=%s, temp_ttl=%ds",
            self.whitelist, self.min_severity, self.temp_ttl,
        )

    def _is_whitelisted(self, ip: str) -> bool:
        """Check if an IP is in the whitelist (must never be blocked)."""
        return ip in self.whitelist

    def _meets_severity_threshold(self, severity: str) -> bool:
        """Check if the alert severity meets the auto-block threshold."""
        return _SEVERITY_ORDER.get(severity, 0) >= _SEVERITY_ORDER.get(self.min_severity, 1)

    async def process_alert(self, alert_event: AlertEvent, db: AsyncSession) -> Alert:
        """
        Process an alert event from a detector.

        Steps:
            1. Store the alert in the database (always).
            2. Broadcast via WebSocket (always).
            3. If whitelisted → log warning, skip block.
            4. If below severity threshold → skip block.
            5. Otherwise → create firewall rule + blocked IP entry.

        Returns:
            The persisted Alert ORM object.
        """
        # ── Step 1: Persist the alert ─────────────────────────────
        alert = Alert(
            source_ip=alert_event.source_ip,
            dest_ip=alert_event.dest_ip,
            dest_port=alert_event.dest_port,
            protocol=alert_event.protocol,
            alert_type=alert_event.alert_type,
            severity=alert_event.severity,
            description=alert_event.description,
            raw_packet=alert_event.raw_packet,
            resolved=False,
            auto_blocked=False,
        )
        db.add(alert)
        await db.flush()  # get the alert.id

        logger.info(
            "Alert #%d recorded: %s/%s from %s — %s",
            alert.id, alert.alert_type, alert.severity,
            alert.source_ip, alert.description[:100],
        )

        # ── Step 2: Broadcast via WebSocket ───────────────────────
        await self.ws.broadcast({
            "type": "new_alert",
            "data": {
                "id": alert.id,
                "timestamp": alert.timestamp.isoformat(),
                "source_ip": alert.source_ip,
                "dest_ip": alert.dest_ip,
                "dest_port": alert.dest_port,
                "protocol": alert.protocol,
                "alert_type": alert.alert_type,
                "severity": alert.severity,
                "description": alert.description,
                "auto_blocked": False,
            },
        })

        # ── Step 3: Whitelist check ───────────────────────────────
        if self._is_whitelisted(alert_event.source_ip):
            logger.warning(
                "WHITELIST: Alert from %s logged but NOT blocked (whitelisted)",
                alert_event.source_ip,
            )
            await db.commit()
            return alert

        # ── Step 4: Severity threshold check ──────────────────────
        if not self._meets_severity_threshold(alert_event.severity):
            logger.info(
                "Alert from %s below auto-block threshold (%s < %s), not blocking",
                alert_event.source_ip, alert_event.severity, self.min_severity,
            )
            await db.commit()
            return alert

        # ── Step 5: Check if already blocked ──────────────────────
        existing = await db.execute(
            select(BlockedIP).where(
                BlockedIP.ip_address == alert_event.source_ip
            )
        )
        if existing.scalar_one_or_none():
            logger.info("IP %s is already blocked, skipping duplicate", alert_event.source_ip)
            await db.commit()
            return alert

        # ── Step 6: Create firewall rule + block ──────────────────
        is_permanent = (alert_event.severity == "high")
        expires_at = None
        if not is_permanent:
            expires_at = datetime.utcnow() + timedelta(seconds=self.temp_ttl)

        rule = FirewallRule(
            priority=50 if alert_event.severity == "high" else 75,
            source_ip=alert_event.source_ip,
            dest_port=alert_event.dest_port,
            protocol=alert_event.protocol.lower() if alert_event.protocol else None,
            action="DROP",
            rule_type="auto",
            is_temporary=not is_permanent,
            ttl_seconds=self.temp_ttl if not is_permanent else None,
            expires_at=expires_at,
            is_active=True,
        )
        db.add(rule)
        await db.flush()

        blocked = BlockedIP(
            ip_address=alert_event.source_ip,
            reason=alert_event.description[:500],
            expires_at=expires_at,
            is_permanent=is_permanent,
            rule_id=rule.id,
        )
        db.add(blocked)

        # Mark alert as having triggered a block
        alert.auto_blocked = True

        await db.commit()

        # ── Step 7: Enforce in iptables ───────────────────────────
        await self.firewall.add_rule(rule)

        logger.warning(
            "AUTO-BLOCK: %s blocked (%s, %s) — rule #%d",
            alert_event.source_ip,
            "permanent" if is_permanent else f"temp {self.temp_ttl}s",
            alert_event.severity,
            rule.id,
        )

        # ── Step 8: Broadcast block event ─────────────────────────
        await self.ws.broadcast({
            "type": "ip_blocked",
            "data": {
                "ip_address": alert_event.source_ip,
                "reason": alert_event.description[:200],
                "is_permanent": is_permanent,
                "expires_at": expires_at.isoformat() if expires_at else None,
                "severity": alert_event.severity,
                "rule_id": rule.id,
            },
        })

        return alert
