"""
api/routes_firewall.py — Firewall rule CRUD + IP block/unblock endpoints.
"""

import logging
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete

from db.models import FirewallRule, BlockedIP, User
from db.schemas import (
    FirewallRuleCreate, FirewallRuleUpdate, FirewallRuleOut,
    BlockIPRequest, UnblockIPRequest, BlockedIPOut,
)
from api.dependencies import get_db, get_current_user
from config import settings

logger = logging.getLogger("ids.api.firewall")
router = APIRouter(prefix="/api", tags=["Firewall"])

# Firewall manager + WS manager injected from main.py
_firewall_manager = None
_ws_manager = None


def set_managers(fw_manager, ws_manager):
    """Called from main.py to inject managers."""
    global _firewall_manager, _ws_manager
    _firewall_manager = fw_manager
    _ws_manager = ws_manager


# ══════════════════════════════════════════════════════════════════════
#  Firewall Rules CRUD
# ══════════════════════════════════════════════════════════════════════

@router.get("/rules", response_model=list[FirewallRuleOut])
async def list_rules(
    active_only: bool = Query(True),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """List all firewall rules, ordered by priority (first-match wins)."""
    query = select(FirewallRule).order_by(FirewallRule.priority)
    if active_only:
        query = query.where(FirewallRule.is_active == True)
    result = await db.execute(query)
    return result.scalars().all()


@router.post("/rules", response_model=FirewallRuleOut, status_code=201)
async def create_rule(
    body: FirewallRuleCreate,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Create a new manual firewall rule and sync to iptables."""
    # Whitelist safety check
    if body.source_ip in settings.WHITELIST_IPS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Cannot create rule for whitelisted IP {body.source_ip}",
        )

    expires_at = None
    if body.is_temporary and body.ttl_seconds:
        expires_at = datetime.utcnow() + timedelta(seconds=body.ttl_seconds)

    rule = FirewallRule(
        priority=body.priority,
        source_ip=body.source_ip,
        dest_port=body.dest_port,
        protocol=body.protocol,
        action=body.action.value,
        rule_type="manual",
        is_temporary=body.is_temporary,
        ttl_seconds=body.ttl_seconds,
        expires_at=expires_at,
        is_active=True,
    )
    db.add(rule)
    await db.flush()

    # Sync to iptables
    if _firewall_manager:
        await _firewall_manager.add_rule(rule)

    logger.info("Manual rule #%d created by %s: %s %s", rule.id, _user.username, rule.action, rule.source_ip)
    return rule


@router.put("/rules/{rule_id}", response_model=FirewallRuleOut)
async def update_rule(
    rule_id: int,
    body: FirewallRuleUpdate,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Update a firewall rule's priority, action, or TTL."""
    result = await db.execute(select(FirewallRule).where(FirewallRule.id == rule_id))
    rule = result.scalar_one_or_none()

    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    # Remove old iptables rule before modification
    if _firewall_manager:
        await _firewall_manager.remove_rule(rule)

    if body.priority is not None:
        rule.priority = body.priority
    if body.action is not None:
        rule.action = body.action.value
    if body.is_temporary is not None:
        rule.is_temporary = body.is_temporary
    if body.ttl_seconds is not None:
        rule.ttl_seconds = body.ttl_seconds
        rule.expires_at = datetime.utcnow() + timedelta(seconds=body.ttl_seconds)

    await db.flush()

    # Re-add updated rule to iptables
    if _firewall_manager and rule.is_active:
        await _firewall_manager.add_rule(rule)

    logger.info("Rule #%d updated by %s", rule.id, _user.username)
    return rule


@router.delete("/rules/{rule_id}", status_code=204)
async def delete_rule(
    rule_id: int,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Delete a firewall rule and remove from iptables."""
    result = await db.execute(select(FirewallRule).where(FirewallRule.id == rule_id))
    rule = result.scalar_one_or_none()

    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    # Remove from iptables
    if _firewall_manager:
        await _firewall_manager.remove_rule(rule)

    # Remove associated blocked IP
    await db.execute(delete(BlockedIP).where(BlockedIP.rule_id == rule.id))

    await db.delete(rule)
    logger.info("Rule #%d deleted by %s", rule_id, _user.username)


# ══════════════════════════════════════════════════════════════════════
#  IP Block / Unblock
# ══════════════════════════════════════════════════════════════════════

@router.get("/blocked", response_model=list[BlockedIPOut])
async def list_blocked(
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """List all currently blocked IPs."""
    result = await db.execute(
        select(BlockedIP).order_by(BlockedIP.blocked_at.desc())
    )
    return result.scalars().all()


@router.post("/block", response_model=BlockedIPOut, status_code=201)
async def block_ip(
    body: BlockIPRequest,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Manually block an IP address."""
    # Whitelist safety
    if body.ip_address in settings.WHITELIST_IPS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Cannot block whitelisted IP {body.ip_address}",
        )

    # Check if already blocked
    existing = await db.execute(
        select(BlockedIP).where(BlockedIP.ip_address == body.ip_address)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"IP {body.ip_address} is already blocked",
        )

    expires_at = None
    if not body.is_permanent and body.ttl_seconds:
        expires_at = datetime.utcnow() + timedelta(seconds=body.ttl_seconds)

    # Create firewall rule
    rule = FirewallRule(
        priority=50,
        source_ip=body.ip_address,
        action="DROP",
        rule_type="manual",
        is_temporary=not body.is_permanent,
        ttl_seconds=body.ttl_seconds,
        expires_at=expires_at,
        is_active=True,
    )
    db.add(rule)
    await db.flush()

    # Create blocked IP entry
    blocked = BlockedIP(
        ip_address=body.ip_address,
        reason=body.reason,
        expires_at=expires_at,
        is_permanent=body.is_permanent,
        rule_id=rule.id,
    )
    db.add(blocked)
    await db.flush()

    # Enforce in iptables
    if _firewall_manager:
        await _firewall_manager.add_rule(rule)

    # Broadcast
    if _ws_manager:
        await _ws_manager.broadcast({
            "type": "ip_blocked",
            "data": {
                "ip_address": body.ip_address,
                "reason": body.reason,
                "is_permanent": body.is_permanent,
            },
        })

    logger.info("Manual block by %s: %s (%s)", _user.username, body.ip_address, body.reason)
    return blocked


@router.post("/unblock", status_code=200)
async def unblock_ip(
    body: UnblockIPRequest,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Manually unblock an IP address."""
    result = await db.execute(
        select(BlockedIP).where(BlockedIP.ip_address == body.ip_address)
    )
    blocked = result.scalar_one_or_none()

    if not blocked:
        raise HTTPException(
            status_code=404,
            detail=f"IP {body.ip_address} is not currently blocked",
        )

    # Deactivate associated rule
    if blocked.rule_id:
        rule_result = await db.execute(
            select(FirewallRule).where(FirewallRule.id == blocked.rule_id)
        )
        rule = rule_result.scalar_one_or_none()
        if rule:
            rule.is_active = False

    # Remove from iptables
    if _firewall_manager:
        await _firewall_manager.remove_rule_by_ip(body.ip_address)

    # Remove blocked entry
    await db.delete(blocked)

    # Broadcast
    if _ws_manager:
        await _ws_manager.broadcast({
            "type": "ip_unblocked",
            "data": {"ip_address": body.ip_address},
        })

    logger.info("Manual unblock by %s: %s", _user.username, body.ip_address)
    return {"detail": f"IP {body.ip_address} unblocked successfully"}
