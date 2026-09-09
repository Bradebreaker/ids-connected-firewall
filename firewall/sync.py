"""
firewall/sync.py — DB ↔ iptables reconciliation.

Ensures the database rule table and the actual iptables state never
drift apart.  On startup and periodically, this module:
    1. Flushes the IDS custom chain.
    2. Re-applies all active rules from the database.

This is the "source of truth" pattern: the DB is always authoritative,
and iptables is rebuilt to match.
"""

import logging
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from db.models import FirewallRule
from firewall.manager import FirewallManager

logger = logging.getLogger("ids.firewall.sync")


async def reconcile(db: AsyncSession, manager: FirewallManager):
    """
    Reconcile iptables state with the database.

    Strategy:
        1. Flush the custom chain (clean slate).
        2. Query all active rules from the DB, ordered by priority.
        3. Re-insert each rule into iptables.

    This ensures iptables always matches the DB, even if someone
    manually modified iptables outside the application.
    """
    logger.info("Starting iptables ↔ DB reconciliation …")

    # Step 1: Flush the custom chain
    await manager.flush_chain()

    # Step 2: Get all active rules, ordered by priority (lower = first)
    result = await db.execute(
        select(FirewallRule)
        .where(FirewallRule.is_active == True)
        .order_by(FirewallRule.priority)
    )
    rules = result.scalars().all()

    # Step 3: Re-apply each rule
    applied = 0
    for rule in rules:
        success = await manager.add_rule(rule)
        if success:
            applied += 1

    logger.info(
        "Reconciliation complete: %d/%d rules applied to iptables",
        applied, len(rules),
    )

    return applied
