"""
firewall/scheduler.py — Background scheduler for auto-expiring temporary blocks.

Uses APScheduler's AsyncIOScheduler to periodically check for expired
temporary firewall rules and remove them from both the database and iptables.
"""

import logging
from datetime import datetime

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from db.database import async_session
from db.models import FirewallRule, BlockedIP
from firewall.manager import FirewallManager

logger = logging.getLogger("ids.firewall.scheduler")


async def expire_temporary_blocks(manager: FirewallManager):
    """
    Check for and remove expired temporary firewall rules.

    This function is called periodically by APScheduler.  It:
        1. Queries for active, temporary rules past their expiry time.
        2. Removes each from iptables.
        3. Marks the rule as inactive in the DB.
        4. Removes the corresponding BlockedIP entry.
    """
    async with async_session() as db:
        try:
            now = datetime.utcnow()

            # Find expired temporary rules
            result = await db.execute(
                select(FirewallRule).where(
                    FirewallRule.is_active == True,
                    FirewallRule.is_temporary == True,
                    FirewallRule.expires_at != None,
                    FirewallRule.expires_at <= now,
                )
            )
            expired_rules = result.scalars().all()

            if not expired_rules:
                return

            logger.info("Found %d expired temporary blocks to remove", len(expired_rules))

            for rule in expired_rules:
                # Remove from iptables
                await manager.remove_rule(rule)

                # Mark rule as inactive
                rule.is_active = False

                # Remove from blocked_ips table
                blocked_result = await db.execute(
                    select(BlockedIP).where(BlockedIP.rule_id == rule.id)
                )
                blocked = blocked_result.scalar_one_or_none()
                if blocked:
                    await db.delete(blocked)

                logger.info(
                    "Expired temporary block removed: %s (rule #%d, expired at %s)",
                    rule.source_ip, rule.id, rule.expires_at,
                )

            await db.commit()

        except Exception as e:
            logger.error("Error during block expiry check: %s", e)
            await db.rollback()


def create_scheduler(manager: FirewallManager) -> AsyncIOScheduler:
    """
    Create and configure the APScheduler for periodic tasks.

    Jobs:
        - expire_temporary_blocks: runs every BLOCK_EXPIRY_CHECK_INTERVAL seconds.
    """
    from config import settings

    scheduler = AsyncIOScheduler()

    scheduler.add_job(
        expire_temporary_blocks,
        "interval",
        seconds=settings.BLOCK_EXPIRY_CHECK_INTERVAL,
        args=[manager],
        id="expire_blocks",
        name="Expire temporary firewall blocks",
        replace_existing=True,
    )

    logger.info(
        "Scheduler configured: block expiry check every %ds",
        settings.BLOCK_EXPIRY_CHECK_INTERVAL,
    )

    return scheduler
