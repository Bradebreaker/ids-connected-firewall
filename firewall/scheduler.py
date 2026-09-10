"""
firewall/scheduler.py — Background scheduler for auto-expiring temporary blocks.

Uses APScheduler's AsyncIOScheduler to periodically check for expired
temporary firewall rules and remove them from both the database and iptables.
"""

import logging
from datetime import datetime

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlalchemy import select, func, delete, text
from sqlalchemy.ext.asyncio import AsyncSession

from db.database import async_session
from db.models import FirewallRule, BlockedIP, Alert
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


async def maintain_database_health():
    """
    Periodic routine maintenance for SQLite database health:
    1. Runs PRAGMA wal_checkpoint(PASSIVE) to merge committed WAL pages
       back into the main database file without blocking active readers or writers.
    2. Enforces alert retention: If total alerts exceed DB_MAX_ALERTS_RETENTION,
       prunes the oldest resolved alerts (ordered deterministically by timestamp, id)
       to prevent table exhaustion while preserving recent/active incidents.
    """
    from config import settings

    async with async_session() as db:
        # 1. Passive WAL checkpoint
        try:
            res = await db.execute(text("PRAGMA wal_checkpoint(PASSIVE);"))
            row = res.fetchone()
            logger.info("Routine WAL checkpoint (PASSIVE) executed: result=%s", row)
        except Exception as e:
            logger.warning("Routine WAL checkpoint error: %s", e)

        # 2. Alert retention check
        try:
            count_res = await db.execute(select(func.count(Alert.id)))
            total_alerts = count_res.scalar() or 0

            max_retention = settings.DB_MAX_ALERTS_RETENTION
            if total_alerts > max_retention:
                excess = total_alerts - max_retention
                logger.info(
                    "Alert retention limit exceeded: %d total alerts (limit %d). Pruning %d oldest alerts.",
                    total_alerts, max_retention, excess
                )
                # First try pruning oldest resolved alerts
                subq_resolved = (
                    select(Alert.id)
                    .where(Alert.resolved == True)
                    .order_by(Alert.timestamp.asc(), Alert.id.asc())
                    .limit(excess)
                )
                resolved_ids = list((await db.execute(subq_resolved)).scalars().all())

                ids_to_prune = resolved_ids
                if len(ids_to_prune) < excess:
                    needed = excess - len(ids_to_prune)
                    subq_all = (
                        select(Alert.id)
                        .where(Alert.id.not_in(ids_to_prune) if ids_to_prune else True)
                        .order_by(Alert.timestamp.asc(), Alert.id.asc())
                        .limit(needed)
                    )
                    more_ids = list((await db.execute(subq_all)).scalars().all())
                    ids_to_prune.extend(more_ids)

                if ids_to_prune:
                    del_stmt = delete(Alert).where(Alert.id.in_(ids_to_prune))
                    await db.execute(del_stmt)
                    await db.commit()
                    logger.info("Retention maintenance: successfully pruned %d oldest alerts.", len(ids_to_prune))
        except Exception as e:
            logger.error("Alert retention maintenance error: %s", e)
            await db.rollback()


def create_scheduler(manager: FirewallManager) -> AsyncIOScheduler:
    """
    Create and configure the APScheduler for periodic tasks.

    Jobs:
        - expire_temporary_blocks: runs every BLOCK_EXPIRY_CHECK_INTERVAL seconds.
        - maintain_database_health: runs every DB_AUTO_CHECKPOINT_INTERVAL seconds.
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

    scheduler.add_job(
        maintain_database_health,
        "interval",
        seconds=settings.DB_AUTO_CHECKPOINT_INTERVAL,
        id="maintain_database",
        name="Routine WAL checkpoint & retention maintenance",
        replace_existing=True,
    )

    logger.info(
        "Scheduler configured: block expiry every %ds, WAL/retention check every %ds",
        settings.BLOCK_EXPIRY_CHECK_INTERVAL,
        settings.DB_AUTO_CHECKPOINT_INTERVAL,
    )

    return scheduler
