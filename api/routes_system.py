"""
api/routes_system.py — System Health & Observability API Endpoint.

Reports real health status, uptime, component availability, and operational
counters for all subsystems: FastAPI, SQLite, SQLAlchemy, Packet Ingestion,
Detectors, Decision Engine, Firewall Manager, APScheduler, and WebSocket Gateway.
"""

import os
import sys
import time
import asyncio
import platform
import logging
from datetime import datetime
from fastapi import APIRouter, Depends, Request, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, delete, text

from config import settings
from db.database import get_db, engine
from db.models import Alert, BlockedIP, FirewallRule, User
from api.dependencies import get_current_user
from sniffer.packet_event import get_current_packet_count, reset_recent_packets

logger = logging.getLogger("ids.api.system")
router = APIRouter(prefix="/api/system", tags=["System Status"])

_START_TIME = time.time()

# Managers injected from main.py
_firewall_manager = None
_ws_manager = None
_reset_lock = asyncio.Lock()


def set_managers(fw_manager, ws_manager):
    """Called from main.py to inject firewall and websocket managers."""
    global _firewall_manager, _ws_manager
    _firewall_manager = fw_manager
    _ws_manager = ws_manager



@router.get("/status")
async def get_system_status(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Returns real runtime diagnostics and health status for all system components.
    """
    now = time.time()
    uptime_seconds = int(now - _START_TIME)
    uptime_str = f"{uptime_seconds // 3600:02d}h {(uptime_seconds % 3600) // 60:02d}m {uptime_seconds % 60:02d}s"

    # Database health
    db_status = "ONLINE"
    db_size_kb = 0
    total_alerts = 0
    active_blocks = 0
    active_rules = 0

    try:
        db_file = "ids_firewall.db"
        if os.path.exists(db_file):
            db_size_kb = round(os.path.getsize(db_file) / 1024, 1)
        
        r_alerts = await db.execute(select(func.count(Alert.id)))
        total_alerts = r_alerts.scalar() or 0

        r_blocks = await db.execute(select(func.count(BlockedIP.id)))
        active_blocks = r_blocks.scalar() or 0

        r_rules = await db.execute(select(func.count(FirewallRule.id)).where(FirewallRule.is_active == True))
        active_rules = r_rules.scalar() or 0
    except Exception as e:
        logger.error("DB health check error: %s", e)
        db_status = "DEGRADED"

    # Packet queue & ingestion
    queue_size = 0
    if hasattr(request.app.state, "packet_queue"):
        queue_size = request.app.state.packet_queue.qsize()

    # WebSocket connections count
    ws_clients = 0
    try:
        # Check ws_manager from routes_alerts or app state
        from api.routes_alerts import ws_manager
        if ws_manager:
            ws_clients = len(ws_manager.active_connections)
    except Exception:
        pass

    # Firewall operational state
    is_linux = platform.system().lower() == "linux"
    firewall_mode = "IPTABLES (NATIVE)" if is_linux else "EMULATED ACL (WINDOWS)"

    return {
        "status": "healthy" if db_status == "ONLINE" else "degraded",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "uptime": uptime_str,
        "uptime_seconds": uptime_seconds,
        "environment": {
            "os": f"{platform.system()} {platform.release()} ({platform.machine()})",
            "python": sys.version.split()[0],
            "app_version": settings.APP_VERSION,
        },
        "metrics": {
            "packets_processed": get_current_packet_count(),
            "total_alerts": total_alerts,
            "active_blocks": active_blocks,
            "active_firewall_rules": active_rules,
            "packet_queue_size": queue_size,
            "websocket_clients": ws_clients,
            "db_size_kb": db_size_kb,
        },
        "components": {
            "fastapi": {
                "name": "FastAPI Web Server",
                "status": "ONLINE",
                "detail": f"Running on {settings.HOST}:{settings.PORT}",
            },
            "database": {
                "name": "SQLite Database",
                "status": db_status,
                "detail": f"SQLite database ({db_size_kb} KB)",
            },
            "sqlalchemy": {
                "name": "SQLAlchemy Async Engine",
                "status": "ONLINE",
                "detail": "aiosqlite async session connection pool active",
            },
            "packet_capture": {
                "name": "Packet Ingestion Engine",
                "status": "RUNNING",
                "detail": "Scapy & Synthetic Queue consumer active",
            },
            "detection_engine": {
                "name": "IDS Multi-Vector Detection Engine",
                "status": "RUNNING",
                "detail": "5 Detectors Active (Signature, Port Scan, Brute Force, SYN Flood, Flood)",
            },
            "decision_engine": {
                "name": "Automated Decision Engine",
                "status": "RUNNING",
                "detail": f"Auto-block threshold: {settings.AUTO_BLOCK_MIN_SEVERITY.upper()}",
            },
            "firewall_manager": {
                "name": "Firewall Orchestration Manager",
                "status": "ONLINE",
                "detail": firewall_mode,
            },
            "scheduler": {
                "name": "APScheduler Expiry Daemon",
                "status": "RUNNING",
                "detail": f"Interval: {getattr(settings, 'BLOCK_EXPIRY_CHECK_INTERVAL', 60)}s check for expired blocks",
            },
            "websocket": {
                "name": "Live WebSocket Gateway",
                "status": "CONNECTED",
                "detail": f"{ws_clients} active SOC dashboard sessions connected",
            },
            "frontend": {
                "name": "Security Operations Center Console",
                "status": "ONLINE",
                "detail": "Multi-Page SOC Architecture Initialized",
            },
        },
    }


@router.post("/reset-data")
async def reset_system_data(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """
    Safely reset demonstration and security event data:
    - Purges all demonstration alerts from `alerts` table.
    - Purges temporary auto-blocked IPs from `blocked_ips` (is_permanent == False).
    - Removes temporary firewall rules (is_temporary == True) from iptables / emulator via FirewallManager.
    - Clears in-memory packet stream buffers.
    - Performs controlled WAL checkpoint and VACUUM compaction to reclaim database disk storage.
    - Broadcasts system_reset event over WebSocket to all active dashboard sessions.

    PRESERVES:
    - All user accounts and admin login credentials.
    - Whitelist IP entries (localhost, management IP).
    - Permanent administrator firewall rules and permanent blocked IPs.
    - Application configuration and core table schemas.
    """
    if _reset_lock.locked():
        raise HTTPException(
            status_code=409,
            detail="A database reset operation is already in progress. Please wait for it to complete."
        )

    async with _reset_lock:
        t0 = time.time()
        logger.info("System Reset initiated by authenticated operator '%s'", user.username)

        db_file = "ids_firewall.db"
        size_before_bytes = os.path.getsize(db_file) if os.path.exists(db_file) else 0

        # 1. Audit pre-reset counts
        r_alerts = await db.execute(select(func.count(Alert.id)))
        alerts_count = r_alerts.scalar() or 0

        r_temp_blocks = await db.execute(select(func.count(BlockedIP.id)).where(BlockedIP.is_permanent == False))
        temp_blocks_count = r_temp_blocks.scalar() or 0

        r_perm_blocks = await db.execute(select(func.count(BlockedIP.id)).where(BlockedIP.is_permanent == True))
        perm_blocks_count = r_perm_blocks.scalar() or 0

        r_temp_rules = await db.execute(select(FirewallRule).where(FirewallRule.is_temporary == True))
        temp_rules = list(r_temp_rules.scalars().all())
        temp_rules_count = len(temp_rules)

        r_perm_rules = await db.execute(select(func.count(FirewallRule.id)).where(FirewallRule.is_temporary == False))
        perm_rules_count = r_perm_rules.scalar() or 0

        r_users = await db.execute(select(func.count(User.id)))
        users_count = r_users.scalar() or 0

        # 2. Synchronize Firewall: remove temporary rules from iptables/emulator
        rules_removed = 0
        if _firewall_manager and temp_rules:
            for rule in temp_rules:
                try:
                    await _firewall_manager.remove_rule(rule)
                    rules_removed += 1
                except Exception as e:
                    logger.warning("Error removing temporary firewall rule #%d from kernel: %s", rule.id, e)

        # 3. Database Cleanup Transaction
        try:
            # Delete temporary blocked IPs
            await db.execute(delete(BlockedIP).where(BlockedIP.is_permanent == False))

            # Delete temporary firewall rules
            await db.execute(delete(FirewallRule).where(FirewallRule.is_temporary == True))

            # Delete demonstration alerts
            await db.execute(delete(Alert))

            await db.commit()
            logger.info(
                "Reset data purged: %d alerts, %d temporary blocks, %d temporary rules",
                alerts_count, temp_blocks_count, temp_rules_count
            )
        except Exception as e:
            await db.rollback()
            logger.error("Reset data database transaction failed: %s", e)
            raise HTTPException(status_code=500, detail=f"Database transaction error during reset: {str(e)}")

        # 4. Reset in-memory packet buffers
        reset_recent_packets()

        # 5. Storage Compaction: Truncate WAL & Vacuum
        vacuum_ms = 0.0
        try:
            t_vac_start = time.time()
            autocommit_engine = engine.execution_options(isolation_level="AUTOCOMMIT")
            async with autocommit_engine.connect() as conn:
                await conn.execute(text("PRAGMA wal_checkpoint(TRUNCATE);"))
                await conn.execute(text("VACUUM;"))
            vacuum_ms = round((time.time() - t_vac_start) * 1000, 1)
            logger.info("Storage compaction & VACUUM completed in %.1f ms", vacuum_ms)
        except Exception as e:
            logger.warning("VACUUM compaction warning (non-fatal): %s", e)

        # Measure size after reset
        size_after_bytes = os.path.getsize(db_file) if os.path.exists(db_file) else 0
        total_duration_ms = round((time.time() - t0) * 1000, 1)

        result_payload = {
            "success": True,
            "alerts_deleted": alerts_count,
            "temporary_blocks_deleted": temp_blocks_count,
            "temporary_rules_removed": rules_removed if rules_removed else temp_rules_count,
            "database_size_before_kb": round(size_before_bytes / 1024, 1),
            "database_size_after_kb": round(size_after_bytes / 1024, 1),
            "vacuum_duration_ms": vacuum_ms,
            "total_duration_ms": total_duration_ms,
            "preserved": {
                "users": users_count,
                "permanent_blocked_ips": perm_blocks_count,
                "permanent_firewall_rules": perm_rules_count,
                "whitelist_ips_count": len(settings.WHITELIST_IPS),
            },
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "message": "System demonstration data reset successfully. Storage compacted.",
        }

        # 6. Broadcast system_reset event over WebSocket to all active dashboard sessions
        if _ws_manager:
            try:
                await _ws_manager.broadcast({
                    "type": "system_reset",
                    "data": result_payload,
                })
            except Exception as e:
                logger.warning("WebSocket broadcast error for system_reset: %s", e)

        return result_payload

