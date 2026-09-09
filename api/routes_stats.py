"""
api/routes_stats.py — Dashboard statistics endpoint.
"""

import logging
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc

from db.models import Alert, BlockedIP, User
from db.schemas import StatsResponse
from api.dependencies import get_db, get_current_user

logger = logging.getLogger("ids.api.stats")
router = APIRouter(prefix="/api", tags=["Statistics"])


@router.get("/stats", response_model=StatsResponse)
async def get_stats(
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """
    Returns a snapshot of dashboard statistics:
        - Total alerts, alerts today
        - Alerts broken down by severity and type
        - Active block count
        - Top attacker IP (most alerts)
        - Alerts per hour for the last 24 hours
        - Current threat level
    """
    now = datetime.utcnow()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    yesterday = now - timedelta(hours=24)

    # Total alerts
    total_result = await db.execute(select(func.count(Alert.id)))
    total_alerts = total_result.scalar() or 0

    # Alerts today
    today_result = await db.execute(
        select(func.count(Alert.id)).where(Alert.timestamp >= today_start)
    )
    alerts_today = today_result.scalar() or 0

    # Alerts by severity
    severity_counts = {"low": 0, "medium": 0, "high": 0}
    for sev in severity_counts:
        r = await db.execute(
            select(func.count(Alert.id)).where(Alert.severity == sev)
        )
        severity_counts[sev] = r.scalar() or 0

    # Alerts by type
    type_counts = {"signature": 0, "port_scan": 0, "brute_force": 0, "syn_flood": 0}
    for atype in type_counts:
        r = await db.execute(
            select(func.count(Alert.id)).where(Alert.alert_type == atype)
        )
        type_counts[atype] = r.scalar() or 0

    # Active blocks
    blocks_result = await db.execute(select(func.count(BlockedIP.id)))
    active_blocks = blocks_result.scalar() or 0

    # Top attacker (IP with most alerts)
    top_result = await db.execute(
        select(Alert.source_ip, func.count(Alert.id).label("cnt"))
        .group_by(Alert.source_ip)
        .order_by(desc("cnt"))
        .limit(1)
    )
    top_row = top_result.first()
    top_attacker = top_row[0] if top_row else None

    # Alerts per hour (last 24h)
    alerts_per_hour = []
    for h in range(24):
        hour_start = yesterday + timedelta(hours=h)
        hour_end   = hour_start + timedelta(hours=1)
        r = await db.execute(
            select(func.count(Alert.id)).where(
                Alert.timestamp >= hour_start,
                Alert.timestamp < hour_end,
            )
        )
        count = r.scalar() or 0
        alerts_per_hour.append({
            "hour": hour_start.isoformat(),
            "count": count,
        })

    # Threat level heuristic
    recent_high = await db.execute(
        select(func.count(Alert.id)).where(
            Alert.severity == "high",
            Alert.timestamp >= now - timedelta(minutes=15),
        )
    )
    recent_high_count = recent_high.scalar() or 0

    recent_medium = await db.execute(
        select(func.count(Alert.id)).where(
            Alert.severity == "medium",
            Alert.timestamp >= now - timedelta(minutes=15),
        )
    )
    recent_medium_count = recent_medium.scalar() or 0

    if recent_high_count >= 5:
        threat_level = "critical"
    elif recent_high_count >= 2:
        threat_level = "high"
    elif recent_medium_count >= 5 or recent_high_count >= 1:
        threat_level = "medium"
    else:
        threat_level = "low"

    return StatsResponse(
        total_alerts=total_alerts,
        alerts_today=alerts_today,
        alerts_by_severity=severity_counts,
        alerts_by_type=type_counts,
        active_blocks=active_blocks,
        top_attacker=top_attacker,
        alerts_per_hour=alerts_per_hour,
        threat_level=threat_level,
    )
