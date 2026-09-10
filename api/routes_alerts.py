"""
api/routes_alerts.py — Alert list endpoint and live WebSocket feed.
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from db.models import Alert, User
from db.schemas import AlertOut
from api.dependencies import get_db, get_current_user
from api.auth import decode_access_token

logger = logging.getLogger("ids.api.alerts")
router = APIRouter(prefix="/api", tags=["Alerts"])

# WebSocket manager will be injected from main.py via app.state
_ws_manager = None


def set_ws_manager(manager):
    """Called from main.py to inject the WebSocket manager."""
    global _ws_manager
    _ws_manager = manager


@router.get("/alerts", response_model=list[AlertOut])
async def list_alerts(
    response: Response,
    severity: Optional[str] = Query(None, pattern="^(low|medium|high|critical)$"),
    alert_type: Optional[str] = Query(None),
    source_ip: Optional[str] = Query(None),
    dest_ip: Optional[str] = Query(None),
    protocol: Optional[str] = Query(None),
    auto_blocked: Optional[bool] = Query(None),
    search: Optional[str] = Query(None),
    date_filter: Optional[str] = Query(None),
    sort_by: str = Query("timestamp"),
    sort_dir: str = Query("desc"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """
    List alerts with rich multi-parameter filters, search, sorting, and pagination.
    """
    from datetime import datetime, timedelta
    from sqlalchemy import func, or_

    query = select(Alert)

    if severity:
        query = query.where(Alert.severity == severity)
    if alert_type:
        query = query.where(Alert.alert_type == alert_type)
    if source_ip:
        query = query.where(Alert.source_ip.contains(source_ip))
    if dest_ip:
        query = query.where(Alert.dest_ip.contains(dest_ip))
    if protocol:
        query = query.where(Alert.protocol.ilike(protocol))
    if auto_blocked is not None:
        query = query.where(Alert.auto_blocked == auto_blocked)
    if search:
        s = f"%{search}%"
        query = query.where(
            or_(
                Alert.source_ip.like(s),
                Alert.dest_ip.like(s),
                Alert.description.like(s),
                Alert.alert_type.like(s),
            )
        )
    if date_filter:
        now = datetime.utcnow()
        if date_filter == "today":
            today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
            query = query.where(Alert.timestamp >= today_start)
        elif date_filter in ["24h", "yesterday"]:
            query = query.where(Alert.timestamp >= now - timedelta(hours=24))
        elif date_filter == "7d":
            query = query.where(Alert.timestamp >= now - timedelta(days=7))

    # Count total matching
    count_query = select(func.count()).select_from(query.subquery())
    total_count_res = await db.execute(count_query)
    total_count = total_count_res.scalar() or 0
    response.headers["X-Total-Count"] = str(total_count)

    # Sorting
    sort_column = Alert.timestamp
    if sort_by == "severity":
        sort_column = Alert.severity
    elif sort_by == "source_ip":
        sort_column = Alert.source_ip
    elif sort_by == "id":
        sort_column = Alert.id

    if sort_dir.lower() == "asc":
        query = query.order_by(sort_column.asc())
    else:
        query = query.order_by(sort_column.desc())

    query = query.offset(offset).limit(limit)
    result = await db.execute(query)
    alerts = result.scalars().all()

    return alerts


@router.get("/alerts/{alert_id}", response_model=AlertOut)
async def get_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Fetch a single alert by ID."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    """
    WebSocket endpoint for live alert streaming.

    Clients connect with:
        ws://host:port/ws/alerts?token=<JWT>

    The token is validated on connection.  Once connected, the client
    receives JSON messages for every new alert and block/unblock event.
    """
    # Authenticate via query parameter token
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=4001, reason="Missing token")
        return

    payload = decode_access_token(token)
    if not payload:
        await websocket.close(code=4001, reason="Invalid or expired token")
        return

    if _ws_manager is None:
        await websocket.close(code=4500, reason="Server not ready")
        return

    await _ws_manager.connect(websocket)

    try:
        # Keep the connection alive — wait for client messages (e.g. ping)
        while True:
            data = await websocket.receive_text()
            # Clients can send "ping" to keep alive
            if data == "ping":
                await websocket.send_text('{"type": "pong"}')
    except WebSocketDisconnect:
        _ws_manager.disconnect(websocket)
    except Exception as e:
        logger.error("WebSocket error: %s", e)
        _ws_manager.disconnect(websocket)
