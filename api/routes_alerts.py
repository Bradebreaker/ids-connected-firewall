"""
api/routes_alerts.py — Alert list endpoint and live WebSocket feed.
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect
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
    severity: Optional[str] = Query(None, pattern="^(low|medium|high)$"),
    alert_type: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """
    List alerts with optional filters, newest first.

    Query params:
        - severity: filter by low/medium/high
        - alert_type: filter by signature/port_scan/brute_force/syn_flood
        - limit: max results (default 50, max 500)
        - offset: pagination offset
    """
    query = select(Alert).order_by(desc(Alert.timestamp))

    if severity:
        query = query.where(Alert.severity == severity)
    if alert_type:
        query = query.where(Alert.alert_type == alert_type)

    query = query.offset(offset).limit(limit)
    result = await db.execute(query)
    alerts = result.scalars().all()

    return alerts


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
