"""
api/websocket_manager.py — WebSocket connection manager for live dashboard updates.

Manages a set of connected WebSocket clients and provides a broadcast
method to push new alerts and block events to all of them simultaneously.
"""

import json
import logging
from typing import Set
from fastapi import WebSocket

logger = logging.getLogger("ids.websocket")


class WebSocketManager:
    """
    Manages active WebSocket connections and broadcasts events.

    Usage:
        manager = WebSocketManager()
        await manager.connect(websocket)         # on new WS connection
        await manager.broadcast({"type": "new_alert", "data": {...}})
        manager.disconnect(websocket)             # on WS disconnect
    """

    def __init__(self):
        self._connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket):
        """Accept and register a new WebSocket connection."""
        await websocket.accept()
        self._connections.add(websocket)
        logger.info(
            "WebSocket connected — %d active connections",
            len(self._connections),
        )

    def disconnect(self, websocket: WebSocket):
        """Remove a disconnected WebSocket."""
        self._connections.discard(websocket)
        logger.info(
            "WebSocket disconnected — %d active connections",
            len(self._connections),
        )

    async def broadcast(self, message: dict):
        """
        Send a JSON message to ALL connected WebSocket clients.

        Silently removes clients that have disconnected.
        """
        if not self._connections:
            return

        payload = json.dumps(message, default=str)
        dead = set()

        for ws in self._connections:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.add(ws)

        # Clean up dead connections
        for ws in dead:
            self._connections.discard(ws)

    @property
    def connection_count(self) -> int:
        return len(self._connections)
