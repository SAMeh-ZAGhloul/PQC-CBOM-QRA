"""In-memory WebSocket connection manager."""
from __future__ import annotations

from collections import defaultdict

from fastapi import WebSocket


class WebSocketManager:
    def __init__(self) -> None:
        self._connections: dict[str, list[WebSocket]] = defaultdict(list)

    async def connect(self, channel: str, websocket: WebSocket) -> None:
        await websocket.accept()
        self._connections[channel].append(websocket)

    def disconnect(self, channel: str, websocket: WebSocket) -> None:
        if websocket in self._connections[channel]:
            self._connections[channel].remove(websocket)

    async def broadcast(self, channel: str, message: dict) -> None:
        for websocket in list(self._connections[channel]):
            await websocket.send_json(message)


manager = WebSocketManager()
