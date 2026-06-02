"""WebSocket event hub — scan progress болон device hot-plug мэдэгдлийг түгээх.

Scan ажил нь тусдаа thread дотор ажилладаг тул thread-аас asyncio event loop руу
аюулгүй publish хийхийн тулд `run_coroutine_threadsafe` ашиглана.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

logger = logging.getLogger("rea.events")


class EventHub:
    def __init__(self) -> None:
        self._clients: set[Any] = set()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._lock = asyncio.Lock()

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    async def connect(self, websocket: Any) -> None:
        await websocket.accept()
        async with self._lock:
            self._clients.add(websocket)
        logger.debug("WS холбогдов (нийт %d)", len(self._clients))

    async def disconnect(self, websocket: Any) -> None:
        async with self._lock:
            self._clients.discard(websocket)

    async def _broadcast(self, message: dict) -> None:
        payload = json.dumps(message, default=str)
        dead: list[Any] = []
        for ws in list(self._clients):
            try:
                await ws.send_text(payload)
            except Exception:  # noqa: BLE001
                dead.append(ws)
        for ws in dead:
            self._clients.discard(ws)

    def publish(self, event_type: str, data: dict) -> None:
        """Аль ч thread-аас дуудаж болох sync publish."""
        message = {"type": event_type, "data": data}
        if self._loop is None:
            logger.debug("Loop bind хийгдээгүй — event алгасав: %s", event_type)
            return
        try:
            asyncio.run_coroutine_threadsafe(self._broadcast(message), self._loop)
        except RuntimeError:
            logger.debug("Event loop ажиллахгүй байна.")


hub = EventHub()
