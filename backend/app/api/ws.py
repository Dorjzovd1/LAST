"""WebSocket endpoint — scan progress, device hot-plug мэдэгдэл."""
from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.core.events import hub

logger = logging.getLogger("rea.ws")
router = APIRouter(tags=["websocket"])


@router.websocket("/ws/events")
async def events_ws(websocket: WebSocket) -> None:
    """Frontend энэ сувгаар бүх real-time үйл явдлыг хүлээн авна."""
    # Эхний холболтод event loop-ийг hub-д холбоно (thread-аас publish хийхэд хэрэгтэй).
    hub.bind_loop(asyncio.get_running_loop())
    await hub.connect(websocket)
    try:
        await websocket.send_json({"type": "connected", "data": {"message": "REA event stream холбогдлоо"}})
        while True:
            # Клиентээс ирэх ping/мессежийг хүлээнэ (холболтыг нээлттэй байлгана).
            await websocket.receive_text()
    except WebSocketDisconnect:
        await hub.disconnect(websocket)
    except Exception:  # noqa: BLE001
        await hub.disconnect(websocket)
