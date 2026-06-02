"""FastAPI entrypoint — Removable Evidence Analyzer backend."""
from __future__ import annotations

import asyncio
import logging
import platform
import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.config import get_settings
from app.core.events import hub
from app.database import init_db
from app.services import device as device_svc
from app.services import writeblock

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("rea.main")

settings = get_settings()


def _hotplug_worker() -> None:
    def on_event(action: str, dev) -> None:
        payload = dev.to_dict() if hasattr(dev, "to_dict") else dev
        hub.publish("device_hotplug", {"action": action, "device": payload})

    try:
        device_svc.monitor_hotplug(on_event)
    except Exception:  # noqa: BLE001
        logger.exception("Hot-plug monitor зогслоо")

REQUIRED_TOOLS = [
    "mmls",
    "fls",
    "icat",
    "blkls",
    "tsk_recover",
    "ntfsundelete",
    "photorec",
    "foremost",
    "scalpel",
    "lsblk",
    "blockdev",
]


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    hub.bind_loop(asyncio.get_running_loop())
    if platform.system() == "Linux":
        threading.Thread(target=_hotplug_worker, daemon=True).start()
    yield


app = FastAPI(
    title="Removable Evidence Analyzer",
    description="Зөөврийн мэдээлэл тээгчийн тоон ул мөрийг read-only горимоор шинжлэх forensic систем.",
    version=__version__,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health", tags=["system"])
def health() -> dict:
    """Системийн төлөв ба forensic хэрэгслүүдийн бэлэн байдал."""
    tools = {name: settings.tool_available(name) for name in REQUIRED_TOOLS}
    all_ready = all(tools.values())
    is_linux = platform.system() == "Linux"
    as_root = writeblock.running_as_root() if is_linux else None
    return {
        "status": "ok",
        "version": __version__,
        "platform": platform.system(),
        "mock_mode": (not all_ready) and settings.allow_mock,
        "tools": tools,
        "tools_ready": all_ready,
        "running_as_root": as_root,
        "device_access_ok": (not is_linux) or as_root or settings.allow_mock,
    }


# Routers (доорх алхмуудад бүртгэгдэнэ)
from app.api import cases, devices, findings, reports, scans, stats, ws  # noqa: E402

app.include_router(devices.router)
app.include_router(cases.router)
app.include_router(scans.router)
app.include_router(findings.router)
app.include_router(reports.router)
app.include_router(stats.router)
app.include_router(ws.router)
