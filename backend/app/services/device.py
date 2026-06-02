"""Зөөврийн төхөөрөмж илрүүлэх (lsblk) ба hot-plug мониторинг (pyudev).

Linux дээр `lsblk -J -O`-ээр блок төхөөрөмжүүдийг JSON хэлбэрээр авч, зөөврийн
(removable / usb / mmc) дискийг ялгана. Forensic CLI/Linux байхгүй орчинд
(Windows/Mac dev) mock төхөөрөмж буцаана.
"""
from __future__ import annotations

import json
import logging
import platform
from dataclasses import asdict, dataclass
from typing import Any, Callable

from app.config import get_settings
from app.services import tools

logger = logging.getLogger("rea.device")
settings = get_settings()

IS_LINUX = platform.system() == "Linux"


@dataclass
class DetectedDevice:
    dev_path: str
    name: str
    serial: str
    bus: str
    size_bytes: int
    fs_type: str
    is_removable: bool
    details: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


_MOCK_DEVICES = [
    DetectedDevice(
        dev_path="/dev/sdb",
        name="SanDisk Ultra USB 3.0",
        serial="4C530001230607118280",
        bus="usb",
        size_bytes=16_000_000_000,
        fs_type="ntfs",
        is_removable=True,
        details={"model": "Ultra", "vendor": "SanDisk", "mock": True},
    ),
    DetectedDevice(
        dev_path="/dev/mmcblk0",
        name="Generic SD Card",
        serial="SD32G-0001",
        bus="mmc",
        size_bytes=32_000_000_000,
        fs_type="vfat",
        is_removable=True,
        details={"model": "SD32G", "vendor": "Generic", "mock": True},
    ),
]


def _parse_size(value: Any) -> int:
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return 0


def _walk_lsblk(node: dict[str, Any]) -> DetectedDevice | None:
    """lsblk JSON node-оос DetectedDevice бэлтгэнэ (зөвхөн disk түвшин)."""
    if node.get("type") != "disk":
        return None

    is_removable = bool(int(node.get("rm", 0) or 0)) or node.get("hotplug") in (True, "1", 1)
    tran = node.get("tran") or ""
    # USB / MMC / зөөврийн дискийг forensic ач холбогдолтой гэж үзнэ.
    if not is_removable and tran not in ("usb", "mmc"):
        return None

    name = node.get("name", "")
    dev_path = node.get("path") or f"/dev/{name}"

    # Файлын системийн төрлийг хүүхэд хуваалтаас авч болно.
    fs_type = node.get("fstype") or ""
    if not fs_type:
        for child in node.get("children", []) or []:
            if child.get("fstype"):
                fs_type = child["fstype"]
                break

    vendor = (node.get("vendor") or "").strip()
    model = (node.get("model") or "").strip()
    label = " ".join(p for p in (vendor, model) if p) or name

    return DetectedDevice(
        dev_path=dev_path,
        name=label,
        serial=(node.get("serial") or "").strip(),
        bus=tran,
        size_bytes=_parse_size(node.get("size")),
        fs_type=fs_type,
        is_removable=True,
        details={
            "vendor": vendor,
            "model": model,
            "rota": node.get("rota"),
            "ro": node.get("ro"),
            "children": [
                {
                    "name": c.get("name"),
                    "fstype": c.get("fstype"),
                    "size": c.get("size"),
                    "label": c.get("label"),
                }
                for c in (node.get("children") or [])
            ],
        },
    )


def list_removable_devices() -> list[DetectedDevice]:
    """Системд холбогдсон зөөврийн төхөөрөмжүүдийг жагсаана."""
    if not IS_LINUX or not tools.is_available("lsblk"):
        if settings.allow_mock:
            logger.info("lsblk байхгүй — mock төхөөрөмж буцааж байна.")
            return list(_MOCK_DEVICES)
        return []

    cols = "NAME,PATH,TYPE,RM,HOTPLUG,SIZE,VENDOR,MODEL,SERIAL,TRAN,FSTYPE,RO,ROTA,LABEL"
    result = tools.run(["lsblk", "-J", "-b", "-o", cols])
    if not result.ok:
        logger.warning("lsblk алдаа: %s", result.stderr)
        return []

    try:
        data = json.loads(result.stdout or "{}")
    except json.JSONDecodeError:
        logger.warning("lsblk JSON parse алдаа.")
        return []

    devices: list[DetectedDevice] = []
    for node in data.get("blockdevices", []):
        dev = _walk_lsblk(node)
        if dev:
            devices.append(dev)
    return devices


def get_device(dev_path: str) -> DetectedDevice | None:
    """Тодорхой dev_path-аар нэг төхөөрөмжийн мэдээллийг авна."""
    for dev in list_removable_devices():
        if dev.dev_path == dev_path:
            return dev
    return None


def monitor_hotplug(on_event: Callable[[str, DetectedDevice | dict], None]) -> None:
    """pyudev-ээр блок төхөөрөмжийн add/remove үйл явдлыг сонсоно (blocking).

    on_event(action, device) — action нь "add" | "remove".
    Энэ функц нь тусдаа thread дотор ажиллах ёстой.
    """
    if not IS_LINUX:
        logger.info("Hot-plug monitor зөвхөн Linux дээр идэвхжинэ.")
        return
    try:
        import pyudev  # type: ignore
    except ImportError:
        logger.warning("pyudev суулгагдаагүй — hot-plug monitor идэвхгүй.")
        return

    context = pyudev.Context()
    monitor = pyudev.Monitor.from_netlink(context)
    monitor.filter_by(subsystem="block")
    logger.info("Hot-plug monitor эхэллээ.")

    for udev_device in iter(monitor.poll, None):
        if udev_device.get("DEVTYPE") != "disk":
            continue
        action = udev_device.action
        dev_path = udev_device.device_node
        if action == "add":
            detected = get_device(dev_path) or {"dev_path": dev_path}
            on_event("add", detected)
        elif action == "remove":
            on_event("remove", {"dev_path": dev_path})
