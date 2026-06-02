"""Write-blocker (бичих хориг) — төхөөрөмжийг зөвхөн унших болгох.

Forensic зарчмын дагуу шинжилгээ эхлэхээс өмнө блок төхөөрөмжийг kernel
түвшинд зөвхөн унших болгоно (`blockdev --setro`). Mount шаардлагатай бол
`ro,noexec,nodev` тугтай хийнэ.

Бүх үйлдэл root эрх шаардана. Linux биш орчинд mock үр дүн буцаана.
"""
from __future__ import annotations

import logging
import platform
import tempfile

from app.config import get_settings
from app.services import tools

logger = logging.getLogger("rea.writeblock")
settings = get_settings()

IS_LINUX = platform.system() == "Linux"


class WriteBlockError(RuntimeError):
    pass


def set_read_only(dev_path: str) -> bool:
    """`blockdev --setro` ашиглан төхөөрөмжийг зөвхөн унших болгоно."""
    if not IS_LINUX or not tools.is_available("blockdev"):
        if settings.allow_mock:
            logger.info("[mock] %s -> read-only", dev_path)
            return True
        raise WriteBlockError("blockdev байхгүй — read-only тохируулах боломжгүй.")

    result = tools.run(["blockdev", "--setro", dev_path])
    if not result.ok:
        raise WriteBlockError(f"blockdev --setro амжилтгүй: {result.stderr.strip()}")
    return True


def is_read_only(dev_path: str) -> bool:
    """`blockdev --getro` — 1 бол зөвхөн унших."""
    if not IS_LINUX or not tools.is_available("blockdev"):
        return settings.allow_mock

    result = tools.run(["blockdev", "--getro", dev_path])
    if not result.ok:
        return False
    return result.stdout.strip() == "1"


def mount_read_only(dev_path: str, mount_point: str | None = None) -> str:
    """Төхөөрөмжийг зөвхөн унших горимоор mount хийж, mount цэгийг буцаана.

    `ro,noexec,nodev,noload` тугуудаар бичилт болон journal replay-ээс сэргийлнэ.
    """
    if mount_point is None:
        mount_point = tempfile.mkdtemp(prefix="rea_ro_")

    if not IS_LINUX or not tools.is_available("mount"):
        if settings.allow_mock:
            logger.info("[mock] %s -> %s (ro)", dev_path, mount_point)
            return mount_point
        raise WriteBlockError("mount байхгүй.")

    # noload нь ext journal-ийн replay-ийг (бичилт) хориглоно.
    opts = "ro,noexec,nodev,noload"
    result = tools.run(["mount", "-o", opts, dev_path, mount_point])
    if not result.ok:
        # noload зарим FS дээр дэмжигдэхгүй тул дахин оролдоно.
        result = tools.run(["mount", "-o", "ro,noexec,nodev", dev_path, mount_point])
        if not result.ok:
            raise WriteBlockError(f"mount амжилтгүй: {result.stderr.strip()}")
    return mount_point


def unmount(mount_point: str) -> None:
    if not IS_LINUX or not tools.is_available("umount"):
        return
    tools.run(["umount", mount_point])
