"""Write-blocker (бичих хориг) — төхөөрөмжийг зөвхөн унших болгох.

Forensic зарчмын дагуу шинжилгээ эхлэхээс өмнө блок төхөөрөмжийг kernel
түвшинд зөвхөн унших болгоно (`blockdev --setro`). Mount шаардлагатай бол
`ro,noexec,nodev` тугтай хийнэ.

Бүх үйлдэл root эрх шаардана. Linux биш орчинд mock үр дүн буцаана.
"""
from __future__ import annotations

import logging
import os
import platform
import tempfile

from app.config import get_settings
from app.services import tools

logger = logging.getLogger("rea.writeblock")
settings = get_settings()

IS_LINUX = platform.system() == "Linux"


class WriteBlockError(RuntimeError):
    pass


def running_as_root() -> bool:
    """Linux дээр root (euid=0) эсэх."""
    if not IS_LINUX:
        return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def _fail(operation: str, dev_path: str, stderr: str) -> None:
    """blockdev/mount алдааг ойлгомжтой монгол мессеж болгоно."""
    err = (stderr or "").strip()
    low = err.lower()
    if "permission denied" in low or "operation not permitted" in low:
        raise WriteBlockError(
            f"{operation} амжилтгүй ({dev_path}): root эрх шаардлагатай. "
            "Backend-ийг sudo-оор ажиллуулна уу:\n"
            "  cd backend && source .venv/bin/activate\n"
            "  sudo $(which uvicorn) app.main:app --host 0.0.0.0 --port 8000"
        )
    if "device or resource busy" in low or "target is busy" in low:
        raise WriteBlockError(
            f"{operation} амжилтгүй ({dev_path}): төхөөрөмж mount хийгдсэн эсвэл ашиглагдаж байна. "
            "Эхлээд unmount хийнэ үү: sudo umount /dev/sdb*"
        )
    raise WriteBlockError(f"{operation} амжилтгүй ({dev_path}): {err or 'unknown error'}")


def set_read_only(dev_path: str) -> bool:
    """`blockdev --setro` ашиглан төхөөрөмжийг зөвхөн унших болгоно."""
    if not IS_LINUX or not tools.is_available("blockdev"):
        if settings.allow_mock:
            logger.info("[mock] %s -> read-only", dev_path)
            return True
        raise WriteBlockError("blockdev байхгүй — read-only тохируулах боломжгүй.")

    if not running_as_root():
        raise WriteBlockError(
            f"Write-block ({dev_path}): backend root эрхгүй ажиллаж байна. "
            "sudo uvicorn app.main:app --host 0.0.0.0 --port 8000"
        )

    result = tools.run(["blockdev", "--setro", dev_path])
    if not result.ok:
        _fail("blockdev --setro", dev_path, result.stderr)
    return True


def is_read_only(dev_path: str) -> bool:
    """`blockdev --getro` — 1 бол зөвхөн унших."""
    if not IS_LINUX or not tools.is_available("blockdev"):
        return settings.allow_mock

    result = tools.run(["blockdev", "--getro", dev_path])
    if not result.ok:
        return False
    return result.stdout.strip() == "1"


def detect_fstype(dev_path: str) -> str:
    """blkid-ээр файлын системийн төрлийг тодорхойлно (ntfs, vfat, exfat…)."""
    if not IS_LINUX or not tools.is_available("blkid"):
        return ""
    result = tools.run(["blkid", "-o", "value", "-s", "TYPE", dev_path])
    if result.ok and result.stdout.strip():
        return result.stdout.strip().lower()
    return ""


def _mount_attempt(dev_path: str, mount_point: str, opts: str, fstype: str | None = None) -> bool:
    args = ["mount"]
    if fstype:
        args += ["-t", fstype]
    args += ["-o", opts, dev_path, mount_point]
    return tools.run(args).ok


def mount_read_only(dev_path: str, mount_point: str | None = None, *, fs_type: str = "") -> str:
    """Төхөөрөмжийг зөвхөн унших горимоор mount хийж, mount цэгийг буцаана.

    USB flash (NTFS/exFAT/FAT32) дээр `-t ntfs-3g` / `exfat` / `vfat` ашиглана.
    """
    if mount_point is None:
        mount_point = tempfile.mkdtemp(prefix="rea_ro_")

    if not IS_LINUX or not tools.is_available("mount"):
        if settings.allow_mock:
            logger.info("[mock] %s -> %s (ro)", dev_path, mount_point)
            return mount_point
        raise WriteBlockError("mount байхгүй.")

    if not running_as_root():
        raise WriteBlockError(
            f"Mount ({dev_path}): backend root эрхгүй. "
            "sudo uvicorn app.main:app --host 0.0.0.0 --port 8000"
        )

    fs = (fs_type or detect_fstype(dev_path)).lower()
    opts_list = ["ro,noexec,nodev,noload", "ro,noexec,nodev"]

    # FS төрлөөр mount оролдлого — Windows USB ихэнхдээ NTFS/exFAT.
    fstype_candidates: list[str | None] = []
    if fs in ("ntfs",):
        fstype_candidates = ["ntfs-3g", "ntfs", None]
    elif fs in ("exfat",):
        fstype_candidates = ["exfat", None]
    elif fs in ("vfat", "fat", "fat32", "msdos"):
        fstype_candidates = ["vfat", None]
    else:
        fstype_candidates = ["ntfs-3g", "exfat", "vfat", None]

    for opts in opts_list:
        for fstype in fstype_candidates:
            if _mount_attempt(dev_path, mount_point, opts, fstype):
                logger.info("Mount OK: %s -> %s (type=%s, opts=%s)", dev_path, mount_point, fstype or "auto", opts)
                return mount_point

    _fail("mount", dev_path, f"FS={fs or 'unknown'} — ntfs-3g/exfat-utils суулгасан эсэхийг шалгана уу")
    return mount_point  # unreachable


def unmount(mount_point: str) -> None:
    if not IS_LINUX or not tools.is_available("umount"):
        return
    tools.run(["umount", mount_point])
