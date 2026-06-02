"""Идэvхтэй (устгагдаагүй) файлуудын каталог — read-only mount walk.

TSK fls body format зарим NTFS/FAT дээр амжилтгүй байж болох тул бодит
төхөөрөмж дээр mount-оос бүх файлыг os.walk-аар цуглуулна. Mount байхгүй
бол TSK fls -r -m (without -d) fallback ашиглана.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from app.config import get_settings
from app.services import metadata

logger = logging.getLogger("rea.active_files")
settings = get_settings()

_SKIP_DIRS = {
    ".Trash-1000",
    "$Recycle.Bin",
    "System Volume Information",
    ".Spotlight-V100",
    ".Trashes",
    ".fseventsd",
}


@dataclass
class LiveFileEntry:
    file_name: str
    original_path: str
    size_bytes: int
    mtime: datetime | None = None
    atime: datetime | None = None
    ctime: datetime | None = None
    crtime: datetime | None = None
    content_path: str = ""
    source_tool: str = "mount-walk"
    meta: dict = field(default_factory=dict)


def _ts_from_stat(st, attr: str) -> datetime | None:
    try:
        val = getattr(st, attr, None)
        if val is None:
            return None
        return datetime.fromtimestamp(val, tz=timezone.utc)
    except (OSError, OverflowError, ValueError):
        return None


def scan_mount(mount_root: str | None, *, max_files: int = 200_000) -> list[LiveFileEntry]:
    """Read-only mount дээрх бүх идэвхтэй файлыг жагсаана."""
    if not mount_root or not os.path.isdir(mount_root):
        if settings.allow_mock:
            return _mock_live_files()
        return []

    entries: list[LiveFileEntry] = []
    seen: set[str] = set()

    for dirpath, dirnames, filenames in os.walk(mount_root, topdown=True):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.startswith("$")]

        rel_dir = os.path.relpath(dirpath, mount_root).replace("\\", "/")
        if rel_dir == ".":
            rel_dir = ""

        for fn in filenames:
            if len(entries) >= max_files:
                logger.warning("Mount walk хязгаарт хүрсэн (%d файл)", max_files)
                break
            full = os.path.join(dirpath, fn)
            rel = f"{rel_dir}/{fn}".lstrip("/")
            key = rel.lower()
            if key in seen:
                continue
            seen.add(key)

            try:
                st = os.stat(full, follow_symlinks=False)
            except OSError:
                continue
            if not os.path.isfile(full):
                continue

            entries.append(
                LiveFileEntry(
                    file_name=fn,
                    original_path=f"/{rel}",
                    size_bytes=st.st_size,
                    mtime=_ts_from_stat(st, "st_mtime"),
                    atime=_ts_from_stat(st, "st_atime"),
                    ctime=_ts_from_stat(st, "st_ctime"),
                    crtime=_ts_from_stat(st, "st_birthtime") if hasattr(st, "st_birthtime") else _ts_from_stat(st, "st_ctime"),
                    content_path=full,
                    meta={
                        "module": "active_file_inventory",
                        "scan_method": "mount_walk",
                        "mime_guess": metadata.guess_mime(full, fn),
                        "on_device": True,
                    },
                )
            )

        if len(entries) >= max_files:
            break

    logger.info("Mount walk: %d идэвхтэй файл (%s)", len(entries), mount_root)
    if not entries and settings.allow_mock:
        return _mock_live_files()
    return entries


def _mock_live_files() -> list[LiveFileEntry]:
    now = datetime.now(timezone.utc)
    samples = [
        ("/Documents/1.pptx", 276000),
        ("/Documents/Dorjzovd.docx", 146000),
        ("/Documents/FINALFINAL.xlsx", 16000),
        ("/Documents/Asuulga.png", 12000),
        ("/Pictures/photo_2021.jpg", 2483920),
        ("/readme.txt", 2048),
    ]
    return [
        LiveFileEntry(
            file_name=Path(path).name,
            original_path=path,
            size_bytes=size,
            mtime=now,
            atime=now,
            ctime=now,
            crtime=now,
            meta={"mock": True, "module": "active_file_inventory"},
        )
        for path, size in samples
    ]
