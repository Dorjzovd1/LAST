"""Recycle Bin / Trash artifact задлан шинжлэх.

- NTFS (Windows): $Recycle.Bin/<SID>/$I* (метадата) + $R* (агуулга).
  $I файл нь устгасан файлын эх зам, хэмжээ, устгасан огноог агуулна.
- Linux Trash spec: .Trash-<uid>/info/*.trashinfo + files/*.

Энэ модуль нь зөвхөн унших горимоор mount хийсэн файлын системийн root зам дээр
ажиллана. Mount хийх боломжгүй (mock) орчинд жишээ artifact буцаана.
"""
from __future__ import annotations

import logging
import os
import struct
from configparser import ConfigParser
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import unquote

from app.config import get_settings

logger = logging.getLogger("rea.recycle")
settings = get_settings()

# Windows FILETIME (1601-01-01) -> Unix epoch (1970-01-01) дискрепанс (секунд).
_FILETIME_EPOCH_DIFF = 11_644_473_600


@dataclass
class RecycleArtifact:
    original_path: str
    deleted_time: datetime | None
    size: int
    source: str                 # "ntfs" | "trash"
    content_path: str = ""      # $R эсвэл files/ доторх бодит агуулга (байгаа бол)
    meta: dict = field(default_factory=dict)


def _filetime_to_dt(filetime: int) -> datetime | None:
    if filetime <= 0:
        return None
    seconds = filetime / 10_000_000 - _FILETIME_EPOCH_DIFF
    try:
        return datetime.fromtimestamp(seconds, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


# --------------------------------------------------------------------------- #
# NTFS $Recycle.Bin
# --------------------------------------------------------------------------- #
def parse_i_file(path: str) -> RecycleArtifact | None:
    """NTFS $I metadata файлыг задлан задлана (Vista+ формат, v1/v2)."""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    if len(data) < 24:
        return None

    header = struct.unpack("<q", data[0:8])[0]
    file_size = struct.unpack("<q", data[8:16])[0]
    del_ft = struct.unpack("<q", data[16:24])[0]

    original_path = ""
    try:
        if header == 2 and len(data) >= 28:
            name_len = struct.unpack("<i", data[24:28])[0]
            raw = data[28 : 28 + name_len * 2]
            original_path = raw.decode("utf-16-le", errors="ignore").rstrip("\x00")
        else:
            # v1: 520 bytes тогтмол UTF-16LE зам (260 wchar).
            raw = data[24:544]
            original_path = raw.decode("utf-16-le", errors="ignore").rstrip("\x00")
    except Exception:  # noqa: BLE001
        original_path = ""

    # Харгалзах $R агуулгыг хайна ($I<id> -> $R<id>).
    content_path = ""
    base = os.path.basename(path)
    if base.startswith("$I"):
        candidate = os.path.join(os.path.dirname(path), "$R" + base[2:])
        if os.path.exists(candidate):
            content_path = candidate

    return RecycleArtifact(
        original_path=original_path,
        deleted_time=_filetime_to_dt(del_ft),
        size=file_size,
        source="ntfs",
        content_path=content_path,
        meta={"i_file": path, "version": header},
    )


def scan_ntfs_recycle(root: str) -> list[RecycleArtifact]:
    artifacts: list[RecycleArtifact] = []
    for dirpath, _dirs, files in os.walk(root):
        if os.path.basename(dirpath.rstrip("/\\")).lower() != "$recycle.bin" and "$recycle.bin" not in dirpath.lower():
            continue
        for fn in files:
            if fn.startswith("$I"):
                art = parse_i_file(os.path.join(dirpath, fn))
                if art:
                    artifacts.append(art)
    return artifacts


# --------------------------------------------------------------------------- #
# Linux Trash spec
# --------------------------------------------------------------------------- #
def parse_trashinfo(path: str) -> RecycleArtifact | None:
    parser = ConfigParser(interpolation=None)
    try:
        parser.read(path, encoding="utf-8")
    except Exception:  # noqa: BLE001
        return None
    if not parser.has_section("Trash Info"):
        return None
    section = parser["Trash Info"]
    original_path = unquote(section.get("Path", ""))
    deleted_raw = section.get("DeletionDate", "")
    deleted_time: datetime | None = None
    if deleted_raw:
        try:
            deleted_time = datetime.fromisoformat(deleted_raw).replace(tzinfo=timezone.utc)
        except ValueError:
            deleted_time = None

    # Харгалзах агуулга: ../files/<name>
    content_path = ""
    info_dir = os.path.dirname(path)
    files_dir = os.path.join(os.path.dirname(info_dir), "files")
    name = os.path.basename(path)
    if name.endswith(".trashinfo"):
        candidate = os.path.join(files_dir, name[: -len(".trashinfo")])
        if os.path.exists(candidate):
            content_path = candidate

    size = os.path.getsize(content_path) if content_path and os.path.exists(content_path) else 0
    return RecycleArtifact(
        original_path=original_path,
        deleted_time=deleted_time,
        size=size,
        source="trash",
        content_path=content_path,
        meta={"trashinfo": path},
    )


def scan_linux_trash(root: str) -> list[RecycleArtifact]:
    artifacts: list[RecycleArtifact] = []
    for dirpath, _dirs, files in os.walk(root):
        if os.path.basename(dirpath) != "info":
            continue
        if ".trash" not in dirpath.lower() and "trash" not in os.path.basename(os.path.dirname(dirpath)).lower():
            continue
        for fn in files:
            if fn.endswith(".trashinfo"):
                art = parse_trashinfo(os.path.join(dirpath, fn))
                if art:
                    artifacts.append(art)
    return artifacts


def scan_recycle(root: str | None) -> list[RecycleArtifact]:
    """Mount цэг дээрх NTFS болон Linux trash artifact-уудыг цуглуулна."""
    if not root or not os.path.isdir(root):
        if settings.allow_mock:
            return _mock_artifacts()
        return []
    artifacts = scan_ntfs_recycle(root) + scan_linux_trash(root)
    if not artifacts and settings.allow_mock:
        return _mock_artifacts()
    return artifacts


def _mock_artifacts() -> list[RecycleArtifact]:
    now = datetime.now(timezone.utc)
    return [
        RecycleArtifact(
            original_path="C:\\Users\\suspect\\Documents\\plan.xlsx",
            deleted_time=now - timedelta(days=2),
            size=45_056,
            source="ntfs",
            meta={"mock": True},
        ),
        RecycleArtifact(
            original_path="/home/suspect/Downloads/leak.zip",
            deleted_time=now - timedelta(hours=5),
            size=1_204_233,
            source="trash",
            meta={"mock": True},
        ),
    ]
