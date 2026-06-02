"""The Sleuth Kit (TSK) wrapper — mmls / fls / icat / tsk_recover.

Файлын системийн метадата ашиглан устгагдсан файлуудыг илрүүлж, тэдгээрийг
сэргээнэ. Linux/TSK байхгүй орчинд mock өгөгдөл буцаана (sample дүрсний
'DELETED:' мөрүүдээс).
"""
from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from app.config import get_settings
from app.services import tools

logger = logging.getLogger("rea.tsk")
settings = get_settings()


@dataclass
class Partition:
    index: int
    start_sector: int
    length_sectors: int
    description: str
    byte_offset: int  # start_sector * sector_size


@dataclass
class DeletedEntry:
    inode: str
    name: str            # path (TSK-ийн өгсөн)
    file_type: str       # r (regular), d (dir) гэх мэт
    size: int = 0
    atime: datetime | None = None
    mtime: datetime | None = None
    ctime: datetime | None = None
    crtime: datetime | None = None
    realloc: bool = False
    deleted: bool = True   # устгагдсан эсэх (list_all_files-д False байж болно)
    meta: dict = field(default_factory=dict)


def _epoch_to_dt(value: str) -> datetime | None:
    try:
        ts = int(value)
    except (TypeError, ValueError):
        return None
    if ts <= 0:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc)


def tsk_available() -> bool:
    return all(tools.is_available(t) for t in ("fls", "icat"))


# --------------------------------------------------------------------------- #
# Partitions (mmls)
# --------------------------------------------------------------------------- #
_MMLS_RE = re.compile(
    r"^\s*(\d+):\s+[\w-]+\s+(\d+)\s+(\d+)\s+(\d+)\s+(.*)$"
)


def list_partitions(image_path: str, sector_size: int = 512) -> list[Partition]:
    """mmls-ээр дүрсний хуваалтын зургийг гаргана.

    Хуваалт олдохгүй (нэг л FS-тэй дүрс) бол offset=0 хуваалт буцаана.
    """
    if not tools.is_available("mmls"):
        return [Partition(0, 0, 0, "whole image (no mmls)", 0)]

    result = tools.run(["mmls", "-b", str(sector_size), image_path])
    if not result.ok:
        # mmls алдаа = хуваалтын хүснэгтгүй, нэг FS гэж үзнэ.
        return [Partition(0, 0, 0, "whole image", 0)]

    partitions: list[Partition] = []
    for line in result.stdout.splitlines():
        m = _MMLS_RE.match(line)
        if not m:
            continue
        idx, start, _end, length, desc = m.groups()
        desc_l = desc.lower()
        if "unallocated" in desc_l or "meta" in desc_l or "extended" in desc_l:
            continue
        start_i = int(start)
        partitions.append(
            Partition(
                index=int(idx),
                start_sector=start_i,
                length_sectors=int(length),
                description=desc.strip(),
                byte_offset=start_i * sector_size,
            )
        )
    if not partitions:
        return [Partition(0, 0, 0, "whole image", 0)]
    return partitions


# --------------------------------------------------------------------------- #
# Deleted files (fls)
# --------------------------------------------------------------------------- #
# Body file format: MD5|name|inode|mode|uid|gid|size|atime|mtime|ctime|crtime
_BODY_FIELDS = 11

# fls -p гаралт:  r/r * 16-128-1:    secret.docx
_FLS_PRETTY_RE = re.compile(
    r"^\s*\S+/\S+\s+\*\s+([\d-]+):\s*(.+?)\s*$"
)


def list_deleted(image_path: str, byte_offset: int = 0) -> list[DeletedEntry]:
    """Устгагдсан файлуудыг TSK `fls`-ээр жагсаана (жинхэнэ нэр/замтай).

    Эхлээд body format (`-m`), дараа нь human-readable (`-p`) ашиглана.
    PhotoRec/carving-ийн ялгаатай нь энд файлын системийн метадатаас
    анхны нэр, зам, огноо гарч ирнэ.
    """
    if not tsk_available():
        if settings.allow_mock:
            return _mock_deleted(image_path)
        return []

    by_inode: dict[str, DeletedEntry] = {}

    for entry in _list_deleted_body(image_path, byte_offset):
        by_inode[entry.inode] = entry

    for entry in _list_deleted_pretty(image_path, byte_offset):
        if entry.inode not in by_inode:
            by_inode[entry.inode] = entry
        else:
            # pretty формат ихэвчлэн илүү цэвэр нэр өгнө.
            existing = by_inode[entry.inode]
            if len(entry.name) > len(existing.name) or "/" in entry.name:
                by_inode[entry.inode] = entry

    entries = list(by_inode.values())
    logger.info("TSK fls: %d устгагдсан файл (offset=%d)", len(entries), byte_offset)
    return entries


def _list_deleted_body(image_path: str, byte_offset: int) -> list[DeletedEntry]:
    """`fls -r -d -m` — body format (бүрэн зам, timestamp)."""
    args = ["fls", "-r", "-d", "-m", "/"]
    if byte_offset:
        args += ["-o", str(byte_offset // 512)]
    args.append(image_path)

    result = tools.run(args, timeout=900)
    if not result.ok:
        logger.warning("fls -m алдаа: %s", result.stderr.strip())
        return []

    entries: list[DeletedEntry] = []
    for line in result.stdout.splitlines():
        entry = _parse_body_line(line)
        if entry and entry.file_type == "r":
            entry.deleted = True
            entries.append(entry)
    return entries


# --------------------------------------------------------------------------- #
# Идэвхтэй + бүх файл — MAC цаг бүхий бүрэн жагсаалт
# --------------------------------------------------------------------------- #
def list_active_files(image_path: str, byte_offset: int = 0) -> list[DeletedEntry]:
    """Идэвхтэй (устгагдаагүй) файлуудыг `fls -r -m` (without -d) ашиглан жагсаана."""
    if not tsk_available():
        if settings.allow_mock:
            return [e for e in _mock_all_files(image_path) if not e.deleted]
        return []

    args = ["fls", "-r", "-m", "/"]
    if byte_offset:
        args += ["-o", str(byte_offset // 512)]
    args.append(image_path)

    result = tools.run(args, timeout=1800)
    if not result.ok:
        logger.warning("fls (идэвхтэй) алдаа: %s", result.stderr.strip())
        return []

    entries: list[DeletedEntry] = []
    for line in result.stdout.splitlines():
        entry = _parse_body_line(line)
        if not entry or entry.file_type != "r" or entry.deleted:
            continue
        entry.deleted = False
        entries.append(entry)

    logger.info("TSK fls: %d идэвхтэй файл (offset=%d)", len(entries), byte_offset)
    return entries


def list_all_files(image_path: str, byte_offset: int = 0) -> list[DeletedEntry]:
    """Файлын системийн БҮХ файлыг (идэвхтэй + устгагдсан) жагсаана."""
    if not tsk_available():
        if settings.allow_mock:
            return _mock_all_files(image_path)
        return []

    active = list_active_files(image_path, byte_offset)
    deleted = list_deleted(image_path, byte_offset)

    by_key: dict[str, DeletedEntry] = {}
    for entry in active:
        by_key[f"{entry.inode}:{entry.name}"] = entry
    for entry in deleted:
        key = f"{entry.inode}:{entry.name}"
        entry.deleted = True
        entry.meta = {**entry.meta, "delete_method": "permanent", "recycle_bypass": True}
        if key not in by_key:
            by_key[key] = entry

    entries = list(by_key.values())
    deleted_n = sum(1 for e in entries if e.deleted)
    active_n = len(entries) - deleted_n
    logger.info(
        "TSK нийт: %d файл (%d идэвхтэй, %d устгагдсан, offset=%d)",
        len(entries), active_n, deleted_n, byte_offset,
    )
    return entries


def _list_deleted_pretty(image_path: str, byte_offset: int) -> list[DeletedEntry]:
    """`fls -r -d -p` — уншигдах хэлбэр (* = устгагдсан, нэр харагдана)."""
    args = ["fls", "-r", "-d", "-p"]
    if byte_offset:
        args += ["-o", str(byte_offset // 512)]
    args.append(image_path)

    result = tools.run(args, timeout=900)
    if not result.ok:
        logger.warning("fls -p алдаа: %s", result.stderr.strip())
        return []

    entries: list[DeletedEntry] = []
    for line in result.stdout.splitlines():
        entry = _parse_pretty_line(line)
        if entry:
            entries.append(entry)
    return entries


def _parse_pretty_line(line: str) -> DeletedEntry | None:
    m = _FLS_PRETTY_RE.match(line)
    if not m:
        return None
    inode, raw_name = m.groups()
    name = raw_name.strip()
    if not name or name in (".", ".."):
        return None
    # Зөвхөн файл (directory биш).
    if line.strip().startswith("d/"):
        return None
    path = name if name.startswith("/") else f"/{name}"
    return DeletedEntry(
        inode=inode,
        name=path,
        file_type="r",
        size=0,
        meta={"source": "fls-pretty"},
    )


def _parse_body_line(line: str) -> DeletedEntry | None:
    parts = line.split("|")
    if len(parts) < _BODY_FIELDS:
        return None
    _md5, name, inode, mode, _uid, _gid, size, atime, mtime, ctime, crtime = parts[:_BODY_FIELDS]

    realloc = "realloc" in name
    # name дотор "(deleted)" тэмдэглэгээ байж болно.
    is_deleted = "(deleted)" in name
    display = name.replace(" (deleted)", "").replace(" (deleted-realloc)", "")
    file_type = "d" if mode.startswith("d") else "r"

    try:
        size_i = int(size)
    except ValueError:
        size_i = 0

    return DeletedEntry(
        inode=inode,
        name=display,
        file_type=file_type,
        size=size_i,
        atime=_epoch_to_dt(atime),
        mtime=_epoch_to_dt(mtime),
        ctime=_epoch_to_dt(ctime),
        crtime=_epoch_to_dt(crtime),
        realloc=realloc,
        deleted=is_deleted,
        meta={"mode": mode},
    )


# --------------------------------------------------------------------------- #
# Recovery (icat / tsk_recover)
# --------------------------------------------------------------------------- #
def recover_inode(
    image_path: str,
    inode: str,
    dest_path: str,
    byte_offset: int = 0,
) -> bool:
    """`icat`-ээр тодорхой inode-ийн агуулгыг сэргээж файлд бичнэ."""
    if not tools.is_available("icat"):
        if settings.allow_mock:
            return _mock_recover(inode, dest_path)
        return False

    Path(dest_path).parent.mkdir(parents=True, exist_ok=True)
    args = ["icat", "-r"]
    if byte_offset:
        args += ["-o", str(byte_offset // 512)]
    args += [image_path, inode]

    result = tools.run_to_file(args, dest_path, timeout=300)
    if not result.ok:
        logger.warning("icat (inode=%s) алдаа: %s", inode, result.stderr.strip())
        return False
    return os.path.exists(dest_path) and os.path.getsize(dest_path) > 0


def recover_all(image_path: str, dest_dir: str, byte_offset: int = 0) -> int:
    """`tsk_recover -e`-ээр бүх (устгагдсан болон идэвхтэй) файлыг сэргээнэ."""
    if not tools.is_available("tsk_recover"):
        return 0
    Path(dest_dir).mkdir(parents=True, exist_ok=True)
    args = ["tsk_recover", "-e"]
    if byte_offset:
        args += ["-o", str(byte_offset // 512)]
    args += [image_path, dest_dir]
    result = tools.run(args, timeout=1800)
    if not result.ok:
        logger.warning("tsk_recover алдаа: %s", result.stderr.strip())
        return 0
    return sum(len(files) for _, _, files in os.walk(dest_dir))


# --------------------------------------------------------------------------- #
# Mock helpers (dev орчин)
# --------------------------------------------------------------------------- #
def _mock_deleted(image_path: str) -> list[DeletedEntry]:
    """Sample дүрсний 'DELETED:<name>' мөрүүдээс хуурамч entry үүсгэнэ."""
    entries: list[DeletedEntry] = []
    now = datetime.now(timezone.utc)
    try:
        with open(image_path, "rb") as fh:
            head = fh.read(4096).decode("utf-8", errors="replace")
    except OSError:
        head = ""
    for i, line in enumerate(head.splitlines()):
        if line.startswith("DELETED:"):
            name = line.split("DELETED:", 1)[1].strip()
            entries.append(
                DeletedEntry(
                    inode=f"{16 + i}-128-1",
                    name=f"/{name}",
                    file_type="r",
                    size=1024 * (i + 1),
                    mtime=now,
                    atime=now,
                    ctime=now,
                    crtime=now,
                    meta={"mock": True},
                )
            )
    if not entries:
        entries = [
            DeletedEntry(inode="16-128-1", name="/secret_plan.docx", file_type="r", size=20480, mtime=now, meta={"mock": True}),
            DeletedEntry(inode="17-128-1", name="/passwords.txt", file_type="r", size=512, mtime=now, meta={"mock": True}),
        ]
    return entries


def _mock_all_files(image_path: str) -> list[DeletedEntry]:
    """Mock/dev орчинд идэвхтэй + устгагдсан файлуудын бүрэн жагсаалтыг үүсгэнэ.

    Бодит TSK байхгүй үед UI болон timeline-ийг турших зорилготой. Файл бүрт
    ялгаатай MAC (modified/accessed/changed/born) цаг оноож "хэзээ ямар үйлдэл
    хийсэн" дүр зургийг харуулна.
    """
    base = datetime.now(timezone.utc)

    def at(days: float) -> datetime:
        return datetime.fromtimestamp(base.timestamp() - days * 86400, tz=timezone.utc)

    # (зам, хэмжээ, устгагдсан эсэх, mtime_days, atime_days, ctime_days, crtime_days)
    samples = [
        ("/Documents/report_Q3.docx", 48213, False, 1, 0.2, 1, 30),
        ("/Documents/budget_2024.xlsx", 91230, False, 2, 0.5, 2, 45),
        ("/Pictures/photo_2021.jpg", 2483920, False, 120, 3, 120, 400),
        ("/Pictures/vacation/IMG_0042.jpg", 3120044, False, 95, 10, 95, 410),
        ("/Downloads/setup_installer.exe", 18234112, False, 7, 1, 7, 7),
        ("/Music/track01.mp3", 5821022, False, 200, 14, 200, 365),
        ("/System/config.sys", 1024, False, 500, 5, 500, 800),
        ("/secret_plan.docx", 20480, True, 3, 1, 0.5, 60),
        ("/passwords.txt", 512, True, 5, 4, 0.2, 90),
        ("/backup_credentials.zip", 81920, True, 10, 9, 1, 120),
        ("/Downloads/leaked_data.csv", 204800, True, 1, 0.5, 0.1, 15),
    ]

    entries: list[DeletedEntry] = []
    for i, (path, size, deleted, mday, aday, cday, crday) in enumerate(samples):
        entries.append(
            DeletedEntry(
                inode=f"{20 + i}-128-1",
                name=path,
                file_type="r",
                size=size,
                mtime=at(mday),
                atime=at(aday),
                ctime=at(cday),
                crtime=at(crday),
                deleted=deleted,
                meta={"mock": True, "delete_method": "permanent" if deleted else None, "recycle_bypass": deleted},
            )
        )
    return entries


def _mock_recover(inode: str, dest_path: str) -> bool:
    Path(dest_path).parent.mkdir(parents=True, exist_ok=True)
    with open(dest_path, "wb") as fh:
        fh.write(f"[MOCK RECOVERED CONTENT for inode {inode}]\n".encode())
        fh.write(b"Lorem ipsum dolor sit amet, recovered deleted file sample.\n")
    return True
