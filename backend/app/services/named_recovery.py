"""Нэртэй файл сэргээх — файлын системийн метадата ашиглана (Photorec биш).

Хэрэгслүүд:
  - TSK fls/icat     — бүх FS (FAT/NTFS/ext…) устгагдсан entry + анхны зам
  - ntfsundelete     — NTFS устгагдсан файл (Windows USB)
  - extundelete      — ext3/ext4 устгагдсан файл (Linux)

Signature carving (photorec/foremost) нэр сэргээхгүй, маш уdaан тул энд оруулаагүй.
"""
from __future__ import annotations

import logging
import os
import re
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from app.config import get_settings
from app.services import recovery_quality, tools, tsk

logger = logging.getLogger("rea.named_recovery")
settings = get_settings()

@dataclass
class NamedFile:
    original_path: str
    file_name: str
    size: int
    recovered_path: str = ""
    source_tool: str = ""
    inode: str = ""
    mtime: datetime | None = None
    atime: datetime | None = None
    ctime: datetime | None = None
    crtime: datetime | None = None
    deleted_time: datetime | None = None
    meta: dict = field(default_factory=dict)


def resolve_partition_path(dev_path: str, fs_type: str = "", details: dict | None = None) -> str:
    """Disk (/dev/sdb) бол хүүхэд partition (/dev/sdb1)-ийг буцаана."""
    details = details or {}
    for child in details.get("children") or []:
        if child.get("fstype"):
            name = child.get("name", "")
            if name:
                return name if name.startswith("/dev") else f"/dev/{name}"
    return dev_path


def _basename(path: str) -> str:
    p = path.replace("\\", "/").rstrip("/")
    return os.path.basename(p) or p


# --------------------------------------------------------------------------- #
# NTFS — ntfsundelete
# --------------------------------------------------------------------------- #
def scan_ntfs(source_path: str, dest_dir: str) -> list[NamedFile]:
    """`ntfsundelete -l` жагсаалтаас устгагдсан файлуудыг нэртэй нь сэргээнэ."""
    if not tools.is_available("ntfsundelete"):
        logger.info("ntfsundelete байхгүй — алгасав.")
        return []

    listing = tools.run(["ntfsundelete", "-f", "-l", source_path], timeout=120)
    if not listing.ok:
        logger.warning("ntfsundelete -l: %s", listing.stderr.strip())
        return []

    Path(dest_dir).mkdir(parents=True, exist_ok=True)
    results: list[NamedFile] = []

    for line in listing.stdout.splitlines():
        if not line.strip() or line.strip().lower().startswith("inode"):
            continue
        parts = line.split()
        if len(parts) < 6 or not parts[0].isdigit():
            continue
        inode, size_s = parts[0], parts[3]
        name = parts[-1] if len(parts) > 6 else parts[5]
        if name in (".", ".."):
            continue
        orig = name if name.startswith(("/", "C:\\", "c:\\")) else f"/{name}"
        orig = orig.replace("\\", "/")
        if recovery_quality.is_junk_recovery_name(name, orig):
            logger.debug("ntfsundelete junk алгасав: %s", name)
            continue
        try:
            size = int(size_s)
        except ValueError:
            size = 0

        deleted_time = None
        date_match = re.search(r"(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})", line)
        if date_match:
            try:
                deleted_time = datetime.strptime(
                    f"{date_match.group(1)} {date_match.group(2)}",
                    "%Y-%m-%d %H:%M:%S",
                ).replace(tzinfo=timezone.utc)
            except ValueError:
                deleted_time = None

        mac = tsk.get_inode_timestamps(source_path, inode, 0)
        safe = re.sub(r"[^\w.\-]", "_", _basename(name))[:120]
        out = Path(dest_dir) / f"{inode}_{safe}"
        rec = tools.run(
            ["ntfsundelete", "-f", "-u", "-i", inode, "-o", str(out), source_path],
            timeout=300,
        )
        recovered = ""
        if out.exists():
            ok, _reason = recovery_quality.validate_recovered_file(str(out), _basename(name), expected_size=size, strict=True)
            if ok:
                recovered = str(out)
            else:
                try:
                    out.unlink(missing_ok=True)
                except OSError:
                    pass
        if not rec.ok and not recovered:
            logger.debug("ntfsundelete inode %s алдаа: %s", inode, rec.stderr.strip())

        results.append(
            NamedFile(
                original_path=orig,
                file_name=_basename(name),
                size=size if recovered else 0,
                recovered_path=recovered,
                source_tool="ntfsundelete",
                inode=inode,
                mtime=mac.get("mtime"),
                atime=mac.get("atime"),
                ctime=mac.get("ctime") or deleted_time,
                crtime=mac.get("crtime"),
                deleted_time=deleted_time,
                meta={
                    "has_original_name": True,
                    "recovery_method": "ntfs_metadata",
                    "recovery_valid": bool(recovered),
                },
            )
        )
    return results


# --------------------------------------------------------------------------- #
# ext3/ext4 — extundelete
# --------------------------------------------------------------------------- #
def scan_ext(source_path: str, dest_dir: str) -> list[NamedFile]:
    """`extundelete --restore-all` — устгагдсан файлуудыг анхны замын бүтэцтэй сэргээнэ."""
    if not tools.is_available("extundelete"):
        logger.info("extundelete байхгүй — алгасав.")
        return []

    work = Path(dest_dir) / "extundelete_out"
    if work.exists():
        shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)

    result = tools.run(
        ["extundelete", "--restore-all", source_path],
        timeout=600,
        cwd=str(work),
    )
    if not result.ok and not (work / "RECOVERED_FILES").exists():
        logger.warning("extundelete: %s", result.stderr.strip())
        return []

    results: list[NamedFile] = []
    recovered_root = work / "RECOVERED_FILES"
    if not recovered_root.exists():
        recovered_root = work

    for root, _dirs, files in os.walk(recovered_root):
        for fn in files:
            fp = os.path.join(root, fn)
            rel = os.path.relpath(fp, recovered_root).replace("\\", "/")
            orig = f"/{rel}" if not rel.startswith("/") else rel
            try:
                size = os.path.getsize(fp)
            except OSError:
                size = 0
            results.append(
                NamedFile(
                    original_path=orig,
                    file_name=_basename(rel),
                    size=size,
                    recovered_path=fp,
                    source_tool="extundelete",
                    meta={"has_original_name": True, "recovery_method": "ext_metadata"},
                )
            )
    return results


def recover_ntfs_inode(source_path: str, inode: str, dest_path: str, *, file_name: str = "") -> bool:
    """NTFS inode-ийг ntfsundelete-ээр сэргээнэ (Shift+Delete / permanent delete).

    icat амжилтгүй үед fallback болгон ашиглана.
    """
    if not tools.is_available("ntfsundelete"):
        return False
    Path(dest_path).parent.mkdir(parents=True, exist_ok=True)
    result = tools.run(
        ["ntfsundelete", "-f", "-u", "-i", recovery_quality.parse_ntfs_mft_inode(inode), "-o", dest_path, source_path],
        timeout=300,
    )
    if not result.ok or not os.path.exists(dest_path):
        return False
    check_name = file_name or os.path.basename(dest_path)
    ok, _ = recovery_quality.validate_recovered_file(dest_path, check_name, strict=False)
    if not ok:
        try:
            os.remove(dest_path)
        except OSError:
            pass
        return False
    return True


def scan_by_filesystem(source_path: str, fs_type: str, dest_dir: str) -> list[NamedFile]:
    """FS төрлөөс хамаарч нэртэй сэргээлтийн хэрэгслийг сонгоно."""
    fs = (fs_type or "").lower()
    if fs in ("ntfs", "exfat"):
        return scan_ntfs(source_path, dest_dir)
    if fs in ("ext2", "ext3", "ext4"):
        return scan_ext(source_path, dest_dir)
    if fs in ("vfat", "fat", "fat32", "msdos"):
        # FAT — TSK fls хангалттай; ntfsundelete/extundelete хэрэггүй.
        return []
    logger.info("FS '%s' — нэмэлт named tool алгасав (TSK fls ашиглана).", fs)
    return []
