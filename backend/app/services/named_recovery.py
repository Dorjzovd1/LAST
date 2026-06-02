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
from app.services import tools

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
        try:
            size = int(size_s)
        except ValueError:
            size = 0

        safe = re.sub(r"[^\w.\-]", "_", _basename(name))[:120]
        out = Path(dest_dir) / f"{inode}_{safe}"
        rec = tools.run(
            ["ntfsundelete", "-u", "-i", inode, "-o", str(out), source_path],
            timeout=300,
        )
        recovered = str(out) if out.exists() and out.stat().st_size > 0 else ""
        if not rec.ok and not recovered:
            logger.debug("ntfsundelete inode %s алдаа: %s", inode, rec.stderr.strip())

        orig = name if name.startswith(("/", "C:\\", "c:\\")) else f"/{name}"
        results.append(
            NamedFile(
                original_path=orig.replace("\\", "/"),
                file_name=_basename(name),
                size=size,
                recovered_path=recovered,
                source_tool="ntfsundelete",
                inode=inode,
                meta={"has_original_name": True, "recovery_method": "ntfs_metadata"},
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


def recover_ntfs_inode(source_path: str, inode: str, dest_path: str) -> bool:
    """NTFS inode-ийг ntfsundelete-ээр сэргээнэ (Shift+Delete / permanent delete).

    icat амжилтгүй үед fallback болгон ашиглана.
    """
    if not tools.is_available("ntfsundelete"):
        return False
    Path(dest_path).parent.mkdir(parents=True, exist_ok=True)
    result = tools.run(
        ["ntfsundelete", "-f", "-u", "-i", inode, "-o", dest_path, source_path],
        timeout=300,
    )
    return result.ok and os.path.exists(dest_path) and os.path.getsize(dest_path) > 0


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
