"""Сэргээсэн файлын чанар шалгалт — хоосон/MFT junk/эвдэрсэн агуулгыг шүүнэ."""
from __future__ import annotations

import os
import re

# NTFS MFT attribute / ADS — бодит файл биш.
_JUNK_PATTERNS = (
    re.compile(r"\(\$FILE_NAME\)", re.I),
    re.compile(r":Zone\.Identifier$", re.I),
    re.compile(r"^\$I[A-Z0-9]", re.I),
    re.compile(r"^\$R[A-Z0-9]", re.I),
    re.compile(r"^\$Recycle", re.I),
)

# Файлын төрлийн magic bytes (эхний байтууд).
_MAGIC: dict[str, bytes] = {
    "docx": b"PK\x03\x04",
    "xlsx": b"PK\x03\x04",
    "pptx": b"PK\x03\x04",
    "zip": b"PK\x03\x04",
    "png": b"\x89PNG\r\n\x1a\n",
    "jpg": b"\xff\xd8\xff",
    "jpeg": b"\xff\xd8\xff",
    "gif": b"GIF8",
    "pdf": b"%PDF",
}

# Хамгийн бага хэмжээ (bytes) — үүнээс бага бол ихэнх програм нээнэ гэж найдахгүй.
_MIN_BYTES: dict[str, int] = {
    "docx": 512,
    "xlsx": 512,
    "pptx": 512,
    "png": 64,
    "jpg": 64,
    "jpeg": 64,
    "gif": 64,
    "pdf": 128,
}


def normalize_recovery_path(path: str) -> str:
    """($FILE_NAME), Zone.Identifier зэрэг хасаж харьцуулах зам."""
    p = (path or "").replace("\\", "/").strip()
    p = re.sub(r"\(\$FILE_NAME\)", "", p, flags=re.I)
    p = re.sub(r":Zone\.Identifier$", "", p, flags=re.I)
    return p.strip().rstrip("/").lower()


def is_junk_recovery_name(name: str, path: str = "") -> bool:
    """MFT attribute / ADS бичлэг эсэх."""
    text = f"{name} {path}"
    return any(p.search(text) for p in _JUNK_PATTERNS)


def parse_ntfs_mft_inode(inode: str) -> str:
    """TSK inode '12345-48-1' -> ntfsundelete-д зориулсан MFT дугаар."""
    if not inode:
        return ""
    return inode.split("-")[0].strip()


def validate_recovered_file(
    path: str,
    file_name: str,
    *,
    expected_size: int = 0,
) -> tuple[bool, str]:
    """Сэргээсэн файл бодит, нээж болох эсэх."""
    if not path or not os.path.isfile(path):
        return False, "файл олдсонгүй"

    actual = os.path.getsize(path)
    if actual == 0:
        return False, "хоосон (0 byte)"

    if is_junk_recovery_name(file_name, path):
        return False, "MFT metadata — бодит файл биш"

    ext = os.path.splitext(file_name)[1].lstrip(".").lower()
    min_sz = _MIN_BYTES.get(ext, 1)
    if actual < min_sz:
        return False, f"хэт жижиг ({actual} B) — {ext or 'файл'} бүрэн биш"

    if expected_size > 512 and actual < expected_size * 0.25:
        return False, f"truncated ({actual}/{expected_size} B)"

    magic = _MAGIC.get(ext)
    if magic:
        try:
            with open(path, "rb") as fh:
                head = fh.read(len(magic) + 8)
        except OSError:
            return False, "унших алдаа"
        if not head.startswith(magic):
            return False, f"формат буруу (.{ext} magic байхгүй)"

    return True, "ok"


def apply_recovery_result(
    finding,
    path: str,
    tool: str,
    *,
    expected_size: int = 0,
) -> bool:
    """Finding-д сэргээлт хадгалах эсвэл амжилтгүй гэж тэмдэглэх."""
    ok, reason = validate_recovered_file(path, finding.file_name, expected_size=expected_size or finding.size_bytes)
    meta = {**(finding.meta or {}), "recovery_tool": tool}
    if ok:
        finding.recovered = True
        finding.recovered_path = path
        finding.size_bytes = os.path.getsize(path)
        meta["recovery_valid"] = True
        meta["recovery_note"] = reason
    else:
        finding.recovered = False
        finding.recovered_path = ""
        meta["recovery_valid"] = False
        meta["recovery_note"] = reason
        if os.path.exists(path):
            try:
                os.remove(path)
            except OSError:
                pass
    finding.meta = meta
    return ok
