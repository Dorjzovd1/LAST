"""File carving — unallocated/slack space-ээс signature-аар файл сэргээх.

Урсгал:
  1. `blkls` ашиглан unallocated блокуудыг тусдаа файл руу гаргана.
  2. `photorec` / `foremost` / `scalpel`-ийн аль боломжтойг ашиглан тэр файлаас
     signature-аар (header/footer) файл сэргээнэ.

Хэрэгсэл байхгүй орчинд mock carved файл буцаана.
"""
from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from app.config import get_settings
from app.services import tools

logger = logging.getLogger("rea.carving")
settings = get_settings()


@dataclass
class CarvedFile:
    path: str
    file_name: str
    size: int
    file_type: str = ""
    source_tool: str = ""
    meta: dict = field(default_factory=dict)


def extract_unallocated(image_path: str, dest_path: str, byte_offset: int = 0) -> str | None:
    """`blkls`-ээр unallocated блокуудыг dest_path руу гаргана."""
    if not tools.is_available("blkls"):
        logger.info("blkls байхгүй — unallocated гаргахыг алгасав.")
        return None
    Path(dest_path).parent.mkdir(parents=True, exist_ok=True)
    args = ["blkls"]
    if byte_offset:
        args += ["-o", str(byte_offset // 512)]
    args.append(image_path)
    result = tools.run_to_file(args, dest_path, timeout=1800)
    if not result.ok:
        logger.warning("blkls алдаа: %s", result.stderr.strip())
        return None
    return dest_path


def carve(image_or_blob: str, out_dir: str) -> list[CarvedFile]:
    """Signature-based carving — анхны нэр сэргээгдэхгүй (зөвхөн агуулга).

    PhotoRec ихэвчлэн уdaан, нэргүй тул сүүлд оролдоно. Идэвхжүүлэхийг
    scan options дотор `run_carving=true` гэж тодорхой заана.
    """
    Path(out_dir).mkdir(parents=True, exist_ok=True)

    if tools.is_available("foremost"):
        return _carve_foremost(image_or_blob, out_dir)
    if tools.is_available("scalpel"):
        return _carve_scalpel(image_or_blob, out_dir)
    if tools.is_available("photorec"):
        return _carve_photorec(image_or_blob, out_dir)

    if settings.allow_mock:
        return _mock_carve(out_dir)
    logger.info("Carving хэрэгсэл олдсонгүй.")
    return []


def _collect(out_dir: str, source_tool: str) -> list[CarvedFile]:
    carved: list[CarvedFile] = []
    for root, _dirs, files in os.walk(out_dir):
        for fn in files:
            # Хэрэгслийн audit/log файлуудыг алгасна.
            if fn in ("audit.txt", "report.xml") or fn.endswith(".log"):
                continue
            fp = os.path.join(root, fn)
            try:
                size = os.path.getsize(fp)
            except OSError:
                size = 0
            carved.append(
                CarvedFile(
                    path=fp,
                    file_name=fn,
                    size=size,
                    file_type=os.path.splitext(fn)[1].lstrip(".").lower(),
                    source_tool=source_tool,
                )
            )
    return carved


def _carve_photorec(src: str, out_dir: str) -> list[CarvedFile]:
    # photorec ихэвчлэн interactive — /log, /d тугуудаар автоматжуулна.
    result = tools.run(
        ["photorec", "/log", "/d", os.path.join(out_dir, "recup"), "/cmd", src, "search"],
        timeout=3600,
    )
    if not result.ok:
        logger.warning("photorec алдаа: %s", result.stderr.strip())
    return _collect(out_dir, "photorec")


def _carve_foremost(src: str, out_dir: str) -> list[CarvedFile]:
    result = tools.run(["foremost", "-i", src, "-o", out_dir, "-T"], timeout=3600)
    if not result.ok:
        # foremost output хавтас байгаа бол үргэлжлүүлнэ.
        logger.warning("foremost буцаалт: %s", result.stderr.strip())
    return _collect(out_dir, "foremost")


def _carve_scalpel(src: str, out_dir: str) -> list[CarvedFile]:
    result = tools.run(["scalpel", "-o", out_dir, src], timeout=3600)
    if not result.ok:
        logger.warning("scalpel буцаалт: %s", result.stderr.strip())
    return _collect(out_dir, "scalpel")


# --------------------------------------------------------------------------- #
# Slack space (heuristic)
# --------------------------------------------------------------------------- #
_PRINTABLE = re.compile(rb"[ -~]{8,}")


def scan_slack_strings(blob_path: str, max_hits: int = 200) -> list[str]:
    """Unallocated/slack blob-оос printable текст хэсгүүдийг ялгаж авна.

    Энэ нь устгагдсан мэдээллийн ул мөр (нэр, зам, түлхүүр үг) илрүүлэхэд тусална.
    """
    hits: list[str] = []
    if not os.path.exists(blob_path):
        return hits
    try:
        with open(blob_path, "rb") as fh:
            data = fh.read(8 * 1024 * 1024)  # эхний 8 MiB
    except OSError:
        return hits
    for m in _PRINTABLE.finditer(data):
        text = m.group().decode("ascii", errors="ignore").strip()
        if len(text) >= 8:
            hits.append(text)
        if len(hits) >= max_hits:
            break
    return hits


def _mock_carve(out_dir: str) -> list[CarvedFile]:
    samples = [
        ("carved_0001.jpg", b"\xff\xd8\xff\xe0MOCK-JPEG-DATA", "jpg"),
        ("carved_0002.pdf", b"%PDF-1.4 MOCK PDF DATA", "pdf"),
        ("carved_0003.docx", b"PK\x03\x04 MOCK DOCX DATA", "docx"),
    ]
    carved: list[CarvedFile] = []
    for name, content, ftype in samples:
        fp = os.path.join(out_dir, name)
        with open(fp, "wb") as fh:
            fh.write(content)
        carved.append(
            CarvedFile(
                path=fp,
                file_name=name,
                size=len(content),
                file_type=ftype,
                source_tool="mock",
                meta={"mock": True},
            )
        )
    return carved
