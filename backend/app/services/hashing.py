"""Файл hash тооцох туслах (MD5 + SHA-256)."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

_CHUNK = 1024 * 1024  # 1 MiB


@dataclass
class Hashes:
    md5: str
    sha256: str


def hash_file(path: str | Path) -> Hashes:
    """Файлыг урсгалаар уншиж MD5 ба SHA-256-ийг нэг дамжуулалтаар тооцно."""
    md5 = hashlib.md5()  # noqa: S324 - forensic тэмдэглэгээ зорилгоор хадгална
    sha = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(_CHUNK):
            md5.update(chunk)
            sha.update(chunk)
    return Hashes(md5=md5.hexdigest(), sha256=sha.hexdigest())


def hash_bytes(data: bytes) -> Hashes:
    return Hashes(
        md5=hashlib.md5(data).hexdigest(),  # noqa: S324
        sha256=hashlib.sha256(data).hexdigest(),
    )
