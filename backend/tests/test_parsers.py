"""Forensic parser-уудын нэгж тест (CLI шаардахгүй)."""
from __future__ import annotations

import struct
from datetime import datetime, timezone

from app.services import recycle
from app.services.metadata import assess_risk
from app.models import FindingType, Severity


def test_filetime_conversion():
    # 2021-01-01 00:00:00 UTC-ийн FILETIME.
    dt = datetime(2021, 1, 1, tzinfo=timezone.utc)
    seconds = dt.timestamp()
    filetime = int((seconds + recycle._FILETIME_EPOCH_DIFF) * 10_000_000)
    back = recycle._filetime_to_dt(filetime)
    assert back is not None
    assert abs((back - dt).total_seconds()) < 2


def test_parse_i_file_v2(tmp_path):
    # $I файл (version 2) бэлтгэнэ.
    path_str = "C:\\Users\\x\\secret.txt"
    encoded = path_str.encode("utf-16-le") + b"\x00\x00"
    name_len = len(path_str) + 1
    data = (
        struct.pack("<q", 2)
        + struct.pack("<q", 12345)
        + struct.pack("<q", 132_000_000_000_000_000)
        + struct.pack("<i", name_len)
        + encoded
    )
    f = tmp_path / "$IABCDEF"
    f.write_bytes(data)
    art = recycle.parse_i_file(str(f))
    assert art is not None
    assert art.size == 12345
    assert "secret.txt" in art.original_path


def test_risk_assessment_levels():
    # Эмзэг түлхүүр үг -> Өндөр, шалтгаантай.
    high = assess_risk(finding_type=FindingType.DELETED_FILE, file_name="passwords.txt", recovered=True)
    assert high.severity == Severity.HIGH
    assert high.score >= 5
    assert any("түлхүүр" in r for r in high.reasons)

    # Эмзэг өргөтгөл + устгагдсан -> Дунд.
    medium = assess_risk(finding_type=FindingType.DELETED_FILE, file_name="report.docx", recovered=False)
    assert medium.severity == Severity.MEDIUM

    # Энгийн файл -> Хэвийн.
    normal = assess_risk(finding_type=FindingType.DELETED_FILE, file_name="image.bin", recovered=False)
    assert normal.severity == Severity.NORMAL
    assert normal.reasons  # шалтгаан хоосон биш


def test_trashinfo(tmp_path):
    info_dir = tmp_path / ".Trash-1000" / "info"
    info_dir.mkdir(parents=True)
    ti = info_dir / "leak.zip.trashinfo"
    ti.write_text(
        "[Trash Info]\nPath=/home/u/leak.zip\nDeletionDate=2021-05-01T12:00:00\n",
        encoding="utf-8",
    )
    art = recycle.parse_trashinfo(str(ti))
    assert art is not None
    assert art.original_path == "/home/u/leak.zip"
    assert art.deleted_time is not None


def test_tsk_fls_pretty_parse():
    from app.services.tsk import _parse_pretty_line

    entry = _parse_pretty_line("r/r * 16-128-1:    secret_plan.docx")
    assert entry is not None
    assert entry.inode == "16-128-1"
    assert "secret_plan.docx" in entry.name

    entry2 = _parse_pretty_line("r/r * 17-128-2:    /Users/x/passwords.txt")
    assert entry2 is not None
    assert "passwords.txt" in entry2.name

    assert _parse_pretty_line("d/d * 18-144-3:    Documents") is None  # directory
    assert _parse_pretty_line("r/r  16-128-1:    active.txt") is None  # not deleted
