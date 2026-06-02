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


def test_risk_assessment_nist_fips():
    """NIST SP 800-60 + FIPS 199 — түвшний жишээ."""
    high = assess_risk(finding_type=FindingType.DELETED_FILE, file_name="passwords.txt", recovered=True)
    assert high.severity == Severity.HIGH
    assert high.overall_impact == "high"
    assert high.confidentiality == "high"
    assert any("NIST SP 800-60" in r for r in high.reasons)
    assert any("FIPS 199" in r for r in high.reasons)

    medium = assess_risk(finding_type=FindingType.DELETED_FILE, file_name="report.docx", recovered=False)
    assert medium.severity == Severity.MEDIUM
    assert medium.overall_impact == "moderate"

    normal = assess_risk(finding_type=FindingType.DELETED_FILE, file_name="image.bin", recovered=False)
    assert normal.severity == Severity.NORMAL
    assert normal.overall_impact == "low"
    assert normal.reasons


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


def test_merge_pretty_preserves_mac_timestamps():
    from datetime import datetime, timezone

    from app.services.tsk import DeletedEntry, _merge_pretty_into_body

    ts = datetime(2024, 3, 10, 12, 0, tzinfo=timezone.utc)
    body = DeletedEntry(
        inode="16-128-1",
        name="/a.txt",
        file_type="r",
        size=18,
        mtime=ts,
        atime=ts,
        ctime=ts,
        crtime=ts,
        deleted=True,
    )
    pretty = DeletedEntry(
        inode="16-128-1",
        name="/Turshiltiin file.txt",
        file_type="r",
        size=0,
        deleted=True,
        meta={"source": "fls-pretty"},
    )
    _merge_pretty_into_body(body, pretty)
    assert body.name == "/Turshiltiin file.txt"
    assert body.mtime == ts
    assert body.size == 18


def test_parse_istat_datetime():
    from app.services.tsk import _parse_istat_datetime

    dt = _parse_istat_datetime("2024-03-10 14:00:00.000000000 (UTC)")
    assert dt is not None
    assert dt.year == 2024
    assert dt.hour == 14


def test_apply_mac_to_finding():
    from datetime import datetime, timezone

    from app.models import Finding, FindingType, Severity
    from app.services.metadata import apply_mac_to_finding

    f = Finding(
        scan_id=1,
        finding_type=FindingType.DELETED_FILE,
        severity=Severity.NORMAL,
        file_name="a.txt",
    )
    ts = datetime(2024, 1, 1, tzinfo=timezone.utc)
    apply_mac_to_finding(f, mtime=ts, ctime=ts, source="test")
    assert f.mtime == ts
    assert f.meta["mac_timestamps"]["mtime"]


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


def test_recovery_junk_names():
    from app.services.recovery_quality import is_junk_recovery_name, normalize_recovery_path

    assert is_junk_recovery_name("doc.docx ($FILE_NAME)", "/doc.docx ($FILE_NAME)")
    assert is_junk_recovery_name("file.png:Zone.Identifier", "/file.png:Zone.Identifier")
    assert not is_junk_recovery_name("report.docx", "/Documents/report.docx")
    assert normalize_recovery_path("/a.docx ($FILE_NAME)") == "/a.docx"


def test_ensure_utc_naive():
    from datetime import datetime, timezone

    from app.utils.time_utils import ensure_utc

    naive = datetime(2026, 6, 2, 8, 38, 15)
    aware = ensure_utc(naive)
    assert aware is not None
    assert aware.tzinfo == timezone.utc
    assert aware.hour == 8


def test_recovery_validate_docx(tmp_path):
    from app.services.recovery_quality import validate_recovered_file

    bad = tmp_path / "fake.docx"
    bad.write_bytes(b"not a zip")
    ok, reason = validate_recovered_file(str(bad), "fake.docx")
    assert not ok
    assert "биш" in reason or "magic" in reason

    good = tmp_path / "good.docx"
    good.write_bytes(b"PK\x03\x04" + b"x" * 600)
    ok2, _ = validate_recovered_file(str(good), "good.docx")
    assert ok2

