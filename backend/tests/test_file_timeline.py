"""File timeline service tests."""
from datetime import datetime, timezone

from app.models import Finding, FindingType, Severity, TimelineEvent
from app.services.file_timeline import (
    build_file_timeline_detail,
    build_file_timeline_events,
    build_scan_timeline_by_file,
)


def _finding(**kwargs) -> Finding:
    defaults = {
        "id": 1,
        "scan_id": 1,
        "finding_type": FindingType.RECYCLE_ARTIFACT,
        "severity": Severity.HIGH,
        "file_name": "leak.zip",
        "original_path": "/home/suspect/Downloads/leak.zip",
        "size_bytes": 1204233,
        "mime_type": "application/zip",
        "recovered": False,
        "mtime": datetime(2024, 3, 10, 14, 0, tzinfo=timezone.utc),
        "atime": datetime(2024, 3, 11, 9, 0, tzinfo=timezone.utc),
        "ctime": datetime(2024, 3, 12, 18, 30, tzinfo=timezone.utc),
        "crtime": datetime(2024, 3, 1, 10, 0, tzinfo=timezone.utc),
        "created_at": datetime(2024, 6, 1, 12, 0, tzinfo=timezone.utc),
        "source_tool": "recycle",
    }
    defaults.update(kwargs)
    return Finding(**defaults)


def test_file_timeline_includes_mac_and_delete():
    f = _finding()
    events = build_file_timeline_events(f, [])
    types = {e["event_type"] for e in events}
    assert "B" in types
    assert "M" in types
    assert "A" in types
    assert "C" in types
    assert "DELETE" in types
    assert "RECYCLE" in types
    assert events[0]["sequence"] == 1
    assert events[-1]["sequence"] == len(events)


def test_file_timeline_detail_narrative():
    f = _finding(recovered=True)
    detail = build_file_timeline_detail(f, [])
    assert detail["event_count"] >= 5
    assert detail["narrative"]
    assert any(e["event_type"] == "RECOVERED" for e in detail["events"])


def test_scan_timeline_by_file_groups():
    f1 = _finding(id=1, file_name="a.doc")
    f2 = _finding(id=2, file_name="b.pdf", finding_type=FindingType.ACTIVE_FILE)
    timeline = [
        TimelineEvent(
            id=10,
            scan_id=1,
            finding_id=1,
            timestamp=datetime(2024, 3, 1, 10, 0, tzinfo=timezone.utc),
            event_type="B",
            description="Born",
        )
    ]
    rows = build_scan_timeline_by_file([f1, f2], timeline)
    assert len(rows) == 2
    assert rows[0]["finding_id"] in (1, 2)
