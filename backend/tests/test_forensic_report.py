"""Forensic report correlation tests."""
from datetime import datetime, timezone

from app.models import Finding, FindingType, Severity, TimelineEvent
from app.services.forensic_report import enrich_forensic_report


def _finding(**kwargs) -> Finding:
    f = Finding(
        scan_id=1,
        finding_type=FindingType.DELETED_FILE,
        severity=Severity.HIGH,
        file_name="leak.zip",
        original_path="/Downloads/leak.zip",
        size_bytes=1024,
        meta={"risk_score": 823, "risk_overall_impact": "high", "risk_information_types": ["Archive"]},
        mtime=datetime(2024, 6, 1, 10, 0, tzinfo=timezone.utc),
    )
    for k, v in kwargs.items():
        setattr(f, k, v)
    f.id = kwargs.get("id", 1)
    return f


def test_correlated_timeline_links_risk():
    f = _finding()
    timeline = [
        TimelineEvent(
            scan_id=1,
            finding_id=1,
            timestamp=datetime(2024, 6, 1, 10, 0, tzinfo=timezone.utc),
            event_type="M",
            description="Modified: leak.zip",
        )
    ]
    report = enrich_forensic_report([f], timeline)
    assert len(report["correlated_timeline"]) == 1
    row = report["correlated_timeline"][0]
    assert row["severity"] == "high"
    assert row["risk_score"] == 823
    assert row["file_name"] == "leak.zip"


def test_risk_summary_suspicious_percent():
    f1 = _finding(severity=Severity.HIGH, id=1)
    f2 = _finding(severity=Severity.NORMAL, file_name="readme.txt", id=2)
    report = enrich_forensic_report([f1, f2], [])
    risk = report["risk_assessment"]
    assert risk["suspicious_count"] == 1
    assert risk["suspicious_percent"] == 50.0
    assert risk["executive_narrative"]
