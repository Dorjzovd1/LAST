"""NIST SP 800-60 + FIPS 199 risk assessment tests."""
from app.models import FindingType, Severity
from app.services.risk_assessment import RISK_STANDARD, assess_risk


def test_standard_label():
    r = assess_risk(finding_type=FindingType.ACTIVE_FILE, file_name="readme.txt")
    assert r.standard == RISK_STANDARD


def test_executable_high_integrity():
    r = assess_risk(finding_type=FindingType.ACTIVE_FILE, file_name="malware.exe")
    assert r.integrity == "high"
    assert r.severity == Severity.HIGH


def test_carved_bumps_integrity():
    r = assess_risk(finding_type=FindingType.CARVED_FILE, file_name="data.bin")
    assert r.integrity in ("moderate", "high")


def test_official_report_generated():
    r = assess_risk(
        finding_type=FindingType.RECYCLE_ARTIFACT,
        file_name="leak.zip",
        original_path="/home/suspect/Downloads/leak.zip",
        recovered=True,
    )
    assert r.report
    assert r.report["title"] == "Эрсдэлийн үнэлгээний албан ёсны тайлбар"
    assert r.report["executive_summary"]
    assert "leak.zip" in r.report["executive_summary"]
    assert r.report.get("examiner_opinion")
    assert r.report.get("recommendations_narrative")
    assert len(r.report["analysis_steps"]) >= 4
    assert len(r.report["recommendations"]) >= 1


def test_unclassified_deleted_stays_low():
    r = assess_risk(finding_type=FindingType.DELETED_FILE, file_name="image.bin")
    assert r.overall_impact == "low"
    assert r.severity == Severity.NORMAL
