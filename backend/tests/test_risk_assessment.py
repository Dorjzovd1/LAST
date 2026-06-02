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


def test_unclassified_deleted_stays_low():
    r = assess_risk(finding_type=FindingType.DELETED_FILE, file_name="image.bin")
    assert r.overall_impact == "low"
    assert r.severity == Severity.NORMAL
