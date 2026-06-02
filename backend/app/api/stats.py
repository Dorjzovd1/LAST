"""Statistics API — Dashboard-ийн нэгдсэн үзүүлэлт (сэжигтэй/хэвийн хувь г.м.)."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import (
    Case,
    Device,
    Finding,
    FindingType,
    ScanJob,
    ScanStatus,
    Severity,
)

router = APIRouter(prefix="/api/stats", tags=["stats"])

# Сэжигтэй гэж үзэх severity-ууд.
_SUSPICIOUS = {Severity.HIGH, Severity.MEDIUM}


@router.get("/overview", summary="Системийн нэгдсэн үзүүлэлт")
def overview(db: Session = Depends(get_db)) -> dict:
    cases = db.query(func.count(Case.id)).scalar() or 0
    devices = db.query(func.count(Device.id)).scalar() or 0
    scans = db.query(func.count(ScanJob.id)).scalar() or 0
    scans_running = (
        db.query(func.count(ScanJob.id))
        .filter(ScanJob.status.in_([ScanStatus.RUNNING, ScanStatus.PENDING]))
        .scalar()
        or 0
    )

    findings_total = db.query(func.count(Finding.id)).scalar() or 0
    findings_recovered = db.query(func.count(Finding.id)).filter(Finding.recovered.is_(True)).scalar() or 0

    # Severity-ээр.
    by_severity = {s.value: 0 for s in Severity}
    for sev, cnt in db.query(Finding.severity, func.count(Finding.id)).group_by(Finding.severity).all():
        by_severity[sev.value] = cnt

    # Төрлөөр.
    by_type = {t.value: 0 for t in FindingType}
    for ft, cnt in db.query(Finding.finding_type, func.count(Finding.id)).group_by(Finding.finding_type).all():
        by_type[ft.value] = cnt

    suspicious = by_severity[Severity.HIGH.value] + by_severity[Severity.MEDIUM.value]
    normal = by_severity[Severity.NORMAL.value]
    total = suspicious + normal
    suspicious_pct = round(suspicious / total * 100, 1) if total else 0.0
    normal_pct = round(normal / total * 100, 1) if total else 0.0

    return {
        "cases": cases,
        "devices": devices,
        "scans": scans,
        "scans_running": scans_running,
        "findings_total": findings_total,
        "findings_recovered": findings_recovered,
        "by_severity": by_severity,
        "by_type": by_type,
        "suspicious": suspicious,
        "normal": normal,
        "suspicious_pct": suspicious_pct,
        "normal_pct": normal_pct,
    }
