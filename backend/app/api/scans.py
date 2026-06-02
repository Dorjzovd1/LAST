"""Scan API — бүх файлын шинжилгээ (идэвхтэй + устгагдсан), timeline, эрсдэл."""
from __future__ import annotations

import threading

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core import audit
from app.database import get_db
from app.models import Device, Finding, FindingType, ScanJob, ScanStatus, Severity, TimelineEvent
from app.schemas import ScanCreate, ScanOut, ScanSummaryOut, TimelineEventOut
from app.services import scanner

router = APIRouter(prefix="/api/scans", tags=["scans"])


@router.get("", response_model=list[ScanOut])
def list_scans(db: Session = Depends(get_db)) -> list[ScanJob]:
    return db.query(ScanJob).order_by(ScanJob.id.desc()).all()


@router.post("", response_model=ScanOut, status_code=201, summary="Шинэ scan эхлүүлэх")
def create_scan(
    payload: ScanCreate,
    db: Session = Depends(get_db),
) -> ScanJob:
    device = db.get(Device, payload.device_id)
    if device is None:
        raise HTTPException(404, "Device олдсонгүй")

    job = ScanJob(
        device_id=payload.device_id,
        status=ScanStatus.PENDING,
        options=payload.options.model_dump(),
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    audit.record(db, action="scan_queued", target=device.dev_path, case_id=device.case_id, detail={"scan_id": job.id})

    # Урт хугацааны scan-ийг тусдаа thread дотор ажиллуулна.
    threading.Thread(target=scanner.run_scan, args=(job.id,), daemon=True).start()
    return job


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: int, db: Session = Depends(get_db)) -> ScanJob:
    job = db.get(ScanJob, scan_id)
    if job is None:
        raise HTTPException(404, "Scan олдсонгүй")
    return job


@router.post("/{scan_id}/cancel", response_model=ScanOut, summary="Scan-ийг цуцлах")
def cancel_scan(scan_id: int, db: Session = Depends(get_db)) -> ScanJob:
    job = db.get(ScanJob, scan_id)
    if job is None:
        raise HTTPException(404, "Scan олдсонгүй")
    if job.status in (ScanStatus.PENDING, ScanStatus.RUNNING):
        job.status = ScanStatus.CANCELLED
        db.add(job)
        db.commit()
        db.refresh(job)
    return job


@router.get("/{scan_id}/summary", response_model=ScanSummaryOut, summary="Scan тойм — нийт файл, эрсдэл, timeline")
def scan_summary(scan_id: int, db: Session = Depends(get_db)) -> ScanSummaryOut:
    job = db.get(ScanJob, scan_id)
    if job is None:
        raise HTTPException(404, "Scan олдсонгүй")

    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    timeline_n = db.query(func.count(TimelineEvent.id)).filter(TimelineEvent.scan_id == scan_id).scalar() or 0

    def count_type(ft: FindingType) -> int:
        return sum(1 for f in findings if f.finding_type == ft)

    def count_sev(sev: Severity) -> int:
        return sum(1 for f in findings if f.severity == sev)

    deleted_types = {FindingType.DELETED_FILE, FindingType.CARVED_FILE}
    return ScanSummaryOut(
        scan_id=scan_id,
        total_files=len(findings),
        active_files=count_type(FindingType.ACTIVE_FILE),
        deleted_files=sum(1 for f in findings if f.finding_type in deleted_types),
        recycle_artifacts=count_type(FindingType.RECYCLE_ARTIFACT),
        carved_files=count_type(FindingType.CARVED_FILE),
        timeline_events=int(timeline_n),
        risk_high=count_sev(Severity.HIGH),
        risk_medium=count_sev(Severity.MEDIUM),
        risk_normal=count_sev(Severity.NORMAL),
        recovered_files=sum(1 for f in findings if f.recovered),
    )


@router.get("/{scan_id}/timeline", response_model=list[TimelineEventOut])
def scan_timeline(scan_id: int, db: Session = Depends(get_db)) -> list[TimelineEvent]:
    return (
        db.query(TimelineEvent)
        .filter(TimelineEvent.scan_id == scan_id)
        .order_by(TimelineEvent.timestamp.asc())
        .all()
    )
