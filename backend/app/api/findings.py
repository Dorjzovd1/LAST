"""Finding API — илэрсэн ул мөр жагсаах, шүүх, сэргээсэн файл татах."""
from __future__ import annotations

import os

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.core import audit
from app.database import get_db
from app.models import Finding, FindingType, Severity, TimelineEvent
from app.schemas import FindingOut, FileTimelineDetailOut, FindingsPageOut
from app.services import recovery_quality
from app.services import file_timeline
from app.services.risk_assessment import assess_risk

router = APIRouter(prefix="/api/findings", tags=["findings"])

_DELETED_TYPES = (
    FindingType.DELETED_FILE,
    FindingType.CARVED_FILE,
    FindingType.RECYCLE_ARTIFACT,
    FindingType.SLACK_SPACE,
)


def _apply_finding_filters(
    query,
    *,
    scan_id: int | None,
    finding_type: FindingType | None,
    deleted_only: bool | None,
    severity: Severity | None,
    recovered: bool | None,
    q: str | None,
):
    if scan_id is not None:
        query = query.filter(Finding.scan_id == scan_id)
    if finding_type is not None:
        query = query.filter(Finding.finding_type == finding_type)
    elif deleted_only:
        query = query.filter(Finding.finding_type.in_(_DELETED_TYPES))
    if severity is not None:
        query = query.filter(Finding.severity == severity)
    if recovered is not None:
        query = query.filter(Finding.recovered == recovered)
    if q:
        like = f"%{q}%"
        query = query.filter((Finding.file_name.ilike(like)) | (Finding.original_path.ilike(like)))
    return query


@router.get("", response_model=FindingsPageOut, summary="Ул мөрүүдийг шүүж жагсаах (pagination)")
def list_findings(
    scan_id: int | None = Query(None),
    finding_type: FindingType | None = Query(None),
    deleted_only: bool | None = Query(None, description="Зөвхөн устгагдсан/recycle/carving"),
    severity: Severity | None = Query(None),
    recovered: bool | None = Query(None),
    q: str | None = Query(None, description="Файлын нэр/замаар хайх"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> FindingsPageOut:
    query = _apply_finding_filters(
        db.query(Finding),
        scan_id=scan_id,
        finding_type=finding_type,
        deleted_only=deleted_only,
        severity=severity,
        recovered=recovered,
        q=q,
    )
    total = query.count()
    items = query.order_by(Finding.id.asc()).offset(offset).limit(limit).all()
    return FindingsPageOut(items=items, total=total, limit=limit, offset=offset)


@router.get("/{finding_id}", response_model=FindingOut)
def get_finding(finding_id: int, db: Session = Depends(get_db)) -> Finding:
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(404, "Finding олдсонгүй")
    return finding


@router.get("/{finding_id}/download", summary="Сэргээсэн файлыг татах")
def download_finding(finding_id: int, db: Session = Depends(get_db)) -> FileResponse:
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(404, "Finding олдсонгүй")
    if not finding.recovered or not finding.recovered_path or not os.path.exists(finding.recovered_path):
        raise HTTPException(404, "Сэргээсэн файл байхгүй")
    ok, reason = recovery_quality.validate_recovered_file(
        finding.recovered_path,
        finding.file_name,
        expected_size=finding.size_bytes,
        strict=not (finding.meta or {}).get("recovery_partial"),
    )
    if not ok:
        raise HTTPException(
            422,
            f"Сэргээсэн агуулга бүрэн биш — нээж болохгүй ({reason}). Шинэ scan эхлүүлнэ үү.",
        )
    audit.record(db, action="finding_downloaded", target=finding.file_name, detail={"finding_id": finding.id})
    return FileResponse(
        finding.recovered_path,
        filename=finding.file_name or f"finding_{finding.id}",
        media_type=finding.mime_type or "application/octet-stream",
    )


@router.get(
    "/{finding_id}/file-timeline",
    response_model=FileTimelineDetailOut,
    summary="Файлын бүрэн activity timeline (MAC + lifecycle)",
)
def finding_file_timeline(finding_id: int, db: Session = Depends(get_db)) -> dict:
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(404, "Finding олдсонгүй")
    stored = (
        db.query(TimelineEvent)
        .filter(TimelineEvent.finding_id == finding_id)
        .order_by(TimelineEvent.timestamp.asc())
        .all()
    )
    return file_timeline.build_file_timeline_detail(finding, stored)


@router.get("/{finding_id}/risk-report", summary="Эрсдэлийн албан ёсны тайлан (NIST/FIPS narrative)")
def finding_risk_report(finding_id: int, db: Session = Depends(get_db)) -> dict:
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(404, "Finding олдсонгүй")
    assessment = assess_risk(
        finding_type=finding.finding_type,
        file_name=finding.file_name or "",
        original_path=finding.original_path or "",
        recovered=finding.recovered,
    )
    return assessment.report


@router.get("/{finding_id}/preview", summary="Текст урьдчилан харах (эхний 4KB)")
def preview_finding(finding_id: int, db: Session = Depends(get_db)) -> dict:
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(404, "Finding олдсонгүй")
    if not finding.recovered_path or not os.path.exists(finding.recovered_path):
        return {"preview": "", "available": False}
    with open(finding.recovered_path, "rb") as fh:
        chunk = fh.read(4096)
    return {
        "preview": chunk.decode("utf-8", errors="replace"),
        "available": True,
        "truncated": os.path.getsize(finding.recovered_path) > 4096,
    }
