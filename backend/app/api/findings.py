"""Finding API — илэрсэн ул мөр жагсаах, шүүх, сэргээсэн файл татах."""
from __future__ import annotations

import os

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.core import audit
from app.database import get_db
from app.models import Finding, FindingType, Severity
from app.schemas import FindingOut
from app.services import recovery_quality
from app.services.risk_assessment import assess_risk

router = APIRouter(prefix="/api/findings", tags=["findings"])


@router.get("", response_model=list[FindingOut], summary="Ул мөрүүдийг шүүж жагсаах")
def list_findings(
    scan_id: int | None = Query(None),
    finding_type: FindingType | None = Query(None),
    severity: Severity | None = Query(None),
    recovered: bool | None = Query(None),
    q: str | None = Query(None, description="Файлын нэр/замаар хайх"),
    db: Session = Depends(get_db),
) -> list[Finding]:
    query = db.query(Finding)
    if scan_id is not None:
        query = query.filter(Finding.scan_id == scan_id)
    if finding_type is not None:
        query = query.filter(Finding.finding_type == finding_type)
    if severity is not None:
        query = query.filter(Finding.severity == severity)
    if recovered is not None:
        query = query.filter(Finding.recovered == recovered)
    if q:
        like = f"%{q}%"
        query = query.filter((Finding.file_name.ilike(like)) | (Finding.original_path.ilike(like)))
    return query.order_by(Finding.id.asc()).all()


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
