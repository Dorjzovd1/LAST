"""Report API — scan-ийн forensic тайланг HTML/JSON хэлбэрээр гаргах."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, Response
from sqlalchemy.orm import Session

from app.config import get_settings
from app.core import audit
from app.database import get_db
from app.schemas import (
    AuditLogOut,
    DeviceOut,
    FindingOut,
    ScanOut,
    TimelineEventOut,
)
from app.services import pdf_report, reporting

router = APIRouter(prefix="/api/reports", tags=["reports"])
settings = get_settings()


@router.get("/scan/{scan_id}/html", response_class=HTMLResponse, summary="HTML forensic тайлан")
def report_html(scan_id: int, db: Session = Depends(get_db)) -> HTMLResponse:
    try:
        data = reporting.build_report_data(db, scan_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc
    audit.record(db, action="report_generated", target=f"scan_{scan_id}", detail={"format": "html"})
    return HTMLResponse(reporting.render_html(data))


@router.get("/scan/{scan_id}/pdf", summary="PDF forensic тайлан (татах)")
def report_pdf(scan_id: int, db: Session = Depends(get_db)) -> Response:
    try:
        data = reporting.build_report_data(db, scan_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc
    pdf_bytes = pdf_report.generate_pdf(data)
    audit.record(db, action="report_generated", target=f"scan_{scan_id}", detail={"format": "pdf"})
    case_no = data["case"].case_number if data["case"] else "case"
    filename = f"REA_report_{case_no}_scan{scan_id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/scan/{scan_id}/json", summary="JSON forensic тайлан")
def report_json(scan_id: int, db: Session = Depends(get_db)) -> dict:
    try:
        data = reporting.build_report_data(db, scan_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc

    return {
        "generated_at": data["generated_at"],
        "summary": data["summary"],
        "case": None if not data["case"] else {
            "case_number": data["case"].case_number,
            "title": data["case"].title,
            "investigator": data["case"].investigator,
        },
        "device": DeviceOut.model_validate(data["device"]) if data["device"] else None,
        "scan": ScanOut.model_validate(data["scan"]),
        "findings": [FindingOut.model_validate(f) for f in data["findings"]],
        "timeline": [TimelineEventOut.model_validate(t) for t in data["timeline"]],
        "audit": [AuditLogOut.model_validate(a) for a in data["audit"]],
    }
