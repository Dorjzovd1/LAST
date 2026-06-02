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


def _json_safe_forensic(forensic: dict) -> dict:
    """Datetime-ийг ISO string болгон JSON-д бэлдэнэ."""
    import copy

    data = copy.deepcopy(forensic)
    for row in data.get("correlated_timeline", []):
        ts = row.get("timestamp")
        if hasattr(ts, "isoformat"):
            row["timestamp"] = ts.isoformat()
    for profile in data.get("finding_profiles", []):
        for key in ("mtime", "atime", "ctime", "crtime"):
            val = profile.get(key)
            if hasattr(val, "isoformat"):
                profile[key] = val.isoformat()
    for profile in data.get("risk_assessment", {}).get("high_risk_findings", []):
        for key in ("mtime", "atime", "ctime", "crtime"):
            val = profile.get(key)
            if hasattr(val, "isoformat"):
                profile[key] = val.isoformat()
    for profile in data.get("risk_assessment", {}).get("medium_risk_findings", []):
        for key in ("mtime", "atime", "ctime", "crtime"):
            val = profile.get(key)
            if hasattr(val, "isoformat"):
                profile[key] = val.isoformat()
    return data


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
    filename = f"REA_report_scan{scan_id}.pdf"
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

    forensic_json = _json_safe_forensic(data["forensic"])

    return {
        "generated_at": data["generated_at"],
        "summary": data["summary"],
        "forensic": forensic_json,
        "device": DeviceOut.model_validate(data["device"]) if data["device"] else None,
        "scan": ScanOut.model_validate(data["scan"]),
        "findings": [FindingOut.model_validate(f) for f in data["findings"]],
        "timeline": [TimelineEventOut.model_validate(t) for t in data["timeline"]],
        "correlated_timeline": forensic_json["correlated_timeline"],
        "risk_assessment": forensic_json["risk_assessment"],
        "correlations": forensic_json["correlations"],
        "audit": [AuditLogOut.model_validate(a) for a in data["audit"]],
    }
