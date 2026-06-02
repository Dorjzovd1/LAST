"""Case API — хэрэг үүсгэх, жагсаах, audit log."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core import audit
from app.database import get_db
from app.models import AuditLog, Case
from app.schemas import AuditLogOut, CaseCreate, CaseOut

router = APIRouter(prefix="/api/cases", tags=["cases"])


@router.get("", response_model=list[CaseOut])
def list_cases(db: Session = Depends(get_db)) -> list[Case]:
    return db.query(Case).order_by(Case.id.desc()).all()


@router.post("", response_model=CaseOut, status_code=201)
def create_case(payload: CaseCreate, db: Session = Depends(get_db)) -> Case:
    if db.query(Case).filter(Case.case_number == payload.case_number).first():
        raise HTTPException(409, "Энэ дугаартай хэрэг аль хэдийн бүртгэгдсэн")
    case = Case(**payload.model_dump())
    db.add(case)
    db.commit()
    db.refresh(case)
    audit.record(db, action="case_created", target=case.case_number, case_id=case.id)
    return case


@router.get("/{case_id}", response_model=CaseOut)
def get_case(case_id: int, db: Session = Depends(get_db)) -> Case:
    case = db.get(Case, case_id)
    if case is None:
        raise HTTPException(404, "Хэрэг олдсонгүй")
    return case


@router.get("/{case_id}/audit", response_model=list[AuditLogOut])
def case_audit(case_id: int, db: Session = Depends(get_db)) -> list[AuditLog]:
    return (
        db.query(AuditLog)
        .filter(AuditLog.case_id == case_id)
        .order_by(AuditLog.timestamp.asc())
        .all()
    )
