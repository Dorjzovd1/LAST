"""Chain-of-custody audit бүртгэлийн туслах."""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.models import AuditLog


def record(
    db: Session,
    *,
    action: str,
    actor: str = "system",
    target: str = "",
    case_id: int | None = None,
    detail: dict | None = None,
) -> AuditLog:
    """Audit бүртгэл нэмж, commit хийнэ."""
    log = AuditLog(
        action=action,
        actor=actor,
        target=target,
        case_id=case_id,
        detail=detail or {},
    )
    db.add(log)
    db.commit()
    db.refresh(log)
    return log
