"""Scan дууссаны дараа сервер дээрх өгөгдөл цэвэрлэх."""
from __future__ import annotations

import logging
import os
import shutil
from pathlib import Path

from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import Finding, ScanJob, TimelineEvent

logger = logging.getLogger("rea.scan_cleanup")


def purge_scan(db: Session, scan_id: int) -> dict[str, int]:
    """Scan-ийн findings, timeline, scan бүртгэл, сэргээсэн файлыг устгана."""
    settings = get_settings()
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    finding_count = len(findings)
    recovered_paths = [f.recovered_path for f in findings if f.recovered_path]

    timeline_removed = (
        db.query(TimelineEvent).filter(TimelineEvent.scan_id == scan_id).delete(synchronize_session=False)
    )
    findings_removed = db.query(Finding).filter(Finding.scan_id == scan_id).delete(synchronize_session=False)
    job = db.get(ScanJob, scan_id)
    scan_removed = 0
    if job is not None:
        db.delete(job)
        scan_removed = 1
    db.commit()

    _remove_path(settings.recovered_dir / f"scan_{scan_id}")
    for path in recovered_paths:
        _remove_file(path)

    logger.info(
        "Scan %s цэвэрлэгдлээ: findings=%d timeline=%d scan=%d",
        scan_id,
        findings_removed,
        timeline_removed,
        scan_removed,
    )
    return {
        "findings_removed": int(findings_removed or finding_count),
        "timeline_removed": int(timeline_removed or 0),
        "scan_removed": scan_removed,
    }


def _remove_path(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)


def _remove_file(path: str) -> None:
    if not path or not os.path.isfile(path):
        return
    try:
        os.remove(path)
    except OSError:
        pass
