"""Metadata нормчлол — MIME төрөл, timeline үүсгэх.

Эрсдэлийн үнэлгээ: `app.services.risk_assessment` (NIST SP 800-60 + FIPS 199).
"""
from __future__ import annotations

import mimetypes
import os
from datetime import datetime

from app.models import Finding, TimelineEvent
from app.services import tools
from app.services.risk_assessment import (
    RISK_FRAMEWORK,
    RISK_RULES,
    RISK_STANDARD,
    RiskAssessment,
    assess_risk,
)

__all__ = [
    "RISK_FRAMEWORK",
    "RISK_RULES",
    "RISK_STANDARD",
    "RiskAssessment",
    "apply_mac_to_finding",
    "assess_risk",
    "build_timeline_events",
    "guess_mime",
]


def guess_mime(path: str, file_name: str = "") -> str:
    """MIME төрлийг `file` команд эсвэл өргөтгөлөөр тодорхойлно."""
    if path and os.path.exists(path) and tools.is_available("file"):
        result = tools.run(["file", "--brief", "--mime-type", path])
        if result.ok and result.stdout.strip():
            return result.stdout.strip()
    name = file_name or path
    mime, _ = mimetypes.guess_type(name)
    return mime or "application/octet-stream"


def apply_mac_to_finding(
    finding: Finding,
    *,
    mtime: datetime | None = None,
    atime: datetime | None = None,
    ctime: datetime | None = None,
    crtime: datetime | None = None,
    source: str = "",
) -> None:
    """Finding-д MAC timestamp оноож, meta-д backup хадгална."""
    pairs = (
        ("mtime", mtime),
        ("atime", atime),
        ("ctime", ctime),
        ("crtime", crtime),
    )
    for field, value in pairs:
        if value is not None and getattr(finding, field) is None:
            setattr(finding, field, value)

    mac_backup: dict[str, str] = dict((finding.meta or {}).get("mac_timestamps") or {})
    for field, value in pairs:
        current = getattr(finding, field)
        if current is not None:
            mac_backup[field] = current.isoformat()

    meta = {**(finding.meta or {})}
    if mac_backup:
        meta["mac_timestamps"] = mac_backup
    if source:
        meta["mac_source"] = source
    finding.meta = meta


def build_timeline_events(finding: Finding) -> list[TimelineEvent]:
    """Finding-ийн MAC timestamp бүрээс timeline үйл явдал үүсгэнэ."""
    events: list[TimelineEvent] = []
    mapping: list[tuple[datetime | None, str, str]] = [
        (finding.crtime, "B", "Born (үүссэн)"),
        (finding.mtime, "M", "Modified (өөрчилсөн)"),
        (finding.atime, "A", "Accessed (хандсан)"),
        (finding.ctime, "C", "Changed (метадата өөрчлөгдсөн)"),
    ]
    label = finding.file_name or finding.original_path or finding.inode
    for ts, kind, desc in mapping:
        if ts is None:
            continue
        events.append(
            TimelineEvent(
                scan_id=finding.scan_id,
                timestamp=ts,
                event_type=kind,
                description=f"{desc}: {label}",
            )
        )
    return events
