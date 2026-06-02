"""Файл бүрийн бүрэн activity timeline — MAC + forensic lifecycle."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.models import Finding, FindingType, TimelineEvent

_MAC_EVENTS: list[tuple[str, str, str, str]] = [
    ("crtime", "B", "mac", "Файл анх үүссэн (Born)"),
    ("mtime", "M", "mac", "Агуулга өөрчлөгдсөн (Modified)"),
    ("atime", "A", "mac", "Файлд хандсан (Accessed)"),
    ("ctime", "C", "mac", "Metadata өөрчлөгдсөн (Changed)"),
]

_MAC_DETAIL: dict[str, str] = {
    "B": (
        "NTFS/APFS зэрэг файлын системийн $STANDARD_INFORMATION Created timestamp. "
        "Файл эхний удаа үүссэн цаг."
    ),
    "M": "Файлын агуулга эсвэл хэмжээ өөрчлөгдсөн — засвар, хадгалалт, хуулбарлах.",
    "A": "Хэрэглэгч эсвэл програм файлд хандсан — нээсэн, уншсан, хуулсан.",
    "C": "Metadata өөрчлөгдсөн — нэр, атрибут, зөвшөөрөл, шилжүүлэх, устгах үйлдэл.",
}

_FINDING_STATUS: dict[FindingType, tuple[str, str, str]] = {
    FindingType.ACTIVE_FILE: (
        "ACTIVE",
        "Идэвхтэй файл",
        "Scan үед файлын системд бүртгэлтэй, ашиглах боломжтой байсан.",
    ),
    FindingType.DELETED_FILE: (
        "DELETED",
        "Устгагдсан файл",
        "Файлын системээс устгагдсан гэж илэрсэн — Shift+Delete эсвэл permanent delete.",
    ),
    FindingType.RECYCLE_ARTIFACT: (
        "RECYCLE",
        "Recycle Bin",
        "Recycle Bin / Trash artifact — хэрэглэгч устгах үйлдэл хийсний ул мөр.",
    ),
    FindingType.CARVED_FILE: (
        "CARVED",
        "Carving",
        "Unallocated space-аас carving-аар сэргээгдсэн — устгагдсан эсвэл форматласны дараа үлдсэн.",
    ),
    FindingType.SLACK_SPACE: (
        "SLACK",
        "Slack space",
        "Cluster slack space-д үлдсэн агуулга.",
    ),
}

_PATH_HINTS: list[tuple[tuple[str, ...], str]] = [
    (("download", "downloads"), "Downloads хавтас — веб, имэйл эсвэл сүлжээнээс татсан байж болзошгүй."),
    (("desktop",), "Desktop — хэрэглэгч шууд хадгалсан эсвэл татсан файл."),
    (("temp", "tmp", "appdata"), "Temp/AppData — програм түр хадгалсан эсвэл суулгагчийн үл мөр."),
    (("usb", "removable", "flash"), "Зөөврийн носитол — USB/flash-оор дамжуулсан байж болзошгүй."),
]


def _aware_ts(value: datetime | None) -> datetime:
    if value is None:
        return datetime.min.replace(tzinfo=timezone.utc)
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _get_ts(finding: Finding, field: str) -> datetime | None:
    return getattr(finding, field, None)


def _path_context(path: str) -> str:
    lower = path.lower().replace("\\", "/")
    for keys, hint in _PATH_HINTS:
        if any(k in lower for k in keys):
            return hint
    if "/" in lower or "\\" in path:
        return f"Зам: {path} — хэрэглэгчийн profile эсвэл програмын хавтас."
    return ""


def _deletion_timestamp(finding: Finding) -> datetime | None:
    """Устгах үйлдлийн ойролцоо цаг — ctime > mtime > atime."""
    meta = finding.meta or {}
    raw = meta.get("deleted_at") or meta.get("deletion_time")
    if raw:
        if isinstance(raw, datetime):
            return raw
        try:
            return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        except ValueError:
            pass
    for field in ("ctime", "mtime", "atime"):
        ts = _get_ts(finding, field)
        if ts is not None:
            return ts
    return None


def build_file_timeline_events(
    finding: Finding,
    stored_events: list[TimelineEvent] | None = None,
) -> list[dict[str, Any]]:
    """Нэг файлын бүрэн timeline — MAC, OS үйлдэл, forensic lifecycle."""
    events: list[dict[str, Any]] = []
    label = finding.file_name or finding.original_path or finding.inode or f"finding-{finding.id}"
    path_ctx = _path_context(finding.original_path or finding.file_name or "")

    # MAC timestamp үйлдлүүд
    seen_mac: set[str] = set()
    for field, kind, category, title in _MAC_EVENTS:
        ts = _get_ts(finding, field)
        if ts is None:
            continue
        key = f"{kind}:{ts.isoformat()}"
        if key in seen_mac:
            continue
        seen_mac.add(key)
        detail = _MAC_DETAIL.get(kind, "")
        if kind == "B" and path_ctx:
            detail = f"{detail} {_path_context(finding.original_path or '')}"
        events.append(
            {
                "id": None,
                "timestamp": ts,
                "event_type": kind,
                "category": category,
                "title": title,
                "description": f"{title}: {label}. {detail}".strip(),
                "source": "ntfs_mac",
            }
        )

    # DB-д хадгалсан timeline (finding_id-тай)
    if stored_events:
        for ev in stored_events:
            if ev.finding_id != finding.id:
                continue
            events.append(
                {
                    "id": ev.id,
                    "timestamp": ev.timestamp,
                    "event_type": ev.event_type,
                    "category": "mac",
                    "title": _MAC_DETAIL.get(ev.event_type, ev.description),
                    "description": ev.description,
                    "source": "scan_timeline",
                }
            )

    # Forensic: илрүүлэлтийн төрөл
    status = _FINDING_STATUS.get(finding.finding_type)
    if status:
        code, title, desc = status
        ts = finding.created_at or _utcnow()
        events.append(
            {
                "id": None,
                "timestamp": ts,
                "event_type": code,
                "category": "forensic",
                "title": title,
                "description": (
                    f"Forensic scan-ээр «{label}» {desc} "
                    f"Эх сурвалж: {finding.source_tool or 'scan'}."
                ),
                "source": "scan_detection",
            }
        )

    # Устгах / recycle тусгай үйл явдал
    if finding.finding_type in (
        FindingType.DELETED_FILE,
        FindingType.RECYCLE_ARTIFACT,
        FindingType.CARVED_FILE,
    ):
        del_ts = _deletion_timestamp(finding)
        if del_ts is not None:
            if finding.finding_type == FindingType.RECYCLE_ARTIFACT:
                del_title = "Recycle Bin-д шилжсэн / устгах үйлдэл"
                del_desc = (
                    "Хэрэглэгч файл устгах үйлдэл хийсэн — Windows Recycle Bin artifact илэрсэн. "
                    "Metadata Changed цаг устгах үйлдэлтэй ойролцоо байж болно."
                )
            elif finding.finding_type == FindingType.CARVED_FILE:
                del_title = "Устгагдсан / форматласны дараа үлдсэн"
                del_desc = (
                    "Файлын системээс алга болсон ч unallocated space-д агуулга үлдсэн. "
                    "Carving-аар сэргээх боломжтой."
                )
            else:
                del_title = "Файл устгагдсан"
                del_desc = (
                    "Permanent delete (Shift+Delete) эсвэл Recycle Bin-ээс хоослосон гэсэн "
                    "таамаглал. Changed/Modified timestamp устгах цагт ойр байж болно."
                )
            events.append(
                {
                    "id": None,
                    "timestamp": del_ts,
                    "event_type": "DELETE",
                    "category": "os",
                    "title": del_title,
                    "description": f"{del_title}: {label}. {del_desc}",
                    "source": "inferred",
                }
            )

    # Сэргээлт
    if finding.recovered:
        rec_ts = finding.created_at or _utcnow()
        events.append(
            {
                "id": None,
                "timestamp": rec_ts,
                "event_type": "RECOVERED",
                "category": "forensic",
                "title": "Forensic сэргээлт",
                "description": (
                    f"«{label}» агуулгыг read-only scan-ийн үед сэргэж, "
                    f"hash баталгаажуулалтад бэлэн болгосон."
                    + (f" SHA-256: {finding.sha256[:16]}…" if finding.sha256 else "")
                ),
                "source": "scan_recovery",
            }
        )

    # Давхардал арилгах (timestamp + event_type)
    unique: dict[tuple[str, str], dict[str, Any]] = {}
    for ev in events:
        ts = ev["timestamp"]
        key = (ev["event_type"], ts.isoformat() if ts else "")
        if key not in unique or ev.get("source") == "ntfs_mac":
            unique[key] = ev
    events = list(unique.values())
    events.sort(key=lambda e: _aware_ts(e["timestamp"]))

    # Дарааллын дугаар
    for idx, ev in enumerate(events, start=1):
        ev["sequence"] = idx

    return events


def build_file_timeline_narrative(finding: Finding, events: list[dict[str, Any]]) -> str:
    """Файлын lifecycle-ийн товч narrative."""
    if not events:
        return "Энэ файлд timestamp бүртгэгдээгүй."

    label = finding.file_name or finding.original_path or "—"
    first = events[0]["timestamp"]
    last = events[-1]["timestamp"]
    mac_count = sum(1 for e in events if e["category"] == "mac")
    parts = [
        f"«{label}» файлын {len(events)} үйл явдлыг цагийн дарааллаар нэгтгэсэн.",
        f"Хугацаа: {first.strftime('%Y-%m-%d %H:%M') if first else '—'}"
        f" – {last.strftime('%Y-%m-%d %H:%M') if last else '—'}.",
        f"Үйлдлийн системийн MAC timestamp: {mac_count}.",
    ]
    path_hint = _path_context(finding.original_path or "")
    if path_hint:
        parts.append(path_hint)

    if finding.finding_type != FindingType.ACTIVE_FILE:
        parts.append(
            "Файл одоогоор идэвхтэй биш — устгагдсан, recycle эсвэл carving-аар илэрсэн."
        )
    return " ".join(parts)


def summarize_file_timeline(finding: Finding, events: list[dict[str, Any]]) -> dict[str, Any]:
    ts_list = [_aware_ts(e["timestamp"]) for e in events if e.get("timestamp")]
    return {
        "finding_id": finding.id,
        "file_name": finding.file_name,
        "original_path": finding.original_path,
        "finding_type": finding.finding_type.value,
        "severity": finding.severity.value,
        "mime_type": finding.mime_type,
        "size_bytes": finding.size_bytes,
        "recovered": finding.recovered,
        "event_count": len(events),
        "mac_events": sum(1 for e in events if e["category"] == "mac"),
        "forensic_events": sum(1 for e in events if e["category"] == "forensic"),
        "first_timestamp": min(ts_list) if ts_list else None,
        "last_timestamp": max(ts_list) if ts_list else None,
    }


def build_scan_timeline_by_file(
    findings: list[Finding],
    timeline: list[TimelineEvent],
) -> list[dict[str, Any]]:
    """Scan-ийн бүх файлыг timeline-аар бүлэглэнэ."""
    events_by_finding: dict[int, list[TimelineEvent]] = {}
    for ev in timeline:
        if ev.finding_id is None:
            continue
        events_by_finding.setdefault(ev.finding_id, []).append(ev)

    rows: list[dict[str, Any]] = []
    for finding in findings:
        stored = events_by_finding.get(finding.id, [])
        file_events = build_file_timeline_events(finding, stored)
        summary = summarize_file_timeline(finding, file_events)
        rows.append(summary)

    rows.sort(
        key=lambda r: (
            r["last_timestamp"] is None,
            -(r["last_timestamp"].timestamp() if r["last_timestamp"] else 0),
        )
    )
    return rows


def build_file_timeline_detail(
    finding: Finding,
    stored_events: list[TimelineEvent],
) -> dict[str, Any]:
    events = build_file_timeline_events(finding, stored_events)
    summary = summarize_file_timeline(finding, events)
    return {
        **summary,
        "events": events,
        "narrative": build_file_timeline_narrative(finding, events),
    }
