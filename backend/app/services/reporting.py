"""Forensic тайлан үүсгэх (HTML, JSON).

Тайлан нь хэргийн мэдээлэл, төхөөрөмж, илэрсэн файлууд (идэвхтэй + устгагдсан),
timeline болон audit бүртгэлийг агуулна. HTML-ийг хөтчөөс PDF болгон хэвлэх
боломжтой.
"""
from __future__ import annotations

import html
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models import (
    AuditLog,
    Case,
    Device,
    Finding,
    ScanJob,
    TimelineEvent,
)


def _esc(value: object) -> str:
    return html.escape(str(value if value is not None else ""))


def build_report_data(db: Session, scan_id: int) -> dict:
    scan = db.get(ScanJob, scan_id)
    if scan is None:
        raise ValueError("Scan олдсонгүй")
    device = db.get(Device, scan.device_id)
    case = db.get(Case, device.case_id) if device and device.case_id else None
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).order_by(Finding.severity.desc()).all()
    timeline = (
        db.query(TimelineEvent)
        .filter(TimelineEvent.scan_id == scan_id)
        .order_by(TimelineEvent.timestamp.asc())
        .all()
    )
    audit = []
    if case:
        audit = db.query(AuditLog).filter(AuditLog.case_id == case.id).order_by(AuditLog.timestamp.asc()).all()

    by_type: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for f in findings:
        by_type[f.finding_type.value] = by_type.get(f.finding_type.value, 0) + 1
        by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1

    return {
        "generated_at": datetime.now(timezone.utc),
        "case": case,
        "device": device,
        "scan": scan,
        "findings": findings,
        "timeline": timeline,
        "audit": audit,
        "summary": {
            "total_findings": len(findings),
            "recovered": sum(1 for f in findings if f.recovered),
            "deleted": sum(1 for f in findings if (f.meta or {}).get("deleted")),
            "by_type": by_type,
            "by_severity": by_severity,
        },
    }


def render_html(data: dict) -> str:
    case = data["case"]
    device = data["device"]
    scan = data["scan"]
    summary = data["summary"]

    def row(cells: list[str], tag: str = "td") -> str:
        return "<tr>" + "".join(f"<{tag}>{c}</{tag}>" for c in cells) + "</tr>"

    def _ts(value: object) -> str:
        return str(value)[:19] if value else "—"

    findings_html = "".join(
        row([
            _esc(f.id),
            _esc(f.finding_type.value),
            f'<span class="sev sev-{f.severity.value}">{_esc(f.severity.value)}</span>',
            _esc(f.file_name),
            _esc(f.original_path),
            _esc(f.size_bytes),
            _ts(f.mtime),
            _ts(f.atime),
            _ts(f.ctime),
            _ts(f.crtime),
            "✓" if f.recovered else "",
        ])
        for f in data["findings"]
    ) or row(["—"] * 11)

    timeline_html = "".join(
        row([_esc(e.timestamp), _esc(e.event_type), _esc(e.description)])
        for e in data["timeline"]
    ) or row(["—", "", ""])

    audit_html = "".join(
        row([_esc(a.timestamp), _esc(a.action), _esc(a.actor), _esc(a.target)])
        for a in data["audit"]
    ) or row(["—", "", "", ""])

    sev_summary = ", ".join(f"{k}: {v}" for k, v in summary["by_severity"].items()) or "—"
    type_summary = ", ".join(f"{k}: {v}" for k, v in summary["by_type"].items()) or "—"

    return f"""<!DOCTYPE html>
<html lang="mn">
<head>
<meta charset="utf-8">
<title>Forensic тайлан — Scan #{_esc(scan.id)}</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 32px; color: #1a1a2e; }}
  h1 {{ border-bottom: 3px solid #0f3460; padding-bottom: 8px; }}
  h2 {{ color: #0f3460; margin-top: 28px; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 8px; font-size: 13px; }}
  th, td {{ border: 1px solid #ccc; padding: 6px 8px; text-align: left; vertical-align: top; }}
  th {{ background: #0f3460; color: #fff; }}
  .meta td:first-child {{ font-weight: 600; width: 220px; background: #f3f4f8; }}
  .sev {{ padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; }}
  .sev-high {{ background: #ffd6d6; color: #a40000; }}
  .sev-medium {{ background: #ffe9c7; color: #8a5a00; }}
  .sev-normal {{ background: #d8f0db; color: #1a6b2a; }}
  .sev-low {{ background: #e3f0ff; color: #0b4a8a; }}
  .sev-info {{ background: #eee; color: #555; }}
  .badge {{ display:inline-block; background:#0f3460; color:#fff; padding:3px 10px; border-radius:12px; }}
</style>
</head>
<body>
  <h1>Removable Evidence Analyzer — Forensic тайлан</h1>
  <p>Үүсгэсэн: <strong>{_esc(data['generated_at'])}</strong> · Scan #<strong>{_esc(scan.id)}</strong></p>

  <h2>1. Хэргийн мэдээлэл</h2>
  <table class="meta">
    {row(["Хэргийн дугаар", _esc(case.case_number if case else '—')])}
    {row(["Гарчиг", _esc(case.title if case else '—')])}
    {row(["Шинжээч", _esc(case.investigator if case else '—')])}
    {row(["Тайлбар", _esc(case.description if case else '—')])}
  </table>

  <h2>2. Төхөөрөмжийн мэдээлэл</h2>
  <table class="meta">
    {row(["Зам (dev)", _esc(device.dev_path if device else '—')])}
    {row(["Нэр / Модель", _esc(device.name if device else '—')])}
    {row(["Сериал", _esc(device.serial if device else '—')])}
    {row(["Холболт (bus)", _esc(device.bus if device else '—')])}
    {row(["Хэмжээ (bytes)", _esc(device.size_bytes if device else '—')])}
    {row(["Файлын систем", _esc(device.fs_type if device else '—')])}
    {row(["Read-only", "Тийм" if device and device.read_only else "Үгүй"])}
  </table>

  <h2>3. Дүгнэлт</h2>
  <p>
    <span class="badge">Нийт файл: {summary['total_findings']}</span>
    <span class="badge">Устгагдсан: {summary.get('deleted', 0)}</span>
    <span class="badge">Сэргээсэн: {summary['recovered']}</span>
  </p>
  <p>Төрлөөр: {_esc(type_summary)}<br>Зэрэглэлээр: {_esc(sev_summary)}</p>

  <h2>4. Файлын жагсаалт (хэзээ ямар үйлдэл хийсэн — MACB цаг)</h2>
  <table>
    {row(["ID", "Төрөл", "Зэрэг", "Файл", "Эх зам", "Хэмжээ", "Modified", "Accessed", "Changed", "Born", "Сэргээсэн"], "th")}
    {findings_html}
  </table>

  <h2>5. Timeline</h2>
  <table>
    {row(["Цаг", "Төрөл (MACB)", "Тайлбар"], "th")}
    {timeline_html}
  </table>

  <h2>6. Chain-of-custody (audit) бүртгэл</h2>
  <table>
    {row(["Цаг", "Үйлдэл", "Хэрэглэгч", "Объект"], "th")}
    {audit_html}
  </table>

  <hr>
  <p style="color:#888;font-size:12px;">Removable Evidence Analyzer-ээр автоматаар үүсгэв. Энэ тайланг хөтчийн "Хэвлэх → PDF болгон хадгалах" замаар PDF болгож болно.</p>
</body>
</html>"""
