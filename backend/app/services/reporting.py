"""Forensic тайлан үүсгэх (HTML, JSON).

Тайлан нь төхөөрөмж, илэрсэн файлууд (идэвхтэй + устгагдсан),
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
    FindingType,
    ScanJob,
    TimelineEvent,
)
from app.services.forensic_report import enrich_forensic_report


def _esc(value: object) -> str:
    return html.escape(str(value if value is not None else ""))


def _narrative_html(text: str) -> str:
    if not text:
        return ""
    return "\n  ".join(
        f'<p class="exec">{_esc(p.strip())}</p>'
        for p in text.split("\n\n")
        if p.strip()
    )


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

    forensic = enrich_forensic_report(findings, timeline)

    return {
        "generated_at": datetime.now(timezone.utc),
        "case": case,
        "device": device,
        "scan": scan,
        "findings": findings,
        "timeline": timeline,
        "audit": audit,
        "forensic": forensic,
        "summary": {
            "total_findings": len(findings),
            "recovered": sum(1 for f in findings if f.recovered),
            "deleted": sum(
                1 for f in findings
                if f.finding_type != FindingType.ACTIVE_FILE
            ),
            "by_type": by_type,
            "by_severity": by_severity,
            "suspicious_count": forensic["risk_assessment"]["suspicious_count"],
            "suspicious_percent": forensic["risk_assessment"]["suspicious_percent"],
        },
    }


def render_html(data: dict) -> str:
    case = data["case"]
    device = data["device"]
    scan = data["scan"]
    summary = data["summary"]
    forensic = data["forensic"]
    risk = forensic["risk_assessment"]
    corr = forensic["correlations"]

    def row(cells: list[str], tag: str = "td") -> str:
        return "<tr>" + "".join(f"<{tag}>{c}</{tag}>" for c in cells) + "</tr>"

    def _ts(value: object) -> str:
        return str(value)[:19] if value else "—"

    def _sev_badge(sev: str) -> str:
        return f'<span class="sev sev-{sev}">{_esc(sev)}</span>'

    correlated_html = "".join(
        row([
            _ts(e.get("timestamp")),
            _esc(e.get("event_type")),
            _sev_badge(str(e.get("severity", "normal"))),
            _esc(e.get("file_name") or "—"),
            _esc(e.get("original_path") or "—"),
            str(e.get("risk_score", 0)),
            _esc(e.get("event_label")),
        ])
        for e in forensic["correlated_timeline"]
    ) or row(["—"] * 7)

    high_risk_html = "".join(
        row([
            _sev_badge("high"),
            _esc(f.get("file_name")),
            _esc(f.get("original_path")),
            str(f.get("risk_score", 0)),
            _esc(", ".join(f.get("information_types") or [])[:80]),
            _ts(f.get("mtime")),
        ])
        for f in risk.get("high_risk_findings", [])
    ) or row(["—"] * 6)

    cluster_html = "".join(
        row([
            _esc(c.get("window")),
            str(c.get("event_count")),
            str(c.get("high_risk_events")),
            str(c.get("medium_risk_events")),
            _esc(c.get("note")),
        ])
        for c in corr.get("time_clusters", [])[:40]
    ) or row(["—"] * 5)

    findings_html = "".join(
        row([
            _esc(f.id),
            _esc(f.finding_type.value),
            _sev_badge(f.severity.value),
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

    audit_html = "".join(
        row([_esc(a.timestamp), _esc(a.action), _esc(a.actor), _esc(a.target)])
        for a in data["audit"]
    ) or row(["—", "", "", ""])

    sev_summary = ", ".join(f"{k}: {v}" for k, v in summary["by_severity"].items()) or "—"
    type_summary = ", ".join(f"{k}: {v}" for k, v in summary["by_type"].items()) or "—"
    report_title = forensic.get("report_title", "Forensic тайлан")

    return f"""<!DOCTYPE html>
<html lang="mn">
<head>
<meta charset="utf-8">
<title>{_esc(report_title)} — Scan #{_esc(scan.id)}</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 32px; color: #1a1a2e; line-height: 1.45; }}
  h1 {{ border-bottom: 3px solid #0f3460; padding-bottom: 8px; font-size: 22px; }}
  h2 {{ color: #0f3460; margin-top: 28px; font-size: 16px; }}
  .exec {{ background: #f0f4fa; border-left: 4px solid #0f3460; padding: 14px 16px; margin: 16px 0; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 8px; font-size: 12px; }}
  th, td {{ border: 1px solid #ccc; padding: 6px 8px; text-align: left; vertical-align: top; }}
  th {{ background: #0f3460; color: #fff; }}
  .meta td:first-child {{ font-weight: 600; width: 220px; background: #f3f4f8; }}
  .sev {{ padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; }}
  .sev-high {{ background: #ffd6d6; color: #a40000; }}
  .sev-medium {{ background: #ffe9c7; color: #8a5a00; }}
  .sev-normal {{ background: #d8f0db; color: #1a6b2a; }}
  .badge {{ display:inline-block; background:#0f3460; color:#fff; padding:3px 10px; border-radius:12px; margin-right:6px; }}
</style>
</head>
<body>
  <h1>{_esc(report_title)}</h1>
  <p>Үүсгэсэн: <strong>{_esc(data['generated_at'])}</strong> · Scan #<strong>{_esc(scan.id)}</strong></p>
  <p><em>Стандарт: {_esc(risk.get('standard', ''))}</em></p>

  <h2>1. Төхөөрөмж</h2>
  <table class="meta">
    {row(["Зам (dev)", _esc(device.dev_path if device else '—')])}
    {row(["Нэр", _esc(device.name if device else '—')])}
    {row(["Хэмжээ", _esc(device.size_bytes if device else '—')])}
    {row(["FS", _esc(device.fs_type if device else '—')])}
    {row(["Read-only", "Тийм" if device and device.read_only else "Үгүй"])}
  </table>

  <h2>2. Сэжигтэй байдлын үнэлгээ (эрсдэл)</h2>
  <div class="exec">{_esc(risk.get('executive_narrative', ''))}</div>
  <p>
    <span class="badge">Нийт: {summary['total_findings']}</span>
    <span class="badge">Сэжигтэй: {summary.get('suspicious_count', 0)} ({summary.get('suspicious_percent', 0)}%)</span>
    <span class="badge">Сэргээсэн: {summary['recovered']}</span>
  </p>
  <p>Төрлөөр: {_esc(type_summary)}<br>Зэрэглэлээр: {_esc(sev_summary)}</p>

  <h2>3. Шинжээчийн тайлан</h2>
  <h3 style="font-size:14px;color:#0f3460;margin-top:12px;">Timeline</h3>
  {_narrative_html(forensic.get("timeline_narrative", ""))}
  <h3 style="font-size:14px;color:#0f3460;margin-top:12px;">Correlation шинжилгээ</h3>
  {_narrative_html(forensic.get("correlation_narrative", ""))}
  <h3 style="font-size:14px;color:#0f3460;margin-top:12px;">Зөвлөмж</h3>
  {_narrative_html(forensic.get("recommendations_narrative", ""))}
  <h3 style="font-size:14px;color:#0f3460;margin-top:12px;">Нэгдсэн дүгнэлт</h3>
  {_narrative_html(forensic.get("examiner_report", ""))}

  <h2>4. Өндөр эрсдэлтэй файлууд (metadata + FIPS)</h2>
  <table>
    {row(["Зэрэг", "Файл", "Зам", "FIPS", "Мэдээллийн төрөл", "Modified"], "th")}
    {high_risk_html}
  </table>

  <h2>5. Уялдуулсан timeline (timestamp + metadata + эрсдэл)</h2>
  <p>Бүх илэрсэн ул мөрийн MAC цагийг metadata болон эрсдэлийн түвшинтэй хамт цагийн дарааллаар.</p>
  <table>
    {row(["Цаг", "MACB", "Эрсдэл", "Файл", "Зам", "FIPS", "Үйлдэл"], "th")}
    {correlated_html}
  </table>

  <h2>6. Цаг хугацааны cluster (correlation)</h2>
  <table>
    {row(["Цагийн цонх", "Үйлдэл", "Өндөр", "Дунд", "Тайлбар"], "th")}
    {cluster_html}
  </table>

  <h2>7. Бүрэн файлын metadata (MACB)</h2>
  <table>
    {row(["ID", "Төрөл", "Зэрэг", "Файл", "Зам", "Хэмжээ", "M", "A", "C", "B", "Сэргээсэн"], "th")}
    {findings_html}
  </table>

  <h2>8. Chain-of-custody</h2>
  <table>
    {row(["Цаг", "Үйлдэл", "Хэрэглэгч", "Объект"], "th")}
    {audit_html}
  </table>

  <hr>
  <p style="color:#888;font-size:12px;">Зөөврийн мэдээлэл тээгч төхөөрөмжийн тоон ул мөр илрүүлэх систем — автomat forensic тайлан.</p>
</body>
</html>"""
