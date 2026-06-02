"""Forensic тайлан — timestamp + metadata уялduulalt, timeline, эрсдэлийн үнэлгээ.

Бүх илэрсэн ул мөрийг MAC цаг, metadata, NIST/FIPS эрсдэлээр холбож
цаг хугацааны дарааллын (timeline) болон сэжигтэй байдлын дүгнэлт үүсгэнэ.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from app.models import Finding, Severity, TimelineEvent
from app.services.risk_assessment import RISK_STANDARD
from app.services.report_narrative import (
    narrate_correlation,
    narrate_scan_executive,
    narrate_scan_recommendations,
    narrate_timeline_overview,
)

_EVENT_LABELS = {
    "B": "Born — үүссэн",
    "M": "Modified — өөрчилсөн",
    "A": "Accessed — хандсан",
    "C": "Changed — метадата",
}

_SEV_ORDER = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.NORMAL: 2}


def _finding_profile(f: Finding) -> dict[str, Any]:
    meta = f.meta or {}
    return {
        "finding_id": f.id,
        "file_name": f.file_name,
        "original_path": f.original_path,
        "finding_type": f.finding_type.value,
        "severity": f.severity.value,
        "risk_score": meta.get("risk_score", 0),
        "risk_overall_impact": meta.get("risk_overall_impact", "low"),
        "risk_confidentiality": meta.get("risk_confidentiality"),
        "risk_integrity": meta.get("risk_integrity"),
        "risk_availability": meta.get("risk_availability"),
        "information_types": meta.get("risk_information_types") or [],
        "mime_type": f.mime_type,
        "size_bytes": f.size_bytes,
        "recovered": f.recovered,
        "md5": f.md5,
        "sha256": f.sha256,
        "mtime": f.mtime,
        "atime": f.atime,
        "ctime": f.ctime,
        "crtime": f.crtime,
        "executive_summary": (meta.get("risk_report") or {}).get("executive_summary", ""),
    }


def build_correlated_timeline(
    findings: list[Finding],
    timeline: list[TimelineEvent],
) -> list[dict[str, Any]]:
    """Timeline үйл явдлыг finding metadata + эрсдэлээр уялduulna."""
    fmap = {f.id: f for f in findings}
    rows: list[dict[str, Any]] = []

    for ev in timeline:
        f = fmap.get(ev.finding_id) if ev.finding_id else None
        meta = f.meta if f else {}
        rows.append(
            {
                "timestamp": ev.timestamp,
                "event_type": ev.event_type,
                "event_label": _EVENT_LABELS.get(ev.event_type, ev.event_type),
                "description": ev.description,
                "finding_id": ev.finding_id,
                "file_name": f.file_name if f else "",
                "original_path": f.original_path if f else "",
                "finding_type": f.finding_type.value if f else "",
                "severity": f.severity.value if f else "normal",
                "risk_score": meta.get("risk_score", 0) if meta else 0,
                "risk_overall_impact": meta.get("risk_overall_impact", "low") if meta else "low",
                "mime_type": f.mime_type if f else "",
                "size_bytes": f.size_bytes if f else 0,
                "recovered": f.recovered if f else False,
            }
        )

    rows.sort(key=lambda r: r["timestamp"] or datetime.min.replace(tzinfo=timezone.utc))
    return rows


def _cluster_by_hour(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Ижил цагийн цонхond олон үйлдэл — сэжигтэй cluster."""
    buckets: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        ts = r.get("timestamp")
        if not ts:
            continue
        key = ts.strftime("%Y-%m-%d %H:00")
        buckets[key].append(r)

    clusters: list[dict[str, Any]] = []
    for window, events in sorted(buckets.items()):
        if len(events) < 2:
            continue
        high = sum(1 for e in events if e.get("severity") == "high")
        medium = sum(1 for e in events if e.get("severity") == "medium")
        finding_ids = sorted({e["finding_id"] for e in events if e.get("finding_id")})
        clusters.append(
            {
                "window": window,
                "event_count": len(events),
                "high_risk_events": high,
                "medium_risk_events": medium,
                "finding_count": len(finding_ids),
                "finding_ids": finding_ids[:20],
                "note": (
                    f"{window} цагийн завсарт {len(events)} үйлдэл, "
                    f"өндөр эрсдэл {high}, дунд {medium}."
                ),
            }
        )
    clusters.sort(key=lambda c: (c["high_risk_events"], c["event_count"]), reverse=True)
    return clusters[:30]


def build_risk_assessment_summary(findings: list[Finding]) -> dict[str, Any]:
    """Сэжигтэй байдлын нэгдсэн үнэлгээ."""
    by_sev: dict[str, int] = defaultdict(int)
    high_findings: list[dict] = []
    medium_findings: list[dict] = []

    for f in findings:
        by_sev[f.severity.value] += 1
        profile = _finding_profile(f)
        if f.severity == Severity.HIGH:
            high_findings.append(profile)
        elif f.severity == Severity.MEDIUM:
            medium_findings.append(profile)

    high_findings.sort(key=lambda x: x.get("risk_score", 0), reverse=True)
    medium_findings.sort(key=lambda x: x.get("risk_score", 0), reverse=True)

    total = len(findings)
    suspicious = by_sev.get("high", 0) + by_sev.get("medium", 0)
    sus_pct = round(suspicious / total * 100, 1) if total else 0.0

    narrative = narrate_scan_executive(
        total=total,
        high=by_sev.get("high", 0),
        medium=by_sev.get("medium", 0),
        normal=by_sev.get("normal", 0),
        suspicious=suspicious,
        sus_pct=sus_pct,
        timeline_count=0,
    )

    return {
        "standard": RISK_STANDARD,
        "total_findings": total,
        "by_severity": dict(by_sev),
        "suspicious_count": suspicious,
        "suspicious_percent": sus_pct,
        "high_risk_findings": high_findings[:25],
        "medium_risk_findings": medium_findings[:25],
        "executive_narrative": narrative,
    }


def build_correlation_analysis(
    findings: list[Finding],
    correlated_timeline: list[dict[str, Any]],
) -> dict[str, Any]:
    """Metadata + цаг хугацааны хамаарал, cluster."""
    deleted_types = {"deleted_file", "recycle_artifact", "carved_file"}
    deletion_findings = [f for f in findings if f.finding_type.value in deleted_types]
    high_risk_deleted = [f for f in deletion_findings if f.severity in (Severity.HIGH, Severity.MEDIUM)]

    # Ижил замын folder-д олон эмзэг файл
    path_groups: dict[str, list[int]] = defaultdict(list)
    for f in findings:
        if f.severity not in (Severity.HIGH, Severity.MEDIUM):
            continue
        folder = (f.original_path or f.file_name).rsplit("/", 1)[0] or "/"
        path_groups[folder.lower()].append(f.id)

    path_hotspots = [
        {"folder": k, "finding_ids": v[:15], "count": len(v)}
        for k, v in path_groups.items()
        if len(v) >= 2
    ]
    path_hotspots.sort(key=lambda x: x["count"], reverse=True)

    return {
        "time_clusters": _cluster_by_hour(correlated_timeline),
        "deletion_activity": {
            "total_deleted_artifacts": len(deletion_findings),
            "high_medium_risk_deleted": len(high_risk_deleted),
            "finding_ids": [f.id for f in high_risk_deleted[:20]],
        },
        "path_hotspots": path_hotspots[:15],
    }


def enrich_forensic_report(
    findings: list[Finding],
    timeline: list[TimelineEvent],
) -> dict[str, Any]:
    """Forensic тайланд нэмэх уялduulсан өгөгдөл."""
    correlated = build_correlated_timeline(findings, timeline)
    risk_summary = build_risk_assessment_summary(findings)
    correlations = build_correlation_analysis(findings, correlated)

    # Timeline narrative-д event count дамjuulna
    risk_summary["executive_narrative"] = narrate_scan_executive(
        total=risk_summary["total_findings"],
        high=risk_summary["by_severity"].get("high", 0),
        medium=risk_summary["by_severity"].get("medium", 0),
        normal=risk_summary["by_severity"].get("normal", 0),
        suspicious=risk_summary["suspicious_count"],
        sus_pct=risk_summary["suspicious_percent"],
        timeline_count=len(correlated),
    )

    high_ev = sum(1 for r in correlated if r.get("severity") == "high")
    ts_list = [r["timestamp"] for r in correlated if r.get("timestamp")]
    first_ts = str(min(ts_list))[:19] if ts_list else ""
    last_ts = str(max(ts_list))[:19] if ts_list else ""

    timeline_narrative = narrate_timeline_overview(
        event_count=len(correlated),
        high_events=high_ev,
        first_ts=first_ts,
        last_ts=last_ts,
    )
    correlation_narrative = narrate_correlation(
        clusters=correlations.get("time_clusters", []),
        path_hotspots=correlations.get("path_hotspots", []),
        deletion=correlations.get("deletion_activity", {}),
    )
    recommendations_narrative = narrate_scan_recommendations(
        high=risk_summary["by_severity"].get("high", 0),
        medium=risk_summary["by_severity"].get("medium", 0),
        deletion_high=correlations.get("deletion_activity", {}).get("high_medium_risk_deleted", 0),
        cluster_count=len(correlations.get("time_clusters", [])),
    )

    finding_profiles = [_finding_profile(f) for f in sorted(findings, key=lambda x: _SEV_ORDER.get(x.severity, 9))]

    examiner_report = (
        f"{risk_summary['executive_narrative']}\n\n"
        f"{timeline_narrative}\n\n"
        f"{correlation_narrative}\n\n"
        f"{recommendations_narrative}"
    )

    return {
        "correlated_timeline": correlated,
        "risk_assessment": risk_summary,
        "correlations": correlations,
        "finding_profiles": finding_profiles,
        "timeline_narrative": timeline_narrative,
        "correlation_narrative": correlation_narrative,
        "recommendations_narrative": recommendations_narrative,
        "examiner_report": examiner_report,
        "report_title": "Forensic тайлан — timestamp, metadata уялдуулалт, эрсдэлийн үнэлгээ",
    }
