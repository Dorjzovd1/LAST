"""Файлын шинжилгээний оркестратор.

Нэг scan ажлыг (ScanJob) гүйцэтгэх логик:
  1. Шинжлэх эх сурвалж бэлтгэх (төхөөрөмж/хуваалт — read-only).
  2. БҮХ файлыг (идэвхтэй + устгагдсан) жагсааж MAC цаг (хэзээ ямар үйлдэл
     хийсэн) болон бусад мэдээллийг авах (TSK). Устгагдсаныг нь сэргээх.
  3. Unallocated/slack space-аас carving.
  4. Recycle/Trash artifact задлах.
  5. Metadata нормчлол + timeline үүсгэх.

Энэ функц нь тусдаа thread дотор ажиллаж, явцыг DB болон WebSocket hub руу мэдээлнэ.
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timezone

from app.config import get_settings
from app.core import audit
from app.core.events import hub
from app.database import SessionLocal
from app.models import (
    Device,
    DeviceState,
    Finding,
    FindingType,
    ScanJob,
    ScanStatus,
)
from app.services import carving, metadata, named_recovery, recycle, tsk, writeblock
from app.services.hashing import hash_file

logger = logging.getLogger("rea.scanner")
settings = get_settings()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _progress(db, job: ScanJob, pct: float, step: str) -> None:
    job.progress = round(pct, 1)
    job.current_step = step
    db.add(job)
    db.commit()
    hub.publish(
        "scan_progress",
        {"scan_id": job.id, "progress": job.progress, "step": step, "status": job.status.value},
    )
    logger.info("[scan %s] %.1f%% — %s", job.id, pct, step)


def run_scan(scan_id: int) -> None:
    """ScanJob-ийг бүрэн гүйцэтгэнэ (background thread дотор)."""
    db = SessionLocal()
    try:
        job = db.get(ScanJob, scan_id)
        if job is None:
            logger.error("ScanJob %s олдсонгүй.", scan_id)
            return

        device = db.get(Device, job.device_id)
        options = job.options or {}

        job.status = ScanStatus.RUNNING
        job.started_at = _utcnow()
        db.add(job)
        db.commit()
        case_id = device.case_id if device else None
        audit.record(db, action="scan_started", target=device.dev_path if device else "", case_id=case_id, detail={"scan_id": scan_id})

        _progress(db, job, 2, "Эх сурвалж бэлтгэж байна")
        source_path, byte_offsets, mount_point = _prepare_source(db, job, device, options)

        total_findings = 0

        # 1) Бүх файл (TSK fls -d — идэвхтэй + Shift+Delete устгагдсан) ------
        _progress(db, job, 15, "Бүх файл + Shift+Delete устгагдсан (TSK -d)")
        for off in byte_offsets:
            for entry in tsk.list_all_files(source_path, off):
                f = _finding_from_entry(job.id, entry)
                if entry.deleted:
                    _maybe_recover(source_path, off, entry, f, options, device)
                _finalize_finding(db, f)
                total_findings += 1

        # 2) FS-т тохирсон нэртэй сэргээлт (ntfsundelete — Shift+Delete NTFS) ---
        if options.get("run_named_tools", True) and device:
            fs = device.fs_type or ""
            part = named_recovery.resolve_partition_path(
                device.dev_path, fs, device.details or {}
            )
            _progress(db, job, 40, f"NTFS permanent delete сэргээлт ({fs or 'auto'})")
            total_findings += _run_named_recovery(db, job, part, fs)

        # 3) Carving (signature — нэргүй, зөвхөн run_carving=true үед) -------
        if options.get("run_carving", False):
            _progress(db, job, 55, "Signature carving (нэргүй — уdaан)")
            total_findings += _run_carving(db, job, source_path, byte_offsets)

        # 4) Recycle / Trash artifact ----------------------------------------
        if options.get("run_recycle", True):
            _progress(db, job, 75, "Recycle/Trash (анхны замтай)")
            total_findings += _run_recycle(db, job, mount_point)

        # 5) Timeline --------------------------------------------------------
        _progress(db, job, 90, "Timeline үүсгэж байна")
        _build_timeline(db, job)

        if mount_point:
            writeblock.unmount(mount_point)

        job.status = ScanStatus.COMPLETED
        job.finished_at = _utcnow()
        job.progress = 100.0
        job.current_step = f"Дууссан — {total_findings} файл бүртгэгдсэн"
        db.add(job)
        if device and device.state != DeviceState.REMOVED:
            device.state = DeviceState.ANALYZED
            db.add(device)
        db.commit()
        audit.record(db, action="scan_completed", target=str(scan_id), case_id=case_id, detail={"findings": total_findings})
        hub.publish("scan_completed", {"scan_id": scan_id, "findings": total_findings})

    except Exception as exc:  # noqa: BLE001
        logger.exception("Scan %s алдаа", scan_id)
        db.rollback()
        job = db.get(ScanJob, scan_id)
        if job:
            job.status = ScanStatus.FAILED
            job.error = str(exc)
            job.finished_at = _utcnow()
            db.add(job)
            db.commit()
            hub.publish("scan_failed", {"scan_id": scan_id, "error": str(exc)})
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# Source preparation
# --------------------------------------------------------------------------- #
def _prepare_source(db, job: ScanJob, device: Device, options: dict):
    """Шинжлэх эх сурвалж (төхөөрөмж/хуваалт) болон offset-уудыг бэлтгэнэ.

    Read-only горимоор төхөөрөмж дээр шууд TSK ажиллуулна (forensic дүрс авахгүй).
    """
    source_path = device.dev_path if device else ""
    mount_point: str | None = None

    if device:
        source_path = named_recovery.resolve_partition_path(
            device.dev_path, device.fs_type or "", device.details or {}
        )
        logger.info("Шинжилгээний эх сурвалж: %s", source_path)

    # Хуваалтын offset-ууд (mmls).
    partitions = tsk.list_partitions(source_path)
    byte_offsets = [p.byte_offset for p in partitions] or [0]

    # Recycle artifact-д зориулж read-only mount оролдоно.
    if options.get("run_recycle", True) and device:
        try:
            mount_point = writeblock.mount_read_only(device.dev_path)
        except Exception as exc:  # noqa: BLE001
            logger.info("Read-only mount амжилтгүй (mock/dev байж болно): %s", exc)
            mount_point = None

    return source_path, byte_offsets, mount_point


# --------------------------------------------------------------------------- #
# Finding builders
# --------------------------------------------------------------------------- #
def _finding_from_entry(scan_id: int, entry: tsk.DeletedEntry) -> Finding:
    """Файлын бичлэг (идэвхтэй эсвэл устгагдсан) — зам, нэр, MAC цагтай.

    Идэвхтэй файл → ACTIVE_FILE, устгагдсан → DELETED_FILE. MAC timestamp
    (modified/accessed/changed/born) нь "хэзээ ямар үйлдэл хийсэн"-ийг илэрхийлнэ.
    """
    path = entry.name.replace("\\", "/")
    file_name = os.path.basename(path.rstrip("/")) or path.lstrip("/") or entry.name
    finding_type = FindingType.DELETED_FILE if entry.deleted else FindingType.ACTIVE_FILE
    return Finding(
        scan_id=scan_id,
        finding_type=finding_type,
        file_name=file_name,
        original_path=path if path.startswith("/") else f"/{path}",
        inode=entry.inode,
        size_bytes=entry.size,
        mtime=entry.mtime,
        atime=entry.atime,
        ctime=entry.ctime,
        crtime=entry.crtime,
        source_tool="tsk-fls",
        meta={
            **entry.meta,
            "has_original_name": True,
            "deleted": entry.deleted,
            "recovery_method": "filesystem_metadata",
        },
    )


def _maybe_recover(
    source_path,
    byte_offset,
    entry,
    finding: Finding,
    options: dict,
    device: Device | None = None,
) -> None:
    if not options.get("recover_files", True) or entry.file_type != "r":
        return
    max_bytes = int(options.get("max_recover_size_mb", 512)) * 1024 * 1024
    if entry.size and entry.size > max_bytes:
        finding.meta = {**finding.meta, "skipped": "size_limit"}
        return
    dest = settings.recovered_dir / f"scan_{finding.scan_id}" / f"{entry.inode.replace('/', '_')}_{finding.file_name}"
    ok = tsk.recover_inode(source_path, entry.inode, str(dest), byte_offset)
    if ok and os.path.exists(dest):
        finding.recovered = True
        finding.recovered_path = str(dest)
        finding.meta = {**finding.meta, "recovery_tool": "icat"}
        return

    # Shift+Delete NTFS: icat амжилтгүй бол ntfsundelete fallback.
    fs = (device.fs_type or "").lower() if device else ""
    if fs in ("ntfs", "exfat") and entry.inode:
        part = source_path
        if device:
            part = named_recovery.resolve_partition_path(
                device.dev_path, fs, device.details or {}
            )
        if named_recovery.recover_ntfs_inode(part, entry.inode, str(dest)):
            finding.recovered = True
            finding.recovered_path = str(dest)
            finding.meta = {**finding.meta, "recovery_tool": "ntfsundelete"}


def _apply_risk(finding: Finding) -> None:
    """Эрсдэлийн үнэлгээ хийж, severity + шалтгааныг meta-д хадгална."""
    risk = metadata.assess_risk(
        finding_type=finding.finding_type,
        file_name=finding.file_name,
        original_path=finding.original_path,
        recovered=finding.recovered,
    )
    finding.severity = risk.severity
    finding.meta = {
        **(finding.meta or {}),
        "risk_score": risk.score,
        "risk_reasons": risk.reasons,
        "risk_level": risk.severity.value,
    }


def _finalize_finding(db, finding: Finding) -> None:
    """Hash, MIME, severity нөхөж DB-д хадгална."""
    if finding.recovered and finding.recovered_path and os.path.exists(finding.recovered_path):
        try:
            h = hash_file(finding.recovered_path)
            finding.md5 = h.md5
            finding.sha256 = h.sha256
        except OSError:
            pass
        finding.mime_type = metadata.guess_mime(finding.recovered_path, finding.file_name)
    else:
        finding.mime_type = metadata.guess_mime("", finding.file_name)
    _apply_risk(finding)
    db.add(finding)
    db.commit()


def _run_named_recovery(db, job: ScanJob, source_path: str, fs_type: str) -> int:
    """ntfsundelete / extundelete — анхны файлын нэр, замтай сэргээлт."""
    dest = settings.recovered_dir / f"scan_{job.id}" / "named"
    named_files = named_recovery.scan_by_filesystem(source_path, fs_type, str(dest))
    count = 0
    seen: set[str] = set()
    for nf in named_files:
        key = nf.original_path.lower()
        if key in seen:
            continue
        seen.add(key)
        finding = Finding(
            scan_id=job.id,
            finding_type=FindingType.DELETED_FILE,
            file_name=nf.file_name,
            original_path=nf.original_path,
            inode=nf.inode,
            size_bytes=nf.size,
            recovered=bool(nf.recovered_path and os.path.exists(nf.recovered_path)),
            recovered_path=nf.recovered_path,
            source_tool=nf.source_tool,
            meta={
                **nf.meta,
                "delete_method": "permanent",
                "recycle_bypass": True,
            },
        )
        if finding.recovered and finding.recovered_path:
            try:
                h = hash_file(finding.recovered_path)
                finding.md5, finding.sha256 = h.md5, h.sha256
            except OSError:
                pass
            finding.mime_type = metadata.guess_mime(finding.recovered_path, finding.file_name)
        else:
            finding.mime_type = metadata.guess_mime("", finding.file_name)
        _apply_risk(finding)
        db.add(finding)
        count += 1
    db.commit()
    return count


def _run_carving(db, job: ScanJob, source_path: str, byte_offsets: list[int]) -> int:
    count = 0
    work_dir = settings.recovered_dir / f"scan_{job.id}" / "carved"
    work_dir.mkdir(parents=True, exist_ok=True)

    # Unallocated блокуудыг гаргаж, тэрхүү blob дээр carve хийнэ.
    blob = str(work_dir / "unallocated.blk")
    extracted = carving.extract_unallocated(source_path, blob, byte_offsets[0]) or source_path

    carved_files = carving.carve(extracted, str(work_dir / "out"))
    for cf in carved_files:
        h = hash_file(cf.path) if os.path.exists(cf.path) else None
        finding = Finding(
            scan_id=job.id,
            finding_type=FindingType.CARVED_FILE,
            file_name=cf.file_name,
            original_path="",
            size_bytes=cf.size,
            recovered=True,
            recovered_path=cf.path,
            mime_type=metadata.guess_mime(cf.path, cf.file_name),
            md5=h.md5 if h else "",
            sha256=h.sha256 if h else "",
            source_tool=cf.source_tool,
            meta={**cf.meta, "has_original_name": False, "recovery_method": "signature_carving"},
        )
        _apply_risk(finding)
        db.add(finding)
        count += 1
    db.commit()

    # Slack/unallocated string ул мөр (нэг нэгтгэсэн finding).
    if os.path.exists(blob):
        strings = carving.scan_slack_strings(blob)
        if strings:
            slack = Finding(
                scan_id=job.id,
                finding_type=FindingType.SLACK_SPACE,
                file_name="unallocated_strings.txt",
                size_bytes=os.path.getsize(blob),
                source_tool="blkls",
                meta={"sample_strings": strings[:50], "total": len(strings)},
            )
            _apply_risk(slack)
            db.add(slack)
            count += 1
            db.commit()
    return count


def _run_recycle(db, job: ScanJob, mount_point: str | None) -> int:
    count = 0
    artifacts = recycle.scan_recycle(mount_point)
    for art in artifacts:
        file_name = os.path.basename(art.original_path.replace("\\", "/")) or art.original_path
        finding = Finding(
            scan_id=job.id,
            finding_type=FindingType.RECYCLE_ARTIFACT,
            file_name=file_name,
            original_path=art.original_path,
            size_bytes=art.size,
            mtime=art.deleted_time,
            recovered=bool(art.content_path),
            recovered_path=art.content_path,
            source_tool=art.source,
            meta={**art.meta, "has_original_name": True, "recovery_method": "recycle_artifact"},
        )
        _apply_risk(finding)
        if art.content_path and os.path.exists(art.content_path):
            try:
                h = hash_file(art.content_path)
                finding.md5, finding.sha256 = h.md5, h.sha256
            except OSError:
                pass
        db.add(finding)
        count += 1
    db.commit()
    return count


def _build_timeline(db, job: ScanJob) -> None:
    findings = db.query(Finding).filter(Finding.scan_id == job.id).all()
    for f in findings:
        for event in metadata.build_timeline_events(f):
            event.finding_id = f.id
            db.add(event)
    db.commit()
