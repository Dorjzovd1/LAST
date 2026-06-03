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
    TimelineEvent,
)
from app.services import active_files, carving, metadata, named_recovery, recovery_quality, recycle, tsk, writeblock
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

        # 1a) Flash/USB идэвхтэй файлууд — mount walk (бүх файл) + TSK -----------
        _progress(db, job, 10, "Flash дээрх бүх идэвхтэй файл (mount walk)")
        total_findings += _run_active_inventory(db, job, mount_point, source_path, byte_offsets)

        # 1b) Устгагдсан файлууд — TSK metadata (+ хязгаартай сэргээлт) ------------
        _progress(db, job, 28, "Устгагдсан файлууд (TSK metadata)")
        total_findings += _run_deleted_inventory(db, job, source_path, byte_offsets, options, device)

        # 2) FS-т тохирсон нэртэй сэргээлт (ntfsundelete — Shift+Delete NTFS) ---
        if options.get("run_named_tools", True) and device:
            fs = device.fs_type or ""
            part = named_recovery.resolve_partition_path(
                device.dev_path, fs, device.details or {}
            )
            _progress(db, job, 40, f"NTFS permanent delete сэргээлт ({fs or 'auto'})")
            total_findings += _run_named_recovery(db, job, part, fs, options)

        # 3) Carving (signature — нэргүй, зөвхөн run_carving=true үед) -------
        if options.get("run_carving", False):
            _progress(db, job, 55, "Signature carving (нэргүй — уdaан)")
            total_findings += _run_carving(db, job, source_path, byte_offsets)

        # 4) Recycle / Trash artifact ----------------------------------------
        if options.get("run_recycle", True):
            _progress(db, job, 75, "Recycle/Trash (анхны замтай)")
            total_findings += _run_recycle(db, job, mount_point)

        # 5) Timeline (бүх файлын MAC activity) --------------------------------
        _progress(db, job, 90, "Activity timeline (MAC — бүх файл)")
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

    # Read-only mount — flash/USB дээрх БҮХ идэвхтэй файл (Documents/*.pptx г.м.)
    mount_point: str | None = None
    if device:
        fs = (device.fs_type or writeblock.detect_fstype(source_path) or "").lower()
        mount_targets = [source_path]
        if device.dev_path and device.dev_path not in mount_targets:
            mount_targets.append(device.dev_path)
        for target in mount_targets:
            try:
                mount_point = writeblock.mount_read_only(target, fs_type=fs)
                logger.info("Flash mount OK: %s -> %s (fs=%s)", target, mount_point, fs or "auto")
                break
            except Exception as exc:  # noqa: BLE001
                logger.warning("Mount амжилтгүй (%s): %s", target, exc)
        if mount_point is None:
            logger.warning(
                "Flash идэвхтэй файл mount-оор уншигдахгүй — TSK fallback. "
                "sudo backend + ntfs-3g/exfat-utils шалгана уу."
            )

    return source_path, byte_offsets, mount_point


# --------------------------------------------------------------------------- #
# Finding builders
# --------------------------------------------------------------------------- #
def _finding_from_live_entry(scan_id: int, entry: active_files.LiveFileEntry) -> Finding:
    """Mount walk-аар илэрсэн идэвхтэй файл."""
    return Finding(
        scan_id=scan_id,
        finding_type=FindingType.ACTIVE_FILE,
        file_name=entry.file_name,
        original_path=entry.original_path,
        size_bytes=entry.size_bytes,
        mtime=entry.mtime,
        atime=entry.atime,
        ctime=entry.ctime,
        crtime=entry.crtime,
        source_tool=entry.source_tool,
        meta={
            **entry.meta,
            "has_original_name": True,
            "deleted": False,
            "module": "active_file_inventory",
            "content_path": entry.content_path,
            "on_device": True,
        },
    )


def _finding_from_entry(scan_id: int, entry: tsk.DeletedEntry) -> Finding:
    """Файлын бичлэг (идэвхтэй эсвэл устгагдсан) — зам, нэр, MAC цагтай.

    Идэвхтэй файл → ACTIVE_FILE, устгагдсан → DELETED_FILE. MAC timestamp
    (modified/accessed/changed/born) нь "хэзээ ямар үйлдэл хийсэн"-ийг илэрхийлнэ.
    """
    path = entry.name.replace("\\", "/")
    file_name = os.path.basename(path.rstrip("/")) or path.lstrip("/") or entry.name
    finding_type = FindingType.DELETED_FILE if entry.deleted else FindingType.ACTIVE_FILE
    finding = Finding(
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
    metadata.apply_mac_to_finding(
        finding,
        mtime=entry.mtime,
        atime=entry.atime,
        ctime=entry.ctime,
        crtime=entry.crtime,
        source=entry.meta.get("mac_source", "tsk-fls"),
    )
    return finding


def _maybe_recover(
    source_path,
    byte_offset,
    entry,
    finding: Finding,
    options: dict,
    device: Device | None = None,
    recover_state: dict | None = None,
) -> None:
    if not options.get("recover_files", True) or entry.file_type != "r":
        return
    max_count = int(options.get("max_recover_count", 100))
    if recover_state is not None and recover_state.get("count", 0) >= max_count:
        finding.meta = {**(finding.meta or {}), "skipped": "recover_limit"}
        return
    max_bytes = int(options.get("max_recover_size_mb", 512)) * 1024 * 1024
    if entry.size and entry.size > max_bytes:
        finding.meta = {**finding.meta, "skipped": "size_limit"}
        return
    dest = settings.recovered_dir / f"scan_{finding.scan_id}" / f"{entry.inode.replace('/', '_')}_{finding.file_name}"
    ok = tsk.recover_inode(source_path, entry.inode, str(dest), byte_offset)
    if ok and recovery_quality.apply_recovery_result(
        finding, str(dest), "icat", expected_size=entry.size or finding.size_bytes
    ):
        if recover_state is not None:
            recover_state["count"] = recover_state.get("count", 0) + 1
        return

    # Shift+Delete NTFS: icat амжилтгүй бол ntfsundelete fallback.
    fs = (device.fs_type or "").lower() if device else ""
    if fs in ("ntfs", "exfat") and entry.inode:
        part = source_path
        if device:
            part = named_recovery.resolve_partition_path(
                device.dev_path, fs, device.details or {}
            )
        if named_recovery.recover_ntfs_inode(part, entry.inode, str(dest), file_name=finding.file_name):
            if recovery_quality.apply_recovery_result(
                finding, str(dest), "ntfsundelete", expected_size=entry.size or finding.size_bytes
            ):
                if recover_state is not None:
                    recover_state["count"] = recover_state.get("count", 0) + 1


def _prepare_finding(finding: Finding, *, hash_content: bool = False) -> None:
    """MIME, severity тооцоолно (commit хийхгүй)."""
    if hash_content and finding.recovered and finding.recovered_path and os.path.exists(finding.recovered_path):
        try:
            h = hash_file(finding.recovered_path)
            finding.md5 = h.md5
            finding.sha256 = h.sha256
        except OSError:
            pass
        finding.mime_type = metadata.guess_mime(finding.recovered_path, finding.file_name)
    elif finding.finding_type == FindingType.ACTIVE_FILE:
        content = (finding.meta or {}).get("content_path") or ""
        mime_guess = (finding.meta or {}).get("mime_guess")
        if mime_guess:
            finding.mime_type = str(mime_guess)
        elif content and os.path.isfile(str(content)):
            finding.mime_type = metadata.guess_mime(str(content), finding.file_name, use_file_command=False)
        else:
            finding.mime_type = metadata.guess_mime_fast(finding.file_name)
    else:
        finding.mime_type = metadata.guess_mime("", finding.file_name)
    _apply_risk(finding)


def _flush_findings(db, batch: list[Finding]) -> int:
    if not batch:
        return 0
    for f in batch:
        db.add(f)
    db.commit()
    n = len(batch)
    batch.clear()
    return n


def _run_active_inventory(
    db,
    job: ScanJob,
    mount_point: str | None,
    source_path: str,
    byte_offsets: list[int],
) -> int:
    """Төхөөрөмж дээрх бүх идэвхтэй файлыг catalog-д бүртгэнэ."""
    count = 0
    batch: list[Finding] = []
    seen: set[str] = set()
    batch_size = 1000
    mount_count = 0

    if mount_point:
        live_entries = active_files.scan_mount(mount_point)
        mount_count = len(live_entries)
        total_live = max(mount_count, 1)
        for idx, entry in enumerate(live_entries):
            key = entry.original_path.lower()
            if key in seen:
                continue
            seen.add(key)
            f = _finding_from_live_entry(job.id, entry)
            _prepare_finding(f, hash_content=False)
            batch.append(f)
            if len(batch) >= batch_size:
                count += _flush_findings(db, batch)
            if mount_count >= 500 and (idx + 1) % 2000 == 0:
                pct = 10 + min(17.0, (idx + 1) / total_live * 17.0)
                _progress(db, job, pct, f"Идэвхтэй файл {idx + 1}/{mount_count}")

    if mount_count == 0:
        for off in byte_offsets:
            for entry in tsk.list_active_files(source_path, off):
                key = (entry.name or "").replace("\\", "/").lower()
                if not key or key in seen:
                    continue
                seen.add(key)
                f = _finding_from_entry(job.id, entry)
                f.finding_type = FindingType.ACTIVE_FILE
                _prepare_finding(f, hash_content=False)
                batch.append(f)
                if len(batch) >= batch_size:
                    count += _flush_findings(db, batch)

    count += _flush_findings(db, batch)
    logger.info("[scan %s] идэвхтэй файл: %d (mount=%d)", job.id, count, mount_count)
    return count


def _run_deleted_inventory(
    db,
    job: ScanJob,
    source_path: str,
    byte_offsets: list[int],
    options: dict,
    device: Device | None,
) -> int:
    """Устгагдсан файлуудыг batch-ээр бүртгэнэ; сэргээлт тоогоор хязгаарлана."""
    count = 0
    batch: list[Finding] = []
    batch_size = 1000
    recover_state = {"count": 0}
    processed = 0

    for off in byte_offsets:
        entries = tsk.list_deleted(source_path, off)
        for entry in entries:
            path = entry.name.replace("\\", "/")
            file_name = os.path.basename(path.rstrip("/")) or entry.name
            if recovery_quality.is_junk_recovery_name(file_name, path):
                continue
            f = _finding_from_entry(job.id, entry)
            f.finding_type = FindingType.DELETED_FILE
            entry.deleted = True
            _maybe_recover(source_path, off, entry, f, options, device, recover_state)
            _prepare_finding(f, hash_content=f.recovered)
            batch.append(f)
            processed += 1
            if len(batch) >= batch_size:
                count += _flush_findings(db, batch)
            if processed % 2000 == 0:
                _progress(db, job, 28 + min(10.0, processed / 20000 * 10), f"Устгагдсан {processed}…")

    count += _flush_findings(db, batch)
    logger.info(
        "[scan %s] устгагдсан файл: %d (сэргээсэн %d)",
        job.id,
        count,
        recover_state.get("count", 0),
    )
    return count


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
        "risk_standard": risk.standard,
        "risk_overall_impact": risk.overall_impact,
        "risk_confidentiality": risk.confidentiality,
        "risk_integrity": risk.integrity,
        "risk_availability": risk.availability,
        "risk_information_types": risk.information_types,
    }


def _finalize_finding(db, finding: Finding) -> None:
    """Hash, MIME, severity нөхөж DB-д хадгална."""
    _prepare_finding(finding, hash_content=True)
    db.add(finding)
    db.commit()


def _run_named_recovery(db, job: ScanJob, source_path: str, fs_type: str, options: dict) -> int:
    """ntfsundelete / extundelete — анхны файлын нэр, замтай сэргээлт."""
    dest = settings.recovered_dir / f"scan_{job.id}" / "named"
    max_bytes = int(options.get("max_recover_size_mb", 512)) * 1024 * 1024
    named_files = named_recovery.scan_by_filesystem(
        source_path,
        fs_type,
        str(dest),
        recover=bool(options.get("recover_files", True)),
        max_recover=int(options.get("max_recover_count", 100)),
        max_bytes=max_bytes,
    )
    existing = db.query(Finding).filter(Finding.scan_id == job.id).all()
    by_norm_path = {
        recovery_quality.normalize_recovery_path(f.original_path or f.file_name): f for f in existing
    }
    by_inode = {(f.inode or "").split("-")[0]: f for f in existing if f.inode}

    count = 0
    seen: set[str] = set()
    for nf in named_files:
        if recovery_quality.is_junk_recovery_name(nf.file_name, nf.original_path):
            continue
        norm = recovery_quality.normalize_recovery_path(nf.original_path)
        if norm in seen:
            continue
        seen.add(norm)

        mft = nf.inode or ""
        prior = by_norm_path.get(norm) or by_inode.get(mft)

        if prior:
            metadata.apply_mac_to_finding(
                prior,
                mtime=nf.mtime,
                atime=nf.atime,
                ctime=nf.ctime or nf.deleted_time,
                crtime=nf.crtime,
                source="ntfsundelete",
            )
            if nf.recovered_path and not prior.recovered:
                recovery_quality.apply_recovery_result(
                    prior, nf.recovered_path, nf.source_tool, expected_size=nf.size
                )
                _apply_risk(prior)
                db.add(prior)
            continue

        if not nf.recovered_path:
            continue

        finding = Finding(
            scan_id=job.id,
            finding_type=FindingType.DELETED_FILE,
            file_name=nf.file_name,
            original_path=nf.original_path,
            inode=nf.inode,
            size_bytes=nf.size,
            recovered=True,
            recovered_path=nf.recovered_path,
            source_tool=nf.source_tool,
            meta={
                **nf.meta,
                "delete_method": "permanent",
                "recycle_bypass": True,
            },
        )
        ok, reason = recovery_quality.validate_recovered_file(
            nf.recovered_path, nf.file_name, expected_size=nf.size
        )
        if not ok:
            continue
        finding.meta = {**finding.meta, "recovery_valid": True, "recovery_note": reason}
        try:
            h = hash_file(finding.recovered_path)
            finding.md5, finding.sha256 = h.md5, h.sha256
        except OSError:
            pass
        finding.mime_type = metadata.guess_mime(finding.recovered_path, finding.file_name)
        finding.size_bytes = os.path.getsize(finding.recovered_path)
        metadata.apply_mac_to_finding(
            finding,
            mtime=nf.mtime,
            atime=nf.atime,
            ctime=nf.ctime or nf.deleted_time,
            crtime=nf.crtime,
            source="ntfsundelete",
        )
        if nf.inode and not all([finding.mtime, finding.atime, finding.ctime, finding.crtime]):
            if finding.recovered:
                ts = tsk.get_inode_timestamps(source_path, nf.inode, 0)
                metadata.apply_mac_to_finding(
                    finding,
                    mtime=ts.get("mtime"),
                    atime=ts.get("atime"),
                    ctime=ts.get("ctime"),
                    crtime=ts.get("crtime"),
                    source="istat",
                )
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
        ctime = art.deleted_time
        atime = None
        crtime = None
        mtime = art.deleted_time
        if art.content_path and os.path.exists(art.content_path):
            try:
                st = os.stat(art.content_path)
                atime = datetime.fromtimestamp(st.st_atime, tz=timezone.utc)
                mtime = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc)
                crtime = datetime.fromtimestamp(getattr(st, "st_birthtime", st.st_ctime), tz=timezone.utc)
            except OSError:
                pass
        finding = Finding(
            scan_id=job.id,
            finding_type=FindingType.RECYCLE_ARTIFACT,
            file_name=file_name,
            original_path=art.original_path,
            size_bytes=art.size,
            mtime=mtime,
            atime=atime,
            ctime=ctime or mtime,
            crtime=crtime,
            recovered=bool(art.content_path),
            recovered_path=art.content_path,
            source_tool=art.source,
            meta={
                **art.meta,
                "has_original_name": True,
                "recovery_method": "recycle_artifact",
                "deleted_at": art.deleted_time.isoformat() if art.deleted_time else None,
            },
        )
        metadata.apply_mac_to_finding(
            finding,
            mtime=mtime,
            atime=atime,
            ctime=ctime or mtime,
            crtime=crtime,
            source="recycle_artifact",
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
    pending: list[TimelineEvent] = []
    for f in findings:
        for event in metadata.build_timeline_events(f):
            event.finding_id = f.id
            pending.append(event)
            if len(pending) >= 3000:
                db.add_all(pending)
                db.commit()
                pending.clear()
    if pending:
        db.add_all(pending)
        db.commit()
