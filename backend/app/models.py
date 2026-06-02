"""ORM моделиуд: Case, Device, ScanJob, Finding, TimelineEvent, AuditLog."""
from __future__ import annotations

import enum
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    BigInteger,
    DateTime,
    Enum as SAEnum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #
class DeviceState(str, enum.Enum):
    DETECTED = "detected"          # таниж мэдсэн, бэлтгэгдээгүй
    READ_ONLY = "read_only"        # write-blocker тохируулсан
    ANALYZED = "analyzed"          # шинжилгээ хийсэн
    REMOVED = "removed"            # салгасан


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class FindingType(str, enum.Enum):
    ACTIVE_FILE = "active_file"        # идэвхтэй (устгагдаагүй) файл — MAC цагтай
    DELETED_FILE = "deleted_file"      # TSK file-system метадата
    CARVED_FILE = "carved_file"        # signature carving
    RECYCLE_ARTIFACT = "recycle_artifact"
    SLACK_SPACE = "slack_space"


class Severity(str, enum.Enum):
    """Эрсдэлийн 3 түвшин."""

    HIGH = "high"      # Өндөр түвшин
    MEDIUM = "medium"  # Дунд түвшин
    NORMAL = "normal"  # Хэвийн


# --------------------------------------------------------------------------- #
# Models
# --------------------------------------------------------------------------- #
class Case(Base):
    """Forensic хэрэг."""

    __tablename__ = "cases"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_number: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(255))
    investigator: Mapped[str] = mapped_column(String(255), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    devices: Mapped[list["Device"]] = relationship(back_populates="case", cascade="all, delete-orphan")
    audit_logs: Mapped[list["AuditLog"]] = relationship(back_populates="case", cascade="all, delete-orphan")


class Device(Base):
    """Зөөврийн мэдээлэл тээгч төхөөрөмж."""

    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int | None] = mapped_column(ForeignKey("cases.id"), nullable=True)

    dev_path: Mapped[str] = mapped_column(String(255), index=True)   # /dev/sdb
    name: Mapped[str] = mapped_column(String(255), default="")        # vendor/model
    serial: Mapped[str] = mapped_column(String(255), default="")
    bus: Mapped[str] = mapped_column(String(32), default="")          # usb / ata / mmc
    size_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    fs_type: Mapped[str] = mapped_column(String(64), default="")
    is_removable: Mapped[bool] = mapped_column(default=True)
    read_only: Mapped[bool] = mapped_column(default=False)
    state: Mapped[DeviceState] = mapped_column(SAEnum(DeviceState), default=DeviceState.DETECTED)
    details: Mapped[dict] = mapped_column(JSON, default=dict)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    case: Mapped[Case | None] = relationship(back_populates="devices")
    scans: Mapped[list["ScanJob"]] = relationship(back_populates="device", cascade="all, delete-orphan")


class ScanJob(Base):
    """Файлын шинжилгээний ажил."""

    __tablename__ = "scan_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"))

    status: Mapped[ScanStatus] = mapped_column(SAEnum(ScanStatus), default=ScanStatus.PENDING)
    progress: Mapped[float] = mapped_column(Float, default=0.0)   # 0..100
    current_step: Mapped[str] = mapped_column(String(255), default="")
    options: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str] = mapped_column(Text, default="")

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    device: Mapped[Device] = relationship(back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    timeline_events: Mapped[list["TimelineEvent"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class Finding(Base):
    """Илэрсэн ул мөр (устгагдсан/carved файл, recycle artifact гэх мэт)."""

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scan_jobs.id"), index=True)

    finding_type: Mapped[FindingType] = mapped_column(SAEnum(FindingType))
    severity: Mapped[Severity] = mapped_column(SAEnum(Severity), default=Severity.NORMAL)

    file_name: Mapped[str] = mapped_column(String(512), default="")
    original_path: Mapped[str] = mapped_column(String(2048), default="")
    inode: Mapped[str] = mapped_column(String(64), default="")
    size_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    mime_type: Mapped[str] = mapped_column(String(128), default="")

    recovered: Mapped[bool] = mapped_column(default=False)
    recovered_path: Mapped[str] = mapped_column(String(1024), default="")
    md5: Mapped[str] = mapped_column(String(32), default="")
    sha256: Mapped[str] = mapped_column(String(64), default="")

    # MAC timestamps
    mtime: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    atime: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ctime: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    crtime: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    source_tool: Mapped[str] = mapped_column(String(64), default="")
    meta: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    scan: Mapped[ScanJob] = relationship(back_populates="findings")


class TimelineEvent(Base):
    """Timestamp дээр суурилсан timeline-ийн нэг үйл явдал."""

    __tablename__ = "timeline_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scan_jobs.id"), index=True)
    finding_id: Mapped[int | None] = mapped_column(ForeignKey("findings.id"), nullable=True)

    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    event_type: Mapped[str] = mapped_column(String(32))   # M / A / C / B
    description: Mapped[str] = mapped_column(Text, default="")

    scan: Mapped[ScanJob] = relationship(back_populates="timeline_events")


class AuditLog(Base):
    """Chain-of-custody бүртгэл — хэн, хэзээ, юу хийсэн."""

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int | None] = mapped_column(ForeignKey("cases.id"), nullable=True)

    action: Mapped[str] = mapped_column(String(128))
    actor: Mapped[str] = mapped_column(String(128), default="system")
    target: Mapped[str] = mapped_column(String(512), default="")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)

    case: Mapped[Case | None] = relationship(back_populates="audit_logs")
