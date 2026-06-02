"""Pydantic schema-ууд (API request/response)."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models import (
    DeviceState,
    FindingType,
    ScanStatus,
    Severity,
)


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ----------------------------- Case ---------------------------------------- #
class CaseCreate(BaseModel):
    case_number: str = Field(..., max_length=64)
    title: str = Field(..., max_length=255)
    investigator: str = ""
    description: str = ""


class CaseOut(ORMModel):
    id: int
    case_number: str
    title: str
    investigator: str
    description: str
    created_at: datetime


# ----------------------------- Device -------------------------------------- #
class DeviceOut(ORMModel):
    id: int
    case_id: int | None
    dev_path: str
    name: str
    serial: str
    bus: str
    size_bytes: int
    fs_type: str
    is_removable: bool
    read_only: bool
    state: DeviceState
    details: dict
    created_at: datetime


class DeviceRegister(BaseModel):
    """lsblk/udev-ээс илэрсэн төхөөрөмжийг хэрэгт бүртгэх."""

    dev_path: str
    case_id: int | None = None


# ----------------------------- Scan ---------------------------------------- #
class ScanOptions(BaseModel):
    recover_files: bool = True         # устгагдсан файлыг сэргээх
    run_carving: bool = False          # photorec — нэргүй, уdaан (default унтраалттай)
    run_recycle: bool = True           # recycle/trash artifact
    run_named_tools: bool = True       # ntfsundelete / extundelete
    max_recover_size_mb: int = 512     # сэргээх файлын дээд хэмжээ


class ScanCreate(BaseModel):
    device_id: int
    options: ScanOptions = ScanOptions()


class ScanOut(ORMModel):
    id: int
    device_id: int
    status: ScanStatus
    progress: float
    current_step: str
    options: dict
    error: str
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime


# ----------------------------- Finding ------------------------------------- #
class FindingOut(ORMModel):
    id: int
    scan_id: int
    finding_type: FindingType
    severity: Severity
    file_name: str
    original_path: str
    inode: str
    size_bytes: int
    mime_type: str
    recovered: bool
    recovered_path: str
    md5: str
    sha256: str
    mtime: datetime | None
    atime: datetime | None
    ctime: datetime | None
    crtime: datetime | None
    source_tool: str
    meta: dict
    created_at: datetime


class TimelineEventOut(ORMModel):
    id: int
    scan_id: int
    finding_id: int | None
    timestamp: datetime
    event_type: str
    description: str


class AuditLogOut(ORMModel):
    id: int
    case_id: int | None
    action: str
    actor: str
    target: str
    detail: dict
    timestamp: datetime
