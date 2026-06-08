"""Device API — илрүүлэх, бүртгэх, read-only хийх."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core import audit
from app.database import get_db
from app.models import Device, DeviceState, ScanJob, ScanStatus
from app.schemas import DeviceOut, DeviceRegister
from app.services import device as device_svc
from app.services import writeblock

router = APIRouter(prefix="/api/devices", tags=["devices"])


@router.get("/detect", summary="Холбогдсон зөөврийн төхөөрөмжүүдийг илрүүлэх")
def detect_devices() -> list[dict]:
    return [d.to_dict() for d in device_svc.list_removable_devices()]


@router.get("", response_model=list[DeviceOut], summary="Бүртгэгдсэн төхөөрөмжүүд")
def list_devices(db: Session = Depends(get_db)) -> list[Device]:
    return db.query(Device).order_by(Device.created_at.desc()).all()


@router.get("/{device_id}", response_model=DeviceOut)
def get_device(device_id: int, db: Session = Depends(get_db)) -> Device:
    device = db.get(Device, device_id)
    if device is None:
        raise HTTPException(404, "Device олдсонгүй")
    return device


@router.post("", response_model=DeviceOut, summary="Илэрсэн төхөөрөмжийг хэрэгт бүртгэх")
def register_device(payload: DeviceRegister, db: Session = Depends(get_db)) -> Device:
    detected = device_svc.get_device(payload.dev_path)
    if detected is None:
        raise HTTPException(404, f"{payload.dev_path} төхөөрөмж олдсонгүй")

    device = Device(
        case_id=payload.case_id,
        dev_path=detected.dev_path,
        name=detected.name,
        serial=detected.serial,
        bus=detected.bus,
        size_bytes=detected.size_bytes,
        fs_type=detected.fs_type,
        is_removable=detected.is_removable,
        details=detected.details,
        state=DeviceState.DETECTED,
    )
    db.add(device)
    db.commit()
    db.refresh(device)
    audit.record(db, action="device_registered", target=device.dev_path, case_id=payload.case_id)
    return device


@router.post("/{device_id}/read-only", response_model=DeviceOut, summary="Write-blocker идэвхжүүлэх")
def make_read_only(device_id: int, db: Session = Depends(get_db)) -> Device:
    device = db.get(Device, device_id)
    if device is None:
        raise HTTPException(404, "Device олдсонгүй")
    try:
        writeblock.set_read_only(device.dev_path)
    except writeblock.WriteBlockError as exc:
        raise HTTPException(400, str(exc)) from exc
    device.read_only = True
    device.state = DeviceState.READ_ONLY
    db.add(device)
    db.commit()
    db.refresh(device)
    audit.record(db, action="set_read_only", target=device.dev_path, case_id=device.case_id)
    return device


@router.delete("/{device_id}", status_code=204, summary="Бүртгэлээс төхөөрөмж устгах")
def delete_device(device_id: int, db: Session = Depends(get_db)) -> None:
    device = db.get(Device, device_id)
    if device is None:
        raise HTTPException(404, "Device олдсонгүй")

    active = (
        db.query(ScanJob)
        .filter(
            ScanJob.device_id == device_id,
            ScanJob.status.in_([ScanStatus.PENDING, ScanStatus.RUNNING]),
        )
        .first()
    )
    if active is not None:
        raise HTTPException(409, "Төхөөрөмжид ажиллаж байгаа scan байна. Эхлээд scan-ийг зогсооно уу.")

    dev_path = device.dev_path
    case_id = device.case_id
    scan_count = len(device.scans)
    db.delete(device)
    db.commit()
    audit.record(
        db,
        action="device_deleted",
        target=dev_path,
        case_id=case_id,
        detail={"scans_removed": scan_count},
    )
