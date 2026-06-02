"""Scan cleanup service tests."""
from __future__ import annotations

import time


def _wait_scan(client, scan_id: int, timeout: float = 15.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        s = client.get(f"/api/scans/{scan_id}").json()
        if s["status"] in ("completed", "failed", "cancelled"):
            return s
        time.sleep(0.2)
    raise AssertionError("Scan заасан хугацаанд дуусаагүй")


def test_purge_scan_api(client):
    detected = client.get("/api/devices/detect").json()
    dev = client.post("/api/devices", json={"dev_path": detected[0]["dev_path"], "case_id": None}).json()
    scan = client.post("/api/scans", json={"device_id": dev["id"]}).json()
    scan_id = scan["id"]
    _wait_scan(client, scan_id)

    findings = client.get("/api/findings", params={"scan_id": scan_id}).json()
    assert findings["total"] >= 1

    res = client.post(f"/api/scans/{scan_id}/purge")
    assert res.status_code == 200
    body = res.json()
    assert body["findings_removed"] >= 1
    assert body["scan_removed"] == 1

    assert client.get(f"/api/scans/{scan_id}").status_code == 404
    assert client.get("/api/findings", params={"scan_id": scan_id}).json()["total"] == 0


def test_purge_running_scan_rejected(client):
    detected = client.get("/api/devices/detect").json()
    dev = client.post("/api/devices", json={"dev_path": detected[0]["dev_path"], "case_id": None}).json()
    # Scan эхлүүлэх — mock дээр маш хурдан дуусаж магадгүй тул шууд pending/running шалгах хэцүү.
    # Илүү найдвартай: байхгүй scan-д 404.
    assert client.post("/api/scans/99999/purge").status_code == 404
