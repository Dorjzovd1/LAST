"""End-to-end API тест (mock горим)."""
from __future__ import annotations

import time


def _wait_scan(client, scan_id: int, timeout: float = 15.0) -> dict:
    """POST /api/scans нь scan-ийг background thread-д ажиллуулдаг тул дуустал хүлээнэ."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        s = client.get(f"/api/scans/{scan_id}").json()
        if s["status"] in ("completed", "failed", "cancelled"):
            return s
        time.sleep(0.2)
    raise AssertionError("Scan заасан хугацаанд дуусаагүй")


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert "tools" in body


def test_full_pipeline(client):
    # 1. Хэрэг үүсгэх
    case = client.post(
        "/api/cases",
        json={"case_number": "TST-1", "title": "Unit test", "investigator": "QA"},
    ).json()
    assert case["id"]

    # 2. Төхөөрөмж илрүүлж бүртгэх
    detected = client.get("/api/devices/detect").json()
    assert len(detected) >= 1
    dev = client.post(
        "/api/devices",
        json={"dev_path": detected[0]["dev_path"], "case_id": case["id"]},
    ).json()
    assert dev["id"]

    # 3. Read-only
    ro = client.post(f"/api/devices/{dev['id']}/read-only").json()
    assert ro["read_only"] is True

    # 4. Scan (background thread-д ажиллана — дуустал хүлээнэ)
    scan = client.post(
        "/api/scans",
        json={"device_id": dev["id"]},
    ).json()
    s = _wait_scan(client, scan["id"])
    assert s["status"] == "completed"

    # 5. Findings — бүх файл (идэвхтэй + устгагдсан) жагсаагдсан байх ёстой
    findings = client.get("/api/findings", params={"scan_id": scan["id"]}).json()
    assert len(findings["items"]) > 0
    types = {f["finding_type"] for f in findings["items"]}
    assert "active_file" in types
    assert "deleted_file" in types

    # 6. Шүүлтүүр
    active_only = client.get(
        "/api/findings", params={"scan_id": scan["id"], "finding_type": "active_file"}
    ).json()
    assert all(f["finding_type"] == "active_file" for f in active_only["items"])

    # MAC цаг (хэзээ ямар үйлдэл хийсэн) бүртгэгдсэн байх ёстой
    assert any(f["mtime"] for f in findings["items"])

    # 7. Timeline
    timeline = client.get(f"/api/scans/{scan['id']}/timeline").json()
    assert len(timeline) > 0

    summary = client.get(f"/api/scans/{scan['id']}/summary").json()
    assert summary["total_files"] == findings["total"]
    assert summary["active_files"] >= 1
    assert summary["timeline_events"] >= 1

    # 8. Тайлан (HTML / JSON / PDF)
    html = client.get(f"/api/reports/scan/{scan['id']}/html")
    assert html.status_code == 200
    assert "Forensic" in html.text
    assert "Хэргийн мэдээлэл" not in html.text
    rep = client.get(f"/api/reports/scan/{scan['id']}/json").json()
    assert rep["summary"]["total_findings"] == findings["total"]
    assert "case" not in rep
    pdf = client.get(f"/api/reports/scan/{scan['id']}/pdf")
    assert pdf.status_code == 200
    assert pdf.headers["content-type"] == "application/pdf"
    assert pdf.content[:5] == b"%PDF-"
    assert len(pdf.content) > 1000

    # 8b. Файлын албан ёсны эрсдэлийн тайлан (narrative)
    risk = client.get(f"/api/findings/{findings['items'][0]['id']}/risk-report").json()
    assert risk["executive_summary"]
    assert risk.get("examiner_opinion")
    assert risk.get("recommendations_narrative")

    file_tl = client.get(f"/api/scans/{scan['id']}/timeline/files").json()
    assert len(file_tl) >= 1
    detail = client.get(f"/api/findings/{findings['items'][0]['id']}/file-timeline").json()
    assert detail["events"]
    assert detail["narrative"]

    # 9. Audit (chain of custody)
    audit = client.get(f"/api/cases/{case['id']}/audit").json()
    actions = {a["action"] for a in audit}
    assert "case_created" in actions
    assert "scan_started" in actions
    assert "scan_completed" in actions


def test_stats_overview(client):
    r = client.get("/api/stats/overview")
    assert r.status_code == 200
    body = r.json()
    for key in ("cases", "devices", "scans", "findings_total", "suspicious_pct", "normal_pct", "by_severity"):
        assert key in body


def test_recover_download(client):
    case = client.post("/api/cases", json={"case_number": "TST-2", "title": "dl"}).json()
    detected = client.get("/api/devices/detect").json()
    dev = client.post("/api/devices", json={"dev_path": detected[0]["dev_path"], "case_id": case["id"]}).json()
    scan = client.post("/api/scans", json={"device_id": dev["id"]}).json()
    _wait_scan(client, scan["id"])

    findings = client.get("/api/findings", params={"scan_id": scan["id"], "recovered": True}).json()
    assert findings["items"], "сэргээсэн файл байх ёстой"
    fid = findings["items"][0]["id"]
    dl = client.get(f"/api/findings/{fid}/download")
    assert dl.status_code == 200
    assert len(dl.content) > 0


def test_delete_device(client):
    detected = client.get("/api/devices/detect").json()
    dev = client.post("/api/devices", json={"dev_path": detected[0]["dev_path"], "case_id": None}).json()
    assert client.delete(f"/api/devices/{dev['id']}").status_code == 204
    assert client.get(f"/api/devices/{dev['id']}").status_code == 404
    assert dev["id"] not in [d["id"] for d in client.get("/api/devices").json()]
