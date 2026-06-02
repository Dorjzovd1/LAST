# Removable Evidence Analyzer (REA)

Ubuntu Linux дээр ажиллах **web суурьт forensic шинжилгээний систем**. USB flash, external
HDD/SSD, SD card зэрэг зөөврийн мэдээлэл тээгчийг серверт холбоход автоматаар таньж,
**read-only (зөвхөн унших)** горимоор тоон ул мөрийг илрүүлж, шинжилж, хооронд нь
уялдуулан timeline болон forensic тайлан гаргана.

> Энэхүү хувилбар нь системийн **бүрэн суурь** (device detection, write-blocker,
> imaging, REST/WebSocket API, React UI) болон эхний модуль болох
> **Deleted File Detection Module**-ийг бүрэн агуулна. User Activity болон
> Browser/Portable artifact модулиудыг дараагийн шатанд нэмнэ.

## Модулиуд

| Модуль | Төлөв | Тайлбар |
|--------|-------|---------|
| Deleted File Detection | Хэрэгжсэн | Устгагдсан файл, recycle artifact, unallocated/slack space, file carving |
| User Activity | Төлөвлөгдсөн | Shortcut, recent file, хэрэглэгчийн үйл ажиллагаа |
| Browser / Portable | Төлөвлөгдсөн | Browser, portable application ул мөр |

## Архитектур

```
Removable Device (/dev/sdX)
        │  (pyudev hot-plug detect)
        ▼
  Write-blocker  ──►  Imaging (dd/ewfacquire + SHA256)
        │
        ▼
  Deleted File Detection
   ├── The Sleuth Kit (fls / icat / tsk_recover)
   ├── File carving (photorec / foremost / scalpel)
   └── Recycle / Trash artifacts
        │
        ▼
  SQLite (findings / metadata / timeline / audit)
        │
        ▼
  FastAPI (REST + WebSocket)  ──►  React UI
```

## Технологи

- **Backend:** Python 3.11+, FastAPI, SQLAlchemy, pyudev
- **Forensic CLI:** The Sleuth Kit, photorec/testdisk, foremost, scalpel, ewf-tools
- **Frontend:** React + Vite + TypeScript

## Эхлэх

Суулгац ба ажиллуулах заавар: [docs/INSTALL.md](docs/INSTALL.md)
Production deploy: [docs/DEPLOY.md](docs/DEPLOY.md)
Forensic журам: [docs/FORENSIC_PROCEDURE.md](docs/FORENSIC_PROCEDURE.md)

```bash
# Ubuntu орчны бэлтгэл (forensic tools + Python + Node)
sudo ./scripts/install_ubuntu.sh

# Backend
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Frontend (өөр терминал)
cd frontend
npm install
npm run dev
```

## Анхааруулга

Энэ систем нь зөөврийн төхөөрөмжийг **зөвхөн унших** горимоор шинжилнэ. Гэвч
forensic журмын дагуу боломжтой бол тусгай hardware write-blocker ашиглахыг зөвлөж байна.
Системийн device-д хандах үйлдлүүд (mount, blockdev, imaging) нь root эрх шаардана.

## Лиценз

MIT — [LICENSE](LICENSE)
