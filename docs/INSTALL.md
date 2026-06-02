# Суулгац ба ажиллуулах заавар

## Шаардлага

- Ubuntu 22.04+ (Linux), root/sudo эрх (device-д хандах)
- Python 3.11+
- Node.js 20+

## 1. Forensic орчны бэлтгэл

Доорх скрипт нь шаардлагатай бүх forensic CLI хэрэгслүүд (The Sleuth Kit, photorec,
foremost, scalpel, ewf-tools) болон Python, Node-ийг суулгана.

```bash
sudo ./scripts/install_ubuntu.sh
```

Суулгасан хэрэгслүүд:

| Хэрэгсэл | Команд | Зориулалт |
|----------|--------|-----------|
| sleuthkit | `mmls`, `fls`, `icat`, `blkls`, `tsk_recover` | Файлын системийн шинжилгээ, устгагдсан файл сэргээх |
| testdisk | `photorec` | File carving (signature-based) |
| foremost | `foremost` | File carving |
| scalpel | `scalpel` | File carving |
| ewf-tools | `ewfacquire`, `ewfverify` | E01 (EnCase) форматтай дүрс |
| util-linux | `lsblk`, `blockdev` | Төхөөрөмж жагсаах, read-only хийх |

## 2. Backend ажиллуулах

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# .env тохиргоо (заавал биш, default утгууд ажиллана)
cp .env.example .env   # шаардлагатай бол засна

# Хөгжүүлэлтийн серверийг асаах
# Анхаар: blockdev/mount зэрэг device үйлдэл root эрх шаардана!
sudo $(which uvicorn) app.main:app --host 0.0.0.0 --port 8000
```

`curl http://localhost:8000/api/health` хариунд `"running_as_root": true` байх ёстой.
Хэрэв `false` бол дээрх командыг **sudo**-оор ажиллуулна уу.

API баримтжуулалт: <http://localhost:8000/docs>

## 3. Frontend ажиллуулах

```bash
cd frontend
npm install
npm run dev
```

UI: <http://localhost:5173> (Vite default). Frontend нь `/api` хүсэлтийг
backend (`localhost:8000`) руу proxy хийнэ — `vite.config.ts`-д тохируулсан.

## 4. Device-д хандах эрх

`pyudev`, `blockdev`, `mount`, `dd` зэрэг үйлдлүүд root эрх шаардана. Хөгжүүлэлтийн
үед backend-ийг `sudo` дор ажиллуулах эсвэл production-д systemd service-ээр
(root) ажиллуулна (`docs/DEPLOY.md`).

## 5. Forensic tool-гүй орчинд (Windows/Mac dev)

Backend нь forensic CLI олдохгүй бол **demo/mock горим**-д шилжиж, sample
өгөгдлөөр API болон UI урсгалыг бүрэн харуулна. Ийм орчинд бодит device detection,
imaging хийгдэхгүй (`REA_ALLOW_MOCK=1` орчны хувьсагчаар удирдана).
