# Production deploy (Ubuntu)

Энэ заавар нь Removable Evidence Analyzer-ийг Ubuntu сервер дээр systemd + nginx
ашиглан production горимд байршуулах талаар.

## 1. Кодыг байршуулах

```bash
sudo mkdir -p /opt/rea
sudo cp -r backend frontend deploy scripts /opt/rea/
sudo mkdir -p /opt/rea/data/{images,recovered,exports}
```

## 2. Forensic орчин ба хамаарал

```bash
sudo /opt/rea/scripts/install_ubuntu.sh

# Backend venv
cd /opt/rea/backend
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# Frontend production build
cd /opt/rea/frontend
npm install
npm run build      # -> /opt/rea/frontend/dist
```

## 3. Backend service (systemd)

```bash
sudo cp /opt/rea/deploy/rea-backend.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now rea-backend
sudo systemctl status rea-backend
```

> `REA_ALLOW_MOCK=0` тул forensic хэрэгсэл заавал суусан байх ёстой. Backend нь
> device-д хандахын тулд root эрхээр ажиллана.

## 4. Nginx reverse proxy

```bash
sudo cp /opt/rea/deploy/nginx.conf /etc/nginx/sites-available/rea
sudo ln -s /etc/nginx/sites-available/rea /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx
```

Одоо <http://server-ip/> хаягаар UI нээгдэнэ.

## 5. Аюулгүй байдлын зөвлөмж (hardening)

- **Root эрх:** Backend нь `blockdev`, `mount`, `dd` ажиллуулахын тулд root шаардана.
  Сервэрийг зөвхөн дотоод (air-gapped) forensic сүлжээнд байрлуулна.
- **Authentication:** Production-д nginx түвшинд basic auth эсвэл VPN/firewall-аар
  хандалтыг хязгаарлана уу (энэ хувилбарт нэвтрэх эрхийн систем ороогүй).
- **HTTPS:** `certbot`-аар TLS сертификат тохируулна.
- **Бүрэн бүтэн байдал:** `data/` хавтсын backup-ийг тогтмол авч, дүрсний hash-ийг
  баталгаажуулна (`docs/FORENSIC_PROCEDURE.md`).
- **Read-only:** Боломжтой бол hardware write-blocker нэмж ашиглана.

## 6. Шинэчлэх

```bash
cd /opt/rea && sudo git pull   # эсвэл шинэ кодыг хуулна
sudo /opt/rea/backend/.venv/bin/pip install -r /opt/rea/backend/requirements.txt
cd /opt/rea/frontend && npm install && npm run build
sudo systemctl restart rea-backend
```

## 7. Тест

```bash
cd /opt/rea/backend
.venv/bin/python -m pytest -q
```
