#!/usr/bin/env bash
#
# Removable Evidence Analyzer - Ubuntu environment bootstrap
# Forensic CLI tools + Python 3.11 + Node.js suuiglana.
#
# Ashiglax: sudo ./scripts/install_ubuntu.sh
#
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "[!] Energ skript root erh shaardana. 'sudo ./scripts/install_ubuntu.sh' gej ajilluulna uu." >&2
  exit 1
fi

echo "==> APT package list shinechilj baina..."
apt-get update -y

echo "==> Forensic CLI heregsluudiig suuiglaj baina..."
# sleuthkit  : mmls, fls, icat, blkls, tsk_recover  (ҮНДСЭН — устгагдсан файлын НЭР)
# testdisk   : photorec  (нэмэлт carving — нэргүй, зөвхөн run_carving=true үед)
# foremost / scalpel : file carving
# ewf-tools  : ewfacquire (E01 image)
# libewf-dev : EWF support
# udev/util-linux : lsblk, blockdev
apt-get install -y \
  sleuthkit \
  testdisk \
  foremost \
  scalpel \
  ewf-tools \
  libewf-dev \
  util-linux \
  udev \
  coreutils \
  file \
  dosfstools \
  ntfs-3g \
  ntfsprogs \
  extundelete \
  fonts-dejavu-core

echo "==> Python 3.11 + venv suuiglaj baina..."
apt-get install -y python3 python3-venv python3-dev python3-pip build-essential libudev-dev

echo "==> Node.js (LTS) suuiglaj baina..."
if ! command -v node >/dev/null 2>&1; then
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
  apt-get install -y nodejs
fi

echo ""
echo "==> Suuiglagdsan heregsluudiig shalgaj baina:"
for bin in mmls fls icat blkls tsk_recover ntfsundelete extundelete foremost scalpel ewfacquire lsblk blockdev python3 node npm; do
  if command -v "$bin" >/dev/null 2>&1; then
    printf "  [OK]   %-12s -> %s\n" "$bin" "$(command -v "$bin")"
  else
    printf "  [MISS] %-12s (oldsongui)\n" "$bin"
  fi
done

echo ""
echo "==> Buten. Daraagiin alxam:"
echo "    cd backend && python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt"
echo "    cd frontend && npm install"
