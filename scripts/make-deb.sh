#!/usr/bin/env bash
# Ne yapar: cargo-deb ile HekaDrop için .deb paketi üretir ve proje köküne
# HekaDrop-<version>.deb adıyla kopyalar.
#
# Kullanım:
#   ./scripts/make-deb.sh

set -euo pipefail

# Proje köküne geç
cd "$(dirname "$0")/.."

# cargo-deb yüklü mü?
if ! cargo deb --version >/dev/null 2>&1; then
  echo "==> cargo-deb bulunamadı — kuruluyor"
  cargo install cargo-deb
fi

# Versiyonu Cargo.toml'dan çek (ilk 'version =' satırı — [package] başlığı altındaki)
VERSION="$(awk -F '"' '/^version[[:space:]]*=/ { print $2; exit }' Cargo.toml)"
if [[ -z "$VERSION" ]]; then
  echo "HATA: Cargo.toml'dan versiyon alınamadı." >&2
  exit 1
fi

echo "==> cargo deb (HekaDrop v${VERSION})"
cargo deb

# cargo-deb çıktı dosyası: target/debian/hekadrop_<version>_amd64.deb
# Mimari host'a göre değişebilir (aarch64, arm64, vb.) — o yüzden glob ile bul.
DEB_SRC="$(ls -t target/debian/hekadrop_"${VERSION}"_*.deb 2>/dev/null | head -n1 || true)"
if [[ -z "$DEB_SRC" || ! -f "$DEB_SRC" ]]; then
  echo "HATA: cargo-deb çıktısı bulunamadı (target/debian/hekadrop_${VERSION}_*.deb)." >&2
  exit 1
fi

DEB_DST="HekaDrop-${VERSION}.deb"
cp -f "$DEB_SRC" "$DEB_DST"

echo ""
echo "✓ .deb paketi hazır:"
echo "   Kaynak : $DEB_SRC"
echo "   Kopya  : $DEB_DST"
echo ""
echo "Kurmak için:"
echo "   sudo apt install ./${DEB_DST}"
echo "   # veya:"
echo "   sudo dpkg -i ${DEB_DST} && sudo apt -f install"
