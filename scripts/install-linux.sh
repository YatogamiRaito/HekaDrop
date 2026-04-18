#!/usr/bin/env bash
# Ne yapar: HekaDrop binary'sini, .desktop dosyasını ve ikon'ları Linux sistemine
# kurar. Kullanıcı-başına (~/.local) veya sistem-geneli (/usr/local) modları vardır.
#
# Kullanım:
#   ./scripts/install-linux.sh            # varsayılan: --user
#   ./scripts/install-linux.sh --user
#   sudo ./scripts/install-linux.sh --system

set -euo pipefail

# Proje köküne geç
cd "$(dirname "$0")/.."

# Varsayılan mod
MODE="user"

# Argüman ayrıştırma
if [[ $# -gt 0 ]]; then
  case "$1" in
    --user)
      MODE="user"
      ;;
    --system)
      MODE="system"
      ;;
    -h|--help)
      echo "Kullanım: $0 [--user|--system]"
      echo "  --user    Kullanıcı-başına kur (~/.local, varsayılan)"
      echo "  --system  Sistem-geneli kur (/usr/local, sudo gerektirir)"
      exit 0
      ;;
    *)
      echo "HATA: Bilinmeyen argüman: $1" >&2
      echo "Kullanım: $0 [--user|--system]" >&2
      exit 2
      ;;
  esac
fi

# Kaynak binary yolu — CARGO_TARGET_DIR override'ına izin ver
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-target}"
SRC_BIN="${CARGO_TARGET_DIR}/release/hekadrop"
SRC_DESKTOP="resources/hekadrop.desktop"
SRC_ICON="resources/icon.png"

# Ön-kontroller: gerekli dosyalar mevcut mu?
if [[ ! -f "$SRC_BIN" ]]; then
  echo "HATA: Release binary bulunamadı: $SRC_BIN" >&2
  echo "       Önce şunu çalıştır: cargo build --release" >&2
  exit 1
fi

if [[ ! -f "$SRC_DESKTOP" ]]; then
  echo "HATA: .desktop dosyası bulunamadı: $SRC_DESKTOP" >&2
  exit 1
fi

if [[ ! -f "$SRC_ICON" ]]; then
  echo "HATA: Icon dosyası bulunamadı: $SRC_ICON" >&2
  exit 1
fi

# Hedef yolları moda göre ayarla
if [[ "$MODE" == "user" ]]; then
  BIN_DIR="${HOME}/.local/bin"
  APP_DIR="${HOME}/.local/share/applications"
  ICON_BASE="${HOME}/.local/share/icons/hicolor"
  SUDO=""
else
  BIN_DIR="/usr/local/bin"
  APP_DIR="/usr/local/share/applications"
  ICON_BASE="/usr/local/share/icons/hicolor"
  # System modda root olmalıyız; sudo yoksa erişim zaten başarısız olur
  if [[ $EUID -ne 0 ]]; then
    echo "HATA: --system kurulumu root yetkisi gerektirir." >&2
    echo "       Şunu dene: sudo $0 --system" >&2
    exit 1
  fi
  SUDO=""
fi

echo "==> HekaDrop Linux kurulumu başlıyor (mod: ${MODE})"

# Dizinleri oluştur
$SUDO mkdir -p "$BIN_DIR" "$APP_DIR" "$ICON_BASE"

# Binary'i kur
echo "==> Binary kopyalanıyor → ${BIN_DIR}/hekadrop"
$SUDO install -m 0755 "$SRC_BIN" "${BIN_DIR}/hekadrop"

# .desktop'u kur
echo "==> .desktop kopyalanıyor → ${APP_DIR}/hekadrop.desktop"
$SUDO install -m 0644 "$SRC_DESKTOP" "${APP_DIR}/hekadrop.desktop"

# İkon'u kur — ImageMagick varsa tüm boyutlara üret
if command -v convert >/dev/null 2>&1; then
  echo "==> ImageMagick algılandı — hicolor boyutları üretiliyor"
  for SIZE in 16 24 32 48 64 128 256 512; do
    ICON_DIR="${ICON_BASE}/${SIZE}x${SIZE}/apps"
    $SUDO mkdir -p "$ICON_DIR"
    $SUDO convert "$SRC_ICON" -resize "${SIZE}x${SIZE}" \
      "${ICON_DIR}/hekadrop.png"
    echo "   - ${SIZE}x${SIZE}"
  done
else
  echo "UYARI: ImageMagick ('convert' komutu) bulunamadı."
  echo "       Tek boyut (512x512) kopyalanıyor — GTK/KDE runtime'da downscale yapacak."
  echo "       Tüm boyutları üretmek için: sudo apt install imagemagick  (veya dnf / pacman)"
  ICON_DIR="${ICON_BASE}/512x512/apps"
  $SUDO mkdir -p "$ICON_DIR"
  $SUDO install -m 0644 "$SRC_ICON" "${ICON_DIR}/hekadrop.png"
fi

# Cache'leri tazele (hata verirse sessizce geç — kritik değil)
if command -v update-desktop-database >/dev/null 2>&1; then
  echo "==> update-desktop-database çağrılıyor"
  $SUDO update-desktop-database "$APP_DIR" >/dev/null 2>&1 || true
fi

if command -v gtk-update-icon-cache >/dev/null 2>&1; then
  echo "==> gtk-update-icon-cache çağrılıyor"
  $SUDO gtk-update-icon-cache -f -t "$ICON_BASE" >/dev/null 2>&1 || true
fi

# Özet
echo ""
echo "✓ HekaDrop başarıyla kuruldu (mod: ${MODE})"
echo ""
echo "Kurulum yerleri:"
echo "  Binary   : ${BIN_DIR}/hekadrop"
echo "  Desktop  : ${APP_DIR}/hekadrop.desktop"
echo "  Icons    : ${ICON_BASE}/<size>/apps/hekadrop.png"
echo ""

# PATH kontrolü (user modda)
if [[ "$MODE" == "user" ]]; then
  case ":${PATH}:" in
    *":${BIN_DIR}:"*)
      ;;
    *)
      echo "UYARI: ${BIN_DIR} PATH'inde değil."
      echo "       ~/.bashrc veya ~/.zshrc dosyana şunu ekle:"
      echo "         export PATH=\"\$HOME/.local/bin:\$PATH\""
      echo ""
      ;;
  esac
fi

# Güvenlik duvarı hatırlatması
echo "Güvenlik duvarı (UFW) kullanıyorsan, Quick Share için şu portları aç:"
echo "  sudo ufw allow 47893/tcp"
echo "  sudo ufw allow 5353/udp"
echo ""
echo "Otomatik başlatma için HekaDrop arayüzünden \"Başlangıçta aç\" seçeneğini işaretle."
