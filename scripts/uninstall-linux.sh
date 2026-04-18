#!/usr/bin/env bash
# Ne yapar: HekaDrop'u Linux sisteminden kaldırır (binary, .desktop, icon'lar,
# systemd user service). Config/log dizinleri kasıtlı olarak dokunulmaz —
# kullanıcı isterse manuel silebilir.
#
# Kullanım:
#   ./scripts/uninstall-linux.sh            # varsayılan: --user
#   ./scripts/uninstall-linux.sh --user
#   sudo ./scripts/uninstall-linux.sh --system

set -euo pipefail

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
      exit 0
      ;;
    *)
      echo "HATA: Bilinmeyen argüman: $1" >&2
      echo "Kullanım: $0 [--user|--system]" >&2
      exit 2
      ;;
  esac
fi

# Hedef yolları moda göre ayarla
if [[ "$MODE" == "user" ]]; then
  BIN_PATH="${HOME}/.local/bin/hekadrop"
  DESKTOP_PATH="${HOME}/.local/share/applications/hekadrop.desktop"
  ICON_BASE="${HOME}/.local/share/icons/hicolor"
  APP_DIR="${HOME}/.local/share/applications"
else
  BIN_PATH="/usr/local/bin/hekadrop"
  DESKTOP_PATH="/usr/local/share/applications/hekadrop.desktop"
  ICON_BASE="/usr/local/share/icons/hicolor"
  APP_DIR="/usr/local/share/applications"
  if [[ $EUID -ne 0 ]]; then
    echo "HATA: --system kaldırma işlemi root yetkisi gerektirir." >&2
    echo "       Şunu dene: sudo $0 --system" >&2
    exit 1
  fi
fi

echo "==> HekaDrop Linux kaldırılıyor (mod: ${MODE})"

# 1) systemd user service varsa durdur & sil (yalnız user modda anlamlı)
if [[ "$MODE" == "user" ]]; then
  SERVICE_PATH="${HOME}/.config/systemd/user/hekadrop.service"
  if [[ -f "$SERVICE_PATH" ]]; then
    echo "==> systemd user service kaldırılıyor"
    systemctl --user disable --now hekadrop.service >/dev/null 2>&1 || true
    rm -f "$SERVICE_PATH"
    systemctl --user daemon-reload >/dev/null 2>&1 || true
    echo "   ✓ ${SERVICE_PATH}"
  fi
fi

# 2) Binary
if [[ -f "$BIN_PATH" ]]; then
  echo "==> Binary siliniyor: $BIN_PATH"
  rm -f "$BIN_PATH"
else
  echo "   (binary zaten yok: $BIN_PATH)"
fi

# 3) .desktop
if [[ -f "$DESKTOP_PATH" ]]; then
  echo "==> .desktop siliniyor: $DESKTOP_PATH"
  rm -f "$DESKTOP_PATH"
else
  echo "   (.desktop zaten yok: $DESKTOP_PATH)"
fi

# 4) Icon'lar — tüm hicolor boyutlarını tara
if [[ -d "$ICON_BASE" ]]; then
  echo "==> Icon'lar siliniyor: ${ICON_BASE}/<size>/apps/hekadrop.png"
  # -f ile: dosya yoksa sessiz geç
  find "$ICON_BASE" -type f -name "hekadrop.png" -print -delete 2>/dev/null || true
fi

# Cache'leri tazele
if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database "$APP_DIR" >/dev/null 2>&1 || true
fi

if command -v gtk-update-icon-cache >/dev/null 2>&1; then
  gtk-update-icon-cache -f -t "$ICON_BASE" >/dev/null 2>&1 || true
fi

# Özet
echo ""
echo "✓ HekaDrop kaldırıldı (mod: ${MODE})"
echo ""
echo "Not: Config ve log dizinlerine dokunulmadı. İstersen manuel sil:"
echo "  rm -rf \"\$HOME/.config/HekaDrop\"      # ayarlar"
echo "  rm -rf \"\$HOME/.local/state/HekaDrop\" # log'lar"
