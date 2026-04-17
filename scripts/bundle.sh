#!/bin/bash
# HekaDrop.app paketleyici — release build + macOS bundle yapısı.
set -euo pipefail

cd "$(dirname "$0")/.."

PROFILE="${PROFILE:-release}"
APP_NAME="HekaDrop"
BUNDLE_DIR="target/${PROFILE}/${APP_NAME}.app"
CONTENTS="${BUNDLE_DIR}/Contents"
MACOS="${CONTENTS}/MacOS"
RESOURCES="${CONTENTS}/Resources"

echo "==> cargo build --${PROFILE}"
if [ "$PROFILE" = "release" ]; then
    cargo build --release
else
    cargo build
fi

echo "==> ${BUNDLE_DIR} temizleniyor"
rm -rf "$BUNDLE_DIR"
mkdir -p "$MACOS" "$RESOURCES"

echo "==> binary kopyalanıyor"
cp "target/${PROFILE}/hekadrop" "${MACOS}/hekadrop"
chmod +x "${MACOS}/hekadrop"

echo "==> Info.plist kopyalanıyor"
cp resources/Info.plist "${CONTENTS}/Info.plist"

if [ -f "resources/AppIcon.icns" ]; then
    echo "==> uygulama ikonu ekleniyor (AppIcon.icns)"
    cp resources/AppIcon.icns "${RESOURCES}/AppIcon.icns"
    /usr/libexec/PlistBuddy -c "Delete :CFBundleIconFile" "${CONTENTS}/Info.plist" 2>/dev/null || true
    /usr/libexec/PlistBuddy -c "Add :CFBundleIconFile string AppIcon" "${CONTENTS}/Info.plist"
else
    echo "==> AppIcon.icns bulunamadı (ikonsuz devam)"
    echo "   Bir ikon eklemek için:"
    echo "     1. 1024×1024 PNG'yi resources/icon.png olarak kaydet"
    echo "     2. ./scripts/make-icon.sh çalıştır"
    echo "     3. tekrar ./scripts/bundle.sh"
fi

echo "==> ad-hoc imza"
codesign --force --deep --sign - "${BUNDLE_DIR}" 2>&1 | tail -3 || true

echo ""
echo "✓ Paket hazır: ${BUNDLE_DIR}"
echo "  Çalıştır:    open \"${BUNDLE_DIR}\""
echo "  Yükle:       cp -R \"${BUNDLE_DIR}\" /Applications/"
echo "  Login Items: Menü çubuğu → Başlangıçta aç"
