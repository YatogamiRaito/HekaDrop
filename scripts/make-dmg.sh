#!/bin/bash
# HekaDrop.app → HekaDrop-<version>.dmg
# Sürükle-bırak kurulumlu DMG üretir (Applications klasörü kısayolu dahil).
# hdiutil macOS'un dahili aracıdır.
set -euo pipefail

cd "$(dirname "$0")/.."

VERSION=$(grep -m1 '^version = ' Cargo.toml | sed 's/.*"\(.*\)".*/\1/')
VOLUME_NAME="HekaDrop ${VERSION}"
DMG_NAME="HekaDrop-${VERSION}.dmg"
DMG_PATH="target/${DMG_NAME}"
STAGING_DIR="target/dmg-staging"

echo "==> .app hazırlanıyor"
./scripts/bundle.sh

echo "==> staging (${STAGING_DIR})"
rm -rf "$STAGING_DIR" "$DMG_PATH"
mkdir -p "$STAGING_DIR"

cp -R target/release/HekaDrop.app "$STAGING_DIR/HekaDrop.app"
ln -s /Applications "$STAGING_DIR/Applications"

# .DS_Store ile ikonu pencerede konumlama — opsiyonel, şimdilik atla (grafiksel tool yok)

echo "==> DMG üretiliyor"
hdiutil create \
    -volname "$VOLUME_NAME" \
    -srcfolder "$STAGING_DIR" \
    -ov \
    -format UDZO \
    -fs HFS+ \
    "$DMG_PATH" >/dev/null

rm -rf "$STAGING_DIR"

echo "==> ad-hoc DMG imzası"
codesign --force --sign - "$DMG_PATH" 2>/dev/null || true

SIZE=$(du -h "$DMG_PATH" | awk '{print $1}')
echo ""
echo "✓ $DMG_PATH ($SIZE)"
echo "  Dağıtım:  double-click → HekaDrop'u Applications'a sürükle"
