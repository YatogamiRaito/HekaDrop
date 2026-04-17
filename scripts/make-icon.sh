#!/bin/bash
# resources/icon.png (1024x1024+ önerilir) → macOS AppIcon.icns üretir.
# iconutil: Xcode Command Line Tools ile birlikte gelir.
# pngquant: lossy compression — ~10× küçük .icns için gerekli. `brew install pngquant`
set -euo pipefail

cd "$(dirname "$0")/.."

SRC="resources/icon.png"
ICONSET_DIR="resources/AppIcon.iconset"
OUT_ICNS="resources/AppIcon.icns"

if [ ! -f "$SRC" ]; then
    echo "HATA: $SRC bulunamadı."
    echo "Uygulama ikonunu 1024×1024+ PNG olarak $SRC konumuna kaydet."
    exit 1
fi

HAS_PNGQUANT=0
if command -v pngquant >/dev/null 2>&1; then
    HAS_PNGQUANT=1
fi

echo "==> $ICONSET_DIR temizleniyor"
rm -rf "$ICONSET_DIR"
mkdir -p "$ICONSET_DIR"

# iconset kuralları: her "logical size" için 1× ve 2× varyant.
# 1024×1024 (512@2x) varyantı çıkarıldı — dosya boyutunu yarı yarıya
# azaltır ve pratikte farkı insan gözü ile görünmez.
SIZES=(
    "16:icon_16x16.png"
    "32:icon_16x16@2x.png"
    "32:icon_32x32.png"
    "64:icon_32x32@2x.png"
    "128:icon_128x128.png"
    "256:icon_128x128@2x.png"
    "256:icon_256x256.png"
    "512:icon_256x256@2x.png"
    "512:icon_512x512.png"
)

echo "==> iconset üretiliyor (sips resize)"
for PAIR in "${SIZES[@]}"; do
    PX="${PAIR%%:*}"
    NAME="${PAIR##*:}"
    sips -z "$PX" "$PX" "$SRC" --out "$ICONSET_DIR/$NAME" >/dev/null
done

if [ "$HAS_PNGQUANT" -eq 1 ]; then
    echo "==> pngquant ile sıkıştırılıyor (--quality 80-95)"
    # --skip-if-larger: zaten küçükse atla; --strip: metadata at
    pngquant --force --strip \
        --quality 45-70 \
        --speed 1 \
        --ext .png \
        "$ICONSET_DIR"/*.png 2>/dev/null || true

    # Küçük boyutlar için daha agresif (ufak ikonlarda detay kaybı görünmez)
    for SMALL in "${ICONSET_DIR}/icon_16x16.png" "${ICONSET_DIR}/icon_16x16@2x.png" \
                 "${ICONSET_DIR}/icon_32x32.png" "${ICONSET_DIR}/icon_32x32@2x.png"; do
        [ -f "$SMALL" ] && pngquant --force --strip --quality 30-60 --speed 1 \
            --ext .png "$SMALL" 2>/dev/null || true
    done
else
    echo "UYARI: pngquant yok — .icns gereksiz büyük olacak."
    echo "       Küçültmek için: brew install pngquant"
fi

echo "==> iconutil ile $OUT_ICNS"
iconutil -c icns "$ICONSET_DIR" -o "$OUT_ICNS"

rm -rf "$ICONSET_DIR"

SIZE=$(du -h "$OUT_ICNS" | awk '{print $1}')
echo ""
echo "✓ $OUT_ICNS hazır ($SIZE)"
echo "  Bundle'a gömmek için: ./scripts/bundle.sh"
