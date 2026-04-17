#!/bin/bash
# Universal2 (x86_64 + aarch64) binary üretir.
# `lipo -create` ile tek dosyada iki mimari birleştirilir.
set -euo pipefail

cd "$(dirname "$0")/.."

OUT="target/release/hekadrop"

echo "==> rustup hedefleri kuruluyor (yoksa)"
rustup target add x86_64-apple-darwin aarch64-apple-darwin 2>&1 | tail -2

echo "==> x86_64 release build"
cargo build --release --target x86_64-apple-darwin

echo "==> aarch64 release build"
cargo build --release --target aarch64-apple-darwin

echo "==> lipo -create → ${OUT}"
mkdir -p target/release
lipo -create \
    target/x86_64-apple-darwin/release/hekadrop \
    target/aarch64-apple-darwin/release/hekadrop \
    -output "$OUT"

file "$OUT"
echo ""
echo "✓ Universal binary: $OUT"
echo "  Bundle'lamak için: ./scripts/bundle.sh"
