#!/bin/bash -eu

if [ "$SANITIZER" = "coverage" ]; then
    export RUSTFLAGS="$RUSTFLAGS -C debug-assertions=no"
    export CFLAGS=""
fi

cd "$SRC/hekadrop"

cargo fuzz build -O --fuzz-dir fuzz

for f in fuzz/fuzz_targets/*.rs; do
    target=$(basename "${f%.*}")
    bin=$(find fuzz/target -name "$target" -type f \
        ! -name "*.d" ! -path "*/deps/*" | head -1)
    if [ -n "$bin" ]; then
        cp "$bin" "$OUT/$target"
    fi
    if [ -d "fuzz/corpus/$target" ] && \
       [ -n "$(ls -A "fuzz/corpus/$target" 2>/dev/null)" ]; then
        zip -j "$OUT/${target}_seed_corpus.zip" "fuzz/corpus/$target"/*
    fi
done
