#!/bin/bash -eu
# OSS-Fuzz build script for HekaDrop.
# https://google.github.io/oss-fuzz/getting-started/new-project-guide/rust-lang/

cd "$SRC/hekadrop"

# cargo-fuzz requires nightly; OSS-Fuzz base image provides it.
rustup default nightly

# Build all fuzz targets.
cargo fuzz build --fuzz-dir fuzz

# Copy binaries into $OUT.
FUZZ_TARGET_DIR="fuzz/target/x86_64-unknown-linux-gnu/release"

targets=(
    fuzz_ukey2_client_init
    fuzz_ukey2_client_finish
    fuzz_frame_decode
    fuzz_secure_decrypt
    fuzz_payload_header
    fuzz_payload_assembler
    fuzz_chunk_hmac
    fuzz_resume_meta
    fuzz_protobuf_frames
    fuzz_endpoint_info
)

for target in "${targets[@]}"; do
    cp "$FUZZ_TARGET_DIR/$target" "$OUT/$target"
done

# Copy seed corpus if present.
for target in "${targets[@]}"; do
    corpus_dir="fuzz/corpus/$target"
    if [ -d "$corpus_dir" ] && [ -n "$(ls -A "$corpus_dir")" ]; then
        zip -j "$OUT/${target}_seed_corpus.zip" "$corpus_dir"/*
    fi
done
