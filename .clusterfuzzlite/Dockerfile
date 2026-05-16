FROM gcr.io/oss-fuzz-base/base-builder-rust

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

COPY . $SRC/hekadrop
WORKDIR $SRC/hekadrop

COPY .clusterfuzzlite/build.sh $SRC/build.sh
