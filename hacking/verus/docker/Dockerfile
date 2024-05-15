#
# Copyright 2024, Colias Group, LLC
#
# SPDX-License-Identifier: BSD-2-Clause
#

FROM debian:bookworm

RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    unzip \
    python3-pip \
    bash-completion \
    man \
    sudo \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp

RUN set -eux; \
    z3_version=4.12.5; \
    arch=$( \
        case $(uname -m) in \
            x86_64) echo x64;; \
            aarch64) echo arm64;; \
            *) false;; \
        esac \
    ); \
    filename=z3-$z3_version-$arch-glibc-2.35; \
    url=https://github.com/Z3Prover/z3/releases/download/z3-$z3_version/$filename.zip; \
    curl -sSfL -o z3.zip $url; \
    unzip z3.zip; \
    rm z3.zip; \
    mkdir -p /opt; \
    mv $filename /opt/z3;

ENV PATH=/opt/z3/bin:$PATH

ENV VERUS_Z3_PATH=/opt/z3/bin/z3

ARG UID
ARG GID

RUN set -eux; \
    if [ $UID -eq 0 ]; then \
        [ $GID -eq 0 ]; \
    else \
        ! getent passwd $UID; \
        if ! getent group $GID; then \
            groupadd --gid $GID x; \
        fi; \
        useradd --uid $UID --gid $GID --groups sudo --create-home x; \
    fi;

RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

USER $UID

ARG TOOLCHAIN

RUN set -eux; \
    if [ $UID -ne 0 ]; then \
        curl -sSf https://sh.rustup.rs | \
            bash -s -- -y --no-modify-path --default-toolchain $TOOLCHAIN; \
    fi;

ENV PATH=/home/x/.cargo/bin:/root/.cargo/bin:$PATH

RUN set -eux; \
    git clone \
        https://github.com/verus-lang/verus \
        --config advice.detachedHead=false; \
    cd verus; \
    git checkout 5a74463572e3241d1f6d7b78d8dddaf2722dc09d;

RUN set -eux; \
    cd verus/tools/vargo; \
    cargo build --release;

ENV PATH=/tmp/verus/tools/vargo/target/release:$PATH

RUN set -eux; \
    cd verus/source; \
    vargo build --release

ENV PATH=/tmp/verus/source/target-verus/release:$PATH

WORKDIR /work/hacking/verus
