FROM ubuntu:22.04

ARG FALCO_VERSION
ARG VERSION_BUCKET=bin

ENV FALCO_VERSION=${FALCO_VERSION}
ENV VERSION_BUCKET=${VERSION_BUCKET}

LABEL name="falcosecurity/falco-modern-bpf"
LABEL maintainer="cncf-falco-dev@lists.cncf.io"

# Install some dependencies
RUN apt-get update && \
    apt-get install -y \
    cmake git build-essential pkg-config autoconf libtool libelf-dev libssl-dev clang llvm

# Install bpftool into the system
RUN git clone --single-branch --branch  v7.0.0  https://github.com/libbpf/bpftool.git; \
    cd bpftool; \
    git submodule update --init; \
    cd src; \
    make install; \
    cd ..

RUN mkdir -p /usr/src/falco

COPY . /usr/src/falco

RUN cd /usr/src/falco; \
    mkdir build && cd build; \
    cmake -DUSE_BUNDLED_DEPS=On -DCREATE_TEST_TARGETS=Off -DBUILD_FALCO_GVISOR=Off -DBUILD_FALCO_MODERN_BPF=On ..; \
    make falco

COPY ./userspace/falco/falco /usr/local/bin/falco

ENTRYPOINT [ "falco", "--modern-bpf"]
