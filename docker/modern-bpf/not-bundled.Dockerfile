FROM ubuntu:22.04 AS builder

LABEL name="falcosecurity/falco-modern-bpf"
LABEL maintainer="cncf-falco-dev@lists.cncf.io"

WORKDIR /

# Install some dependencies
RUN apt-get update && \
    apt-get install -y \
    cmake git ca-certificates build-essential pkg-config autoconf libtool libelf-dev libssl-dev clang llvm \
    libc-ares-dev libprotobuf-dev protobuf-compiler libjq-dev libgrpc++-dev protobuf-compiler-grpc libcurl4-openssl-dev libyaml-cpp-dev \
    libjsoncpp-dev libtbb-dev libb64-dev curl --no-install-recommends

# Install bpftool
RUN git clone --branch  v7.0.0  https://github.com/libbpf/bpftool.git; \
    cd ./bpftool; \
    git submodule update --init; \
    cd src; \
    make install

WORKDIR /usr/src/falco

# Copy the entire build context and also some files
# Please note: the <src> paths of files and directories
# will be interpreted as relative to the source of the build context
COPY . /usr/src/falco
COPY ./falco.yaml /etc/falco/falco.yaml
COPY ./rules/* /etc/falco/

# We need bundled libbpf if we want a recent version
RUN mkdir build && cd build; \
    cmake -DUSE_BUNDLED_DEPS=Off -DCREATE_TEST_TARGETS=Off -DBUILD_FALCO_GVISOR=Off -DUSE_BUNDLED_OPENSSL=ON -DBUILD_FALCO_MODERN_BPF=On -DUSE_BUNDLED_VALIJSON=On -DUSE_BUNDLED_RE2=On -DUSE_BUNDLED_LIBBPF=On -DUSE_BUNDLED_ZLIB=On ..; \
    make falco -j4; \
    ln -s ./build/userspace/falco/falco /usr/bin/falco

RUN echo $PATH2

ENTRYPOINT [ "falco", "--modern-bpf"]
