FROM archlinux:latest

LABEL name="falcosecurity/falco-modern-bpf"
LABEL maintainer="cncf-falco-dev@lists.cncf.io"

RUN pacman -Syu --noconfirm git cmake make llvm clang pkgconf libelf zlib libffi libbpf linux-tools glibc gcc gtest protobuf openssl tbb libb64 wget jq yaml-cpp curl c-ares grpc libyaml libpcap 

COPY ./falco /usr/local/bin/falco

ENTRYPOINT [ "falco", "--modern-bpf"]
