FROM ubuntu:22.04 as modern_builder

# Dependencies needed by `Falco` building phase
RUN apt update; \
    apt install -y --no-install-recommends ca-certificates cmake build-essential git clang-14 llvm-14 linux-headers-$(uname -r) m4 rpm

# Dependencies needed by `bpftool`
RUN apt install -y libelf-dev zlib1g zlib1g-dev

# Move some executables in the `$PATH`
RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-14 90; \
    update-alternatives --install /usr/bin/llvm-strip llvm-strip /usr/bin/llvm-strip-14 90 

# Install BPFTOOL `v6.7.0` if we are on not so recent kernel version
RUN git clone https://github.com/libbpf/bpftool.git --branch v6.7.0 --single-branch; \
    cd bpftool; \
    git submodule update --init; \
    cd src && make install; \
    cd ./../..; \
    rm -rf bpftool
