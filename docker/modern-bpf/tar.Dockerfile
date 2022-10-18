FROM ubuntu:22.04 AS builder

COPY ./falco.tar.gz /

WORKDIR /

RUN mkdir falco; \
    tar -xzf falco.tar.gz -C falco --strip-component 1 \
    rm -rf /falco/usr/src/falco-*; \
    rm /falco/usr/bin/falco-driver-loader

RUN sed -e 's/time_format_iso_8601: false/time_format_iso_8601: true/' < /falco/etc/falco/falco.yaml > /falco/etc/falco/falco.yaml.new; \
    mv /falco/etc/falco/falco.yaml.new /falco/etc/falco/falco.yaml

FROM debian:11-slim

LABEL name="falcosecurity/falco-modern-bpf"
LABEL maintainer="cncf-falco-dev@lists.cncf.io"

COPY --from=builder /falco /

CMD ["/usr/bin/falco", "-o", "time_format_iso_8601=true", "--modern-bpf"]
