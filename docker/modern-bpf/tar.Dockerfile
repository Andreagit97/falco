FROM ubuntu:22.04 AS builder

COPY ./falco.tar.gz /

WORKDIR /

# 1. We remove the falco directory with the name releated to the version and to the arch
# 2. We remove the source folder
# 3. We remove the falco-driver-loader binary
# 4. We move the `etc` folder from `falco/usr/local/etc` to `/falco/etc`
# 5. We remove the `/falco/usr/local` folder
RUN mkdir falco; \
    tar -xzf falco.tar.gz -C falco --strip-component 1; \
    rm -rf /falco/usr/src; \
    rm /falco/usr/bin/falco-driver-loader; \
    mv /falco/usr/local/etc /falco/; \
    rm -rf /falco/usr/local

# the time displayed in log messages and output messages will be in ISO 8601.
RUN sed -e 's/time_format_iso_8601: false/time_format_iso_8601: true/' < /falco/etc/falco/falco.yaml > /falco/etc/falco/falco.yaml.new; \
    mv /falco/etc/falco/falco.yaml.new /falco/etc/falco/falco.yaml

FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y \
    libelf-dev

LABEL name="falcosecurity/falco-modern-bpf"
LABEL maintainer="cncf-falco-dev@lists.cncf.io"

COPY --from=builder /falco /

CMD ["/usr/bin/falco", "-o", "time_format_iso_8601=true", "--modern-bpf"]
