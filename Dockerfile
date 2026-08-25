FROM golang:1.27-bookworm as builder

ENV GOGC off
ENV CGO_ENABLED 0

RUN set -x \
  && apt update \
  && DEBIAN_FRONTEND="noninteractive" apt install -y wget ca-certificates make ruby-dev build-essential

RUN  cd /tmp \
  && wget https://github.com/upx/upx/releases/download/v5.0.2/upx-5.0.2-amd64_linux.tar.xz \
  && tar -xf upx-5.0.2-amd64_linux.tar.xz
RUN cp /tmp/upx-5.0.2-amd64_linux/upx /sbin \
    && chmod +x /sbin/upx

WORKDIR /src
COPY . /src

RUN set -x \
    && go mod tidy \
    && go mod vendor \
    && go build -v -mod=vendor -trimpath \
      -o /go/bin/driveprober ./cmd \
    && upx -3 /go/bin/driveprober

# Executable image
FROM ubuntu

RUN useradd -r -s /usr/sbin/nologin -u 2034 cloudprober

WORKDIR /

COPY --from=builder /go/bin/driveprober /bin/driveprober
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

RUN chown cloudprober /bin/driveprober
USER cloudprober

# Metadata params
ARG BUILD_DATE
ARG VERSION
ARG VCS_REF

# Metadata
LABEL org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.name="Driveprober" \
      org.label-schema.vcs-url="https://github.com/drivenet/cloudprober-ocsp" \
      org.label-schema.vcs-ref=$VCS_REF \
      org.label-schema.version=$VERSION \
      com.microscaling.license="Apache-2.0"

ENTRYPOINT ["/bin/driveprober", "--logtostderr"]