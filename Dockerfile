FROM golang:1 as builder

ENV GOGC off
ENV CGO_ENABLED 0

RUN set -x \
    && apt update \
    && apt install -y upx-ucl

WORKDIR /src
COPY . /src

RUN set -x \
    && go build -v -mod=vendor -trimpath \
      -o /go/bin/driveprober ./cmd \
    && upx -3 /go/bin/driveprober

# Executable image
FROM scratch

WORKDIR /

COPY --from=builder /go/bin/driveprober /bin/driveprober
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

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