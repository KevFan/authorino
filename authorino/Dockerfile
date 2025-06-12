# Build the manager binary
FROM registry.access.redhat.com/ubi9/go-toolset:1.23 AS builder
ARG TARGETOS
ARG TARGETARCH
ARG version
ENV version=${version:-unknown}
ARG git_sha
ENV git_sha=${git_sha:-unknown}
ARG dirty
ENV dirty=${dirty:-unknown}

USER root
WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the go source
COPY cmd/main.go cmd/main.go
COPY api/ api/
COPY internal/ internal/

# Build
# the GOARCH has not a default value to allow the binary be built according to the host where the command
# was called. For example, if we call make docker-build in a local env which has the Apple Silicon M1 SO
# the docker BUILDPLATFORM arg will be linux/arm64 when for Apple x86 it will be linux/amd64. Therefore,
# by leaving it empty we can ensure that the container and binary shipped on it will have the same platform.
RUN GO111MODULE=on GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -a -ldflags "-X main.version=${version} -X main.gitSHA=${git_sha} -X main.dirty=${dirty}" \
    -o /usr/bin/authorino cmd/main.go

# Use Red Hat minimal base image to package the binary
# https://catalog.redhat.com/software/containers/ubi9-minimal
FROM registry.access.redhat.com/ubi9-minimal:latest

# shadow-utils is required for `useradd`
RUN PKGS="shadow-utils" \
    && microdnf --assumeyes install --nodocs $PKGS \
    && rpm --verify --nogroup --nouser $PKGS \
    && microdnf -y clean all
RUN useradd -u 1000 -s /bin/sh -m -d /home/authorino authorino

WORKDIR /home/authorino/bin
ENV PATH=/home/authorino/bin:$PATH
COPY --from=builder /usr/bin/authorino ./authorino

RUN chown -R authorino:root /home/authorino \
    && chmod -R 750 /home/authorino
USER authorino

ENTRYPOINT ["authorino", "server"]