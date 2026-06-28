# syntax=docker/dockerfile:1
#
# Dockerfile for the MOSS K8s sidecar (moss-sidecar).
#
# Multi-stage build:
#   1. build  — Go toolchain compiles the sidecar binary.
#   2. runtime — minimal image (distroless/static) carrying only the binary.
#
# The sidecar runs as a native sidecar (init container, restartPolicy: Always)
# in a pod with shareProcessNamespace: true. It needs:
#   - /proc access (shared PID namespace) for the SIGTERM->SIGKILL path.
#   - the pod service-account token (/var/run/secrets/kubernetes.io/) for the
#     client-go pod-delete path.
# distroless/static is sufficient; it has no shell, which is fine because the
# sidecar is a single static Go binary.

FROM golang:1.25-alpine AS build
WORKDIR /src

# Cache deps first.
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build the sidecar binary as a static Linux binary.
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -ldflags='-s -w' -o /out/moss-sidecar \
    ./sidecar/cmd

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/moss-sidecar /usr/local/bin/moss-sidecar

# The sidecar runs as root by default because the signal-kill path must be
# able to terminate the sibling agent process regardless of the uid that
# agent runs as (signalling a process in the shared PID namespace requires
# CAP_KILL / a matching uid). The pod's securityContext can harden this
# further where the agent uid is known.

ENTRYPOINT ["/usr/local/bin/moss-sidecar"]
