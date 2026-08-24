# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

# This Dockerfile contains multiple targets.
# Use 'docker build --target=<name> .' to build one.

ARG ALPINE_VERSION=3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
ARG GO_VERSION=1.27.0@sha256:65b6f280bf050ec5af12716857e8ea8439d694dbba8f31ceeb7630670071f2bb


# devbuild compiles the binary
# -----------------------------------
FROM golang:${GO_VERSION} AS devbuild
ENV CGO_ENABLED=0
# Leave the GOPATH
WORKDIR /build
COPY . ./
RUN go build -o openbao-csi-provider

# dev runs the binary from devbuild
# -----------------------------------
FROM alpine:${ALPINE_VERSION} AS dev
COPY --from=devbuild /build/openbao-csi-provider /bin/
ENTRYPOINT [ "/bin/openbao-csi-provider" ]

# Default release image.
# -----------------------------------
FROM alpine:${ALPINE_VERSION} AS default

ARG PRODUCT_VERSION
ARG PRODUCT_REVISION
ARG PRODUCT_NAME=openbao-csi-provider
ARG TARGETOS TARGETARCH

LABEL version=$PRODUCT_VERSION
LABEL revision=$PRODUCT_REVISION

COPY $BIN_NAME /bin/
ENTRYPOINT [ "/bin/openbao-csi-provider" ]

# ===================================
#
#   Set default target to 'dev'.
#
# ===================================
FROM dev
