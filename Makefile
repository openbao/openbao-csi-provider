REGISTRY_NAME?=quay.io/openbao
IMAGE_NAME=openbao-csi-provider
VERSION?=0.0.0-dev
IMAGE_TAG=$(REGISTRY_NAME)/$(IMAGE_NAME):$(VERSION)
# commented because it may not be in use
IMAGE_TAG_LATEST=$(REGISTRY_NAME)/$(IMAGE_NAME):latest
# https://reproducible-builds.org/docs/source-date-epoch/
DATE_FMT=+%Y-%m-%d-%H:%M
SOURCE_DATE_EPOCH ?= $(shell git log -1 --pretty=%ct)
ifdef SOURCE_DATE_EPOCH
  BUILD_DATE ?= $(shell date -u -d "@$(SOURCE_DATE_EPOCH)" $(DATE_FMT) 2>/dev/null || date -u -r "$(SOURCE_DATE_EPOCH)" $(DATE_FMT) 2>/dev/null || date -u $(DATE_FMT))
else
    BUILD_DATE ?= $(shell date $(DATE_FMT))
endif
PKG=github.com/openbao/openbao-csi-provider/internal/version
LDFLAGS?="-X '$(PKG).BuildVersion=$(VERSION)' \
	-X '$(PKG).BuildDate=$(BUILD_DATE)' \
	-X '$(PKG).GoVersion=$(shell go version)'"
CSI_DRIVER_VERSION=1.3.2
OPENBAO_HELM_VERSION=0.4.0
OPENBAO_VERSION=2.0.0-alpha20240329
GOLANGCI_LINT_FORMAT?=colored-line-number

OPENBAO_VERSION_ARGS=--set server.image.tag=$(OPENBAO_VERSION)

.PHONY: default build test bootstrap fmt lint image e2e-image e2e-setup e2e-teardown e2e-test mod setup-kind promote-staging-manifest copyright

GO111MODULE?=on
export GO111MODULE

default: test

bootstrap:
	@echo "Downloading tools..."
	@go generate -tags tools tools/tools.go

fmt:
	gofumpt -l -w .

lint:
	golangci-lint run \
		--disable-all \
		--timeout=10m \
		--out-format=$(GOLANGCI_LINT_FORMAT) \
		--enable=gofmt \
		--enable=gosimple \
		--enable=govet \
		--enable=errcheck \
		--enable=ineffassign \
		--enable=unused

build:
	CGO_ENABLED=0 go build \
		-ldflags $(LDFLAGS) \
		-o dist/ \
		.

test:
	go test ./...

image:
	docker build \
		--build-arg GO_VERSION=$(shell cat .go-version) \
		--target dev \
		--no-cache \
		--tag $(IMAGE_TAG) \
		.

e2e-image:
	REGISTRY_NAME="e2e" VERSION="latest" make image

setup-kind:
	kind create cluster

e2e-setup:
	kind load docker-image e2e/openbao-csi-provider:latest
	kubectl apply -f test/bats/configs/cluster-resources.yaml
	helm install secrets-store-csi-driver secrets-store-csi-driver \
		--repo https://kubernetes-sigs.github.io/secrets-store-csi-driver/charts \
		--version=$(CSI_DRIVER_VERSION) \
		--wait --timeout=5m \
		--namespace=csi \
		--set linux.image.pullPolicy="IfNotPresent" \
		--set syncSecret.enabled=true \
		--set tokenRequests[0].audience="openbao"
	helm install openbao-bootstrap test/bats/configs/openbao \
		--namespace=csi
	helm install openbao openbao \
		--repo https://openbao.github.io/openbao-helm \
		--version=$(OPENBAO_HELM_VERSION) \
		--wait --timeout=5m \
		--namespace=csi \
		--values=test/bats/configs/openbao/openbao.values.yaml \
		$(OPENBAO_VERSION_ARGS)
	kubectl wait --namespace=csi --for=condition=Ready --timeout=3m pod -l app.kubernetes.io/name=openbao || kubectl describe pods --namespace=csi -l app.kubernetes.io/name=openbao
	kubectl exec -i --namespace=csi openbao-0 -- /bin/sh /mnt/bootstrap/bootstrap.sh
	kubectl wait --namespace=csi --for=condition=Ready --timeout=3m pod -l app.kubernetes.io/name=openbao-csi-provider || kubectl describe pods --namespace=csi -l app.kubernetes.io/name=openbao-csi-provider

e2e-teardown:
	helm uninstall --namespace=csi openbao || true
	helm uninstall --namespace=csi openbao-bootstrap || true
	helm uninstall --namespace=csi secrets-store-csi-driver || true
	kubectl delete --ignore-not-found -f test/bats/configs/cluster-resources.yaml

e2e-test:
	bats test/bats/provider.bats

mod:
	@go mod tidy

promote-staging-manifest: # promote staging manifests to release dir
	@rm -rf deployment
	@cp -r manifest_staging/deployment .

copyright:
	copywrite headers
