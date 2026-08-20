DOCKER ?= podman
GO_IMAGE := docker.io/golang:1.23-alpine
PROJECT := github.com/eduardoramos/zoraxy-cert-warden
ROOT := $(shell pwd)
ZORAXY_VERSION ?= v3.3.3

.PHONY: all test build build-amd64 build-arm64 build-all integration-test e2e-test clean

all: test build-all

test:
	$(DOCKER) run --rm -v "$(ROOT):/src" -w /src $(GO_IMAGE) go test ./...

build:
	mkdir -p dist
	$(DOCKER) run --rm -v "$(ROOT):/src" -w /src $(GO_IMAGE) \
		sh -c 'go build -ldflags="-s -w" -o dist/zoraxy-cert-sync-linux-$$(uname -m | sed s/aarch64/arm64/ | sed s/x86_64/amd64/) ./cmd/cert-sync'

build-amd64:
	mkdir -p dist
	$(DOCKER) run --rm -v "$(ROOT):/src" -w /src $(GO_IMAGE) \
		sh -c 'CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o dist/zoraxy-cert-sync-linux-amd64 ./cmd/cert-sync'

build-arm64:
	mkdir -p dist
	$(DOCKER) run --rm -v "$(ROOT):/src" -w /src $(GO_IMAGE) \
		sh -c 'CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o dist/zoraxy-cert-sync-linux-arm64 ./cmd/cert-sync'

build-all: build-amd64 build-arm64

integration-test:
	ZORAXY_VERSION=$(ZORAXY_VERSION) $(DOCKER) compose -f tests/docker/docker-compose.test.yml up --build --abort-on-container-exit tests

e2e-test:
	ZORAXY_VERSION=$(ZORAXY_VERSION) $(DOCKER) compose -f tests/docker/docker-compose.test.yml up --build --abort-on-container-exit e2e

integration-test-shell:
	ZORAXY_VERSION=$(ZORAXY_VERSION) $(DOCKER) compose -f tests/docker/docker-compose.test.yml up --build -d zoraxy

clean:
	rm -rf dist tmp
	$(DOCKER) compose -f tests/docker/docker-compose.test.yml down -v
