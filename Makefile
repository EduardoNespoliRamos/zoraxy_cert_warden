DOCKER ?= podman
GO_IMAGE := docker.io/golang:1.25.13-alpine
GO_DEBIAN_IMAGE := docker.io/golang:1.25.13-bookworm
PROJECT := github.com/eduardoramos/zoraxy-cert-warden
ROOT := $(shell pwd)
ZORAXY_VERSION ?= v3.3.3
VERSION ?= dev
LDFLAGS := -s -w -X main.Version=$(VERSION)
STATICCHECK_VERSION := v0.7.0
GOVULNCHECK_VERSION := v1.7.0
ACTIONLINT_VERSION := v1.7.7

.PHONY: all fmt-check test race vet staticcheck govulncheck actionlint repeat-test certwarden-api-test quality build build-amd64 build-arm64 build-all verify-version integration-test e2e-test e2e-remote-test e2e-clean clean

all: test build-all

test:
	$(DOCKER) run --rm -v "$(ROOT):/src" -w /src $(GO_IMAGE) go test ./...

fmt-check:
	$(DOCKER) run --rm -v "$(ROOT):/src:ro" -w /src $(GO_IMAGE) sh -c 'gofmt -d $$(find . -name "*.go" -not -path "./dist/*") > /tmp/gofmt.diff; test ! -s /tmp/gofmt.diff || (cat /tmp/gofmt.diff && exit 1)'

race:
	$(DOCKER) run --rm -v "$(ROOT):/src" -w /src $(GO_DEBIAN_IMAGE) sh -c 'CGO_ENABLED=1 go test -race ./...'

vet:
	$(DOCKER) run --rm -v "$(ROOT):/src" -w /src $(GO_IMAGE) go vet ./...

staticcheck:
	$(DOCKER) run --rm -v "$(ROOT):/src" -w /src $(GO_IMAGE) sh -c 'go install honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION) && staticcheck ./...'

govulncheck:
	$(DOCKER) run --rm -v "$(ROOT):/src" -w /src $(GO_IMAGE) sh -c 'go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) && govulncheck ./...'

actionlint:
	$(DOCKER) run --rm -v "$(ROOT):/src" -w /src $(GO_IMAGE) sh -c 'go install github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION) && actionlint'

repeat-test:
	$(DOCKER) run --rm -v "$(ROOT):/src" -w /src $(GO_IMAGE) go test -count=50 ./internal/watcher ./internal/sync

certwarden-api-test:
	$(DOCKER) run --rm -v "$(ROOT):/src" -w /src $(GO_IMAGE) go test ./internal/certwarden ./internal/secretstore ./tests/certwardenmock

quality: fmt-check test race vet staticcheck govulncheck actionlint repeat-test certwarden-api-test

build:
	mkdir -p dist
	$(DOCKER) run --rm -v "$(ROOT):/src" -w /src $(GO_IMAGE) \
		sh -c 'go build -ldflags="$(LDFLAGS)" -o dist/zoraxy-cert-sync-linux-$$(uname -m | sed s/aarch64/arm64/ | sed s/x86_64/amd64/) ./cmd/cert-sync'

build-amd64:
	mkdir -p dist
	$(DOCKER) run --rm -v "$(ROOT):/src" -w /src $(GO_IMAGE) \
		sh -c 'CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o dist/zoraxy-cert-sync-linux-amd64 ./cmd/cert-sync'

build-arm64:
	mkdir -p dist
	$(DOCKER) run --rm -v "$(ROOT):/src" -w /src $(GO_IMAGE) \
		sh -c 'CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o dist/zoraxy-cert-sync-linux-arm64 ./cmd/cert-sync'

build-all: build-amd64 build-arm64

verify-version: build-amd64
	@test "$(VERSION)" != "dev" || (echo "VERSION must be a semantic release version" >&2; exit 1)
	@actual=`$(DOCKER) run --rm -v "$(ROOT)/dist:/dist:ro" --entrypoint /dist/zoraxy-cert-sync-linux-amd64 $(GO_IMAGE) -introspect | $(DOCKER) run --rm -i $(GO_IMAGE) sh -c 'tr -d " \n"'`; \
	 expected='"version_major":'`printf '%s' "$(VERSION)" | cut -d. -f1`',"version_minor":'`printf '%s' "$(VERSION)" | cut -d. -f2`',"version_patch":'`printf '%s' "$(VERSION)" | cut -d. -f3`; \
	 printf '%s' "$$actual" | grep -q "$$expected" || (echo "introspect does not report $(VERSION)" >&2; exit 1)

integration-test:
	$(DOCKER) build -f tests/docker/Dockerfile.tests -t zoraxy-cert-warden-integration .
	$(DOCKER) run --rm zoraxy-cert-warden-integration

e2e-test:
	ZORAXY_VERSION=$(ZORAXY_VERSION) E2E_SUITE=$${E2E_SUITE:-compatibility} $(DOCKER) compose -f tests/docker/docker-compose.test.yml up --build --abort-on-container-exit --exit-code-from e2e e2e

e2e-remote-test:
	E2E_SUITE=certwarden-api $(MAKE) e2e-test

e2e-clean:
	$(DOCKER) compose -f tests/docker/docker-compose.test.yml down -v

integration-test-shell:
	ZORAXY_VERSION=$(ZORAXY_VERSION) $(DOCKER) compose -f tests/docker/docker-compose.test.yml up --build -d zoraxy

clean:
	rm -rf dist tmp
	$(MAKE) e2e-clean
