# CloudSecurity-AF Go port — build/test targets. Run from the go/ directory.
# Mirrors the acceptance gate every port task and CI use (docs/DESIGN.md §0.4):
#   go build ./... && go vet ./... && go test ./... && test -z "$(gofmt -l .)"
#
# The AgentField Go SDK is a REAL versioned require resolved from
# proxy.golang.org (no replace directive), so no GOWORK/replace dance is needed
# for CI/Docker. A gitignored go.work is the local dev path; set GOWORK=off to
# ignore it explicitly.

.PHONY: build vet test check fmt fmt-check lint run docker-build docker-up docker-down

# Compile every package in the module.
build:
	go build ./...

# Static analysis (go vet) across the module.
vet:
	go vet ./...

# Unit tests across the module.
test:
	go test ./...

# Fail when any file is not gofmt-clean (the CI gate).
fmt-check:
	@test -z "$$(gofmt -l .)" || { echo "gofmt needed:"; gofmt -l .; exit 1; }

# The full local gate CI runs: build + vet + tests + gofmt.
check: build vet test fmt-check

# Format every Go source file in place.
fmt:
	gofmt -w .

# Optional lint pass. Only the ABSENCE of the tool may be a no-op; a lint
# FAILURE must fail the target.
#
# `command -v X && X run || echo ...` cannot express that: a shell A && B || C
# chain runs C whenever EITHER A or B exits non-zero, so a real lint failure
# printed "golangci-lint not installed" and exited 0 — a false green with a
# false reason. An if/then/else is the only correct shape.
lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed; skipping (install: https://golangci-lint.run)"; \
	fi

# Run the CloudSecurity node (node id cloudsecurity, default port 8015).
run:
	go run ./cmd/cloudsecurity-af

# --- Docker (multi-stage image + Go-node compose add-on) ------------------
# The Dockerfile expects the REPO ROOT as the build context (it COPYs go/go.mod,
# go/ ...), so the context is the parent dir. The compose add-on
# (docker-compose.go.yml) lives at the repo root and joins the Python
# cloudsecurity-af stack's external network.
# Override the image tag with: make docker-build IMAGE=myrepo/cloudsecurity-af-go:dev
#
# The tag is `cloudsecurity-af-go`, NOT `cloudsecurity-af`: the root README's
# `docker build --build-arg AFORGE_VERSION=v0.1.0 -t cloudsecurity-af .` builds
# the PYTHON image and resolves to `cloudsecurity-af:latest`, so sharing the tag
# would make whichever image was built last silently own it — a `docker run
# cloudsecurity-af` would then get the other node (port 8005 vs 8015, a
# different entrypoint) with nothing in `docker images` to tell them apart.
# .github/workflows/go.yml already builds `cloudsecurity-af-go:test`.
IMAGE ?= cloudsecurity-af-go:latest

docker-build:
	docker build -f Dockerfile -t $(IMAGE) ..

# Bring up the Go node (cloudsecurity-go:8015) as an ADD-ON to the Python stack.
# Start the Python stack first (`docker compose up` — it owns the control plane
# and the shared network); this add-on joins that network as an external ref.
docker-up:
	docker compose -f ../docker-compose.go.yml up --build

# Tear the Go-node add-on down.
docker-down:
	docker compose -f ../docker-compose.go.yml down
