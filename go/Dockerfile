# CloudSecurity-AF Go node — multi-stage build.
#
# Build from the repo ROOT so the go/ module is in the build context and the
# paths below (go/go.mod, go/) resolve. The docker-compose.go.yml add-on builds
# it exactly this way (build.context: ., dockerfile: go/Dockerfile):
#
#     docker build -f go/Dockerfile -t cloudsecurity-af:latest .
#
# The AgentField Go SDK is a REAL versioned require resolved from
# proxy.golang.org — so there is no SDK clone stage, no GOWORK=off and no
# `replace` dance. `go mod download` pulls the SDK and every other dependency
# straight from the module proxy, cache-keyed on go.mod/go.sum.

# ---------------------------------------------------------------------------
# Stage 0 — aforge: fetch the released AForge CLI from the public download host
# and verify it against the release checksums (which hash the DECOMPRESSED
# binaries). This stage is copied from the repo's own Python Dockerfile so both
# images ship the identical, checksum-verified binary. Both ARGs are overridable
# so CI or a local mirror can serve the assets from somewhere else:
#
#     docker build --build-arg AFORGE_BASE_URL=... --build-arg AFORGE_VERSION=... .
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS aforge

ARG AFORGE_BASE_URL=https://agentfield.ai/downloads/aforge
ARG AFORGE_VERSION=v0.1.0
ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl && \
    rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    arch="${TARGETARCH:-$(dpkg --print-architecture)}"; \
    mkdir -p /out; \
    cd /out; \
    curl -fsSL "${AFORGE_BASE_URL}/${AFORGE_VERSION}/aforge-linux-${arch}.gz" -o aforge.gz; \
    gunzip -c aforge.gz > aforge; \
    rm aforge.gz; \
    curl -fsSL "${AFORGE_BASE_URL}/${AFORGE_VERSION}/checksums.txt" -o checksums.txt; \
    grep " aforge-linux-${arch}$" checksums.txt | sed 's/  aforge-linux-.*/  aforge/' > aforge.sha256; \
    test -s aforge.sha256; \
    sha256sum -c aforge.sha256; \
    rm checksums.txt aforge.sha256; \
    chmod +x aforge


# ---------------------------------------------------------------------------
# Stage 1 — builder: fetch modules from the proxy, build the static binary.
# Go 1.23 satisfies go.mod's `go 1.21` directive.
# ---------------------------------------------------------------------------
FROM golang:1.23-bookworm AS builder

WORKDIR /src

# Prime the module cache from go.mod/go.sum first so dependency downloads cache
# independently of source edits (this layer re-runs only when go.mod/go.sum change).
COPY go/go.mod go/go.sum ./
RUN go mod download

# Copy the rest of the module and build a static binary.
COPY go/ ./
ENV CGO_ENABLED=0 GOOS=linux
RUN go build -trimpath -ldflags="-s -w" -o /out/cloudsecurity-af ./cmd/cloudsecurity-af


# ---------------------------------------------------------------------------
# Stage 2 — runtime: slim Debian mirroring the Python image (opencode CLI + a
# non-root cloudsecurity user), but shipping the single static Go binary instead
# of a Python runtime. The entrypoint generates opencode.json at container start
# from CLOUDSECURITY_MODEL, falling back to HARNESS_MODEL and then to the image
# default — config.py's precedence chain — so the model env vars are honoured
# (the Python image bakes a fixed opencode.json instead). Note that
# HARNESS_MODEL is already set below, so CLOUDSECURITY_MODEL is the variable to
# reach for when overriding the model for a running container.
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

ARG OPENCODE_VERSION=1.17.15

ENV AGENTFIELD_SERVER=http://agentfield:8080 \
    HARNESS_PROVIDER=aforge \
    AGENTFIELD_AFORGE_COMMAND=exec \
    HARNESS_MODEL=openrouter/moonshotai/kimi-k2.5 \
    AI_MODEL=openrouter/moonshotai/kimi-k2.5 \
    PORT=8015 \
    NODE_ID=cloudsecurity \
    HOME=/home/cloudsecurity \
    PATH=/home/cloudsecurity/.opencode/bin:${PATH} \
    XDG_DATA_HOME=/home/cloudsecurity/.local/share

# XDG_DATA_HOME IS set here, and the Python image does NOT set it — a deliberate
# packaging difference, recorded as divergence 6 in go/README.md.
#
# config.py::provider_env / internal/config.ProviderEnv both read the variable
# and fall back to `<tmpdir>/opencode-shared-data`, so the Python container puts
# the harness's data home somewhere container-local that a restart throws away.
# Pointing it at the cloudsecurity user's home (created and chowned below, and
# backed by the named volume `opencode-data` in docker-compose.go.yml) keeps
# that state across restarts. The node CODE is unchanged; only the image is.

# SEC_AF_WORKSPACES_DIR is deliberately NOT set here.
#
# app.py::_workspaces_root only takes the explicit branch when the variable is
# truthy; otherwise it mkdir's /workspaces, WRITE-PROBES it with a .write_test
# file and falls back to ~/.sec-af/workspaces on OSError. The Python image and
# the Python compose both leave it unset, so that fallback is live for them.
# docker-compose.go.yml bind-mounts a HOST directory onto /workspaces, and a
# bind does not inherit the image's `chown cloudsecurity /workspaces` — it
# arrives owned by the host uid (root when Docker auto-creates ./workspaces).
# Baking the variable skipped the probe, so every remote repo_url clone failed
# with a permission error and surfaced as HTTP 500 where the Python stack on the
# same bind silently fell back and succeeded.

# System deps: ca-certificates (HTTPS to the LLM/cloud providers), curl
# (healthcheck + opencode installer), git (repo_url clones in _resolve_repo).
# Create the non-root cloudsecurity user (uid/gid 10001) and install the
# opencode CLI as that user so it lands under /home/cloudsecurity/.opencode.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git && \
    groupadd --gid 10001 cloudsecurity && \
    useradd --uid 10001 --gid cloudsecurity --create-home --home-dir /home/cloudsecurity --shell /bin/sh cloudsecurity && \
    su -s /bin/sh cloudsecurity -c "curl -fsSL https://opencode.ai/install | bash -s -- --version ${OPENCODE_VERSION} --no-modify-path" && \
    mkdir -p /workspaces /home/cloudsecurity/.local/share && \
    chown -R cloudsecurity:cloudsecurity /workspaces /home/cloudsecurity && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/cloudsecurity-af /usr/local/bin/cloudsecurity-af
COPY --from=aforge /out/aforge /usr/local/bin/aforge
COPY go/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

USER cloudsecurity
# Cwd must be writable by the cloudsecurity user: the recon agents write their
# inventory/graph into per-run temp dirs, and the AgentField Go SDK creates its
# schema output dir under the process cwd when a harness call carries no Cwd.
# `/` is root-owned, and $HOME is cloudsecurity-owned in the image AND cannot be
# replaced by a compose bind the way /workspaces is.
WORKDIR /home/cloudsecurity

EXPOSE 8015

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8015}/health || exit 1

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["/usr/local/bin/cloudsecurity-af"]
