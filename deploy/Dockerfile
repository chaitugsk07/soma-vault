# syntax=docker/dockerfile:1
# Build context: the soma-platform parent directory.
# Build command (from soma-platform/):
#   docker build -f soma-vault/deploy/Dockerfile -t soma-vault:dev .
#
# The build context must include all four sibling repos because soma-vault
# depends on them via Cargo path deps:
#   ../soma-schema          (workspace dep in Cargo.toml)
#   ../soma-ui/web/packages/ui  (dashboard dep)
#   ../../../soma-infra     (relative to crates/*, resolves to sibling)

# ── Stage 1: builder ──────────────────────────────────────────────────────────
# Match the base image to what rust-toolchain.toml resolves to (channel="stable")
# so rustup does NOT re-download a whole toolchain on every build. A mismatch here
# triggers a multi-hundred-MB toolchain fetch from static.rust-lang.org per build
# (slow and flaky in CI/containers). Bump this in lockstep with stable.
FROM rust:1.96-bookworm AS builder

# Network resilience for cargo: the sparse index fetches only the index entries
# it needs (far fewer requests than the old git index), and the retry/timeout
# knobs tolerate a flaky crates.io CDN instead of failing the build on the first
# slow transfer.
ENV CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse \
    CARGO_NET_RETRY=10 \
    CARGO_NET_TIMEOUT=120 \
    CARGO_HTTP_TIMEOUT=120 \
    CARGO_HTTP_LOW_SPEED_LIMIT=0

# System deps needed by sqlx / openssl / etc.
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install trunk for the dashboard WASM bundle.
# Pin to a known-good release to keep builds reproducible.
RUN cargo install trunk --locked --version 0.21.14

# Copy all four repos into /build, preserving the relative layout that the
# path deps in Cargo.toml and dashboard/Cargo.toml expect.
#
#   /build/soma-vault          ← this repo
#   /build/soma-schema         ← ../soma-schema
#   /build/soma-ui             ← ../soma-ui   (dashboard dep: ../../soma-ui/…)
#   /build/soma-infra          ← ../../../soma-infra   (crates/ dep)
#
# We copy manifests first so that Cargo can resolve the dependency graph
# and Docker can cache the dependency-download layer separately.

# ── manifests only (layer-cache layer) ────────────────────────────────────────
COPY soma-vault/Cargo.toml soma-vault/Cargo.lock /build/soma-vault/
COPY soma-vault/crates/soma-api/Cargo.toml      /build/soma-vault/crates/soma-api/
COPY soma-vault/crates/soma-cli/Cargo.toml      /build/soma-vault/crates/soma-cli/
COPY soma-vault/crates/soma-crypto/Cargo.toml   /build/soma-vault/crates/soma-crypto/
COPY soma-vault/crates/soma-server/Cargo.toml   /build/soma-vault/crates/soma-server/
COPY soma-vault/crates/soma-storage/Cargo.toml  /build/soma-vault/crates/soma-storage/
COPY soma-vault/crates/soma-sdk/Cargo.toml      /build/soma-vault/crates/soma-sdk/
COPY soma-vault/dashboard/Cargo.toml            /build/soma-vault/dashboard/
COPY soma-vault/rust-toolchain.toml             /build/soma-vault/

# Add the wasm target AFTER copying rust-toolchain.toml so rustup applies it
# to the toolchain version the project actually requires (not the image default).
# The toolchain file triggers a rustup channel sync on first cargo invocation;
# adding the target here ensures it lands on the right toolchain.
RUN cd /build/soma-vault && rustup target add wasm32-unknown-unknown

# Sibling manifests.
COPY soma-schema/Cargo.toml soma-schema/Cargo.lock /build/soma-schema/
COPY soma-infra/Cargo.toml soma-infra/Cargo.lock /build/soma-infra/
COPY soma-ui/web/packages/ui/Cargo.toml             /build/soma-ui/web/packages/ui/

# Stub out every lib/main so `cargo fetch` (and the first cargo build) can
# download and compile all dependencies without needing the real source.
RUN bash -c '\
  set -e; \
  for f in \
    /build/soma-vault/crates/soma-api/src/lib.rs \
    /build/soma-vault/crates/soma-cli/src/main.rs \
    /build/soma-vault/crates/soma-crypto/src/lib.rs \
    /build/soma-vault/crates/soma-server/src/main.rs \
    /build/soma-vault/crates/soma-storage/src/lib.rs \
    /build/soma-vault/crates/soma-sdk/src/lib.rs \
    /build/soma-vault/dashboard/src/main.rs; \
  do \
    mkdir -p "$(dirname $f)"; \
    echo "fn main() {}" > "$f"; \
  done; \
  for f in \
    /build/soma-schema/src/lib.rs \
    /build/soma-infra/src/lib.rs \
    /build/soma-ui/web/packages/ui/src/lib.rs; \
  do \
    mkdir -p "$(dirname $f)"; \
    echo "" > "$f"; \
  done \
'

# Pre-fetch/compile workspace deps.  The subsequent full COPY will replace the
# stubs and invalidate this layer only if manifests changed.
WORKDIR /build/soma-vault
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo fetch

# ── full source copy ───────────────────────────────────────────────────────────
COPY soma-vault/  /build/soma-vault/
COPY soma-schema/ /build/soma-schema/
COPY soma-infra/ /build/soma-infra/
COPY soma-ui/     /build/soma-ui/

# ── build portal (trunk outputs to dashboard/dist/) ───────────────────────────
# The dashboard is a SEPARATE cargo project (the root workspace excludes it), so
# the earlier `cargo fetch` did not download its deps. The shared registry cache
# mount lets a partial fetch survive a retry, so a flaky crates.io doesn't fail
# the whole build. The retry loop covers transient CDN 5xx/timeouts.
WORKDIR /build/soma-vault/dashboard
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    for i in 1 2 3 4 5; do cargo fetch && break || sleep 10; done
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    trunk build --release

# ── build server + CLI binaries ───────────────────────────────────────────────
WORKDIR /build/soma-vault
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo build --release -p soma-server -p soma-cli

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

# ca-certificates: needed for TLS outbound calls (e.g. KMS endpoints).
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 soma \
    && useradd --uid 10001 --gid soma --no-create-home --shell /sbin/nologin soma

# Copy the server binary and the CLI binary.
# The CLI is also required in the image so `docker run ... soma keygen` works.
COPY --from=builder /build/soma-vault/target/release/soma-server /usr/local/bin/soma-server
COPY --from=builder /build/soma-vault/target/release/soma /usr/local/bin/soma

# soma-storage embeds the migrations path at compile time as:
#   concat!(env!("CARGO_MANIFEST_DIR"), "/../../migrations")
# which expands to the literal string:
#   /build/soma-vault/crates/soma-storage/../../migrations
#
# On Linux, the kernel resolves ".." by traversing real directories, so
# /build/soma-vault/crates/soma-storage/ must exist for the ".." component
# to resolve.  We create the directory and copy migrations to their
# normalised location so the path resolves correctly at runtime.
RUN mkdir -p /build/soma-vault/crates/soma-storage
COPY --from=builder /build/soma-vault/migrations /build/soma-vault/migrations

WORKDIR /app

# The server writes the root token to ./soma-root-token (relative to CWD=/app)
# on first boot.  Make /app writable by the non-root runtime user so the write
# succeeds.  Alternatively, set SOMA_TOKEN_FILE to /tmp/soma-root-token.
RUN chown 10001:10001 /app

# Runtime defaults.  Callers MUST supply:
#   DATABASE_URL          – Postgres connection string
#   SOMA_MASTER_KEK_HEX   – 64-char hex master key (generate with: soma keygen)
#
# SOMA_COOKIE_SECURE should be "true" when behind TLS (default in server code).
ENV SOMA_BIND=0.0.0.0:8080

USER 10001
EXPOSE 8080

ENTRYPOINT ["soma-server"]
