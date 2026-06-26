# soma-vault

[![CI](https://github.com/chaitugsk07/soma-vault/actions/workflows/ci.yml/badge.svg)](https://github.com/chaitugsk07/soma-vault/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square)](LICENSE)

**Stop committing `.env` files.** soma-vault keeps your secrets and config out of the repo and injects them into your app at runtime — so they can't be committed, shared over Slack, or pulled into an AI agent's context window.

Secrets and typed configuration management in a single async Rust binary — low memory footprint, memory-safe, and designed for stateless Kubernetes pods that scale without manual unseal steps.

---

## What it is

soma-vault stores two things in one place:

- **Secrets** — API keys, credentials, tokens, and certificates. Each value is envelope-encrypted (AES-GCM per-secret DEK, AES-KW-wrapped master key). A Postgres dump without the master key is useless.
- **Typed config** — non-sensitive application settings with per-environment overrides. Values are schema-validated, version-tracked, and exportable as dotenv or JSON.

Both are organized in a three-level hierarchy: **project → environment → secret|config**.

The server, the admin portal, and the migration runner ship as one binary. There are no sidecars, no agents to install, and no manual unseal on startup — the binary reads `SOMA_MASTER_KEK_HEX` from the environment and is ready immediately. Cloud-KMS auto-unseal via workload identity (AWS IRSA / GCP / Azure) is on the roadmap; see the Status section below.

---

## Status

soma-vault is at **v0.x** (Phase-1 lean MVP). The core is working and tested.

### Works today

- Envelope-encrypted secrets with a full version ledger
- Typed config (string, number, boolean, JSON) with a version ledger
- Three-level hierarchy: project → environment → secret|config
- EAV attribute registry, managed through the admin portal
- Bearer-token and cookie authentication
- `soma init` — interactive wizard: picks a project and environment, writes `.soma.toml` to the current directory
- `soma import <file>` — parses a `.env` file, uploads each key as a secret, then offers to delete the file and add it to `.gitignore`
- `soma run -- <your-command>` — injects secrets and config as environment variables into a child process (project/env from `.soma.toml` or `--project`/`--env` flags)
- `soma export` — produces a dotenv or JSON snapshot of an environment
- Admin portal with 8 screens (embedded Leptos dashboard, served at `/`)
- Migrate-on-boot via the [`soma-schema`](https://github.com/chaitugsk07/soma-schema) runner

### On the roadmap (not yet built)

- Multi-tenant auth and soma-iam integration
- RBAC
- HMAC-chained audit log
- Cloud-KMS auto-unseal (AWS IRSA / GCP Workload Identity / Azure Workload Identity)
- Dynamic secrets
- TypeScript and Python SDKs
- Marketing and documentation sites

---

## Quickstart (60 seconds)

### Local — Docker

```sh
# 1. Generate a master key and start the stack
echo "SOMA_MASTER_KEK_HEX=$(docker run --rm ghcr.io/chaitugsk07/soma-vault soma keygen)" > deploy/.env
docker compose -f deploy/docker-compose.yml up -d

# 2. Find the root token printed to stderr on first boot
docker compose -f deploy/docker-compose.yml logs soma-vault 2>&1 | grep -A1 "ROOT TOKEN"

# 3. Log in, pick a project and environment, kill your .env
soma login --server http://localhost:8080 --token <token>
soma init
soma import .env       # uploads secrets, offers to delete .env and add it to .gitignore

# 4. Run your app with secrets injected — no .env file needed
soma run -- node server.js
```

On first boot the server prints the root token to stderr in a banner and writes it to `/tmp/soma-root-token` (mode 0600) inside the container. It is shown only once.

### Kubernetes

```sh
helm install soma-vault ./deploy/helm
```

The root token location is printed in the post-install notes (`helm install` output).

---

## Security model

Secrets are envelope-encrypted: each value gets its own AES-256-GCM DEK, and the DEK is AES-KW-wrapped under the master key. A Postgres dump without the master key is useless.

In the current MVP the master key is `SOMA_MASTER_KEK_HEX` — a hex string you supply at startup. Treat it as a root secret. Anyone with both the Postgres data and this key can decrypt everything, so keep it out of your repo, your CI logs, and the same backup location as your database dumps.

Cloud-KMS auto-unseal (AWS IRSA / GCP Workload Identity / Azure Workload Identity) is on the roadmap. When that lands, pods will prove their identity to the KMS and unwrap the key themselves — no pre-shared secret handed to the process.

To find secrets already committed to your git history, use [gitleaks](https://github.com/gitleaks/gitleaks); soma-vault is where they go once you've found them.

---

## Architecture

soma-vault is a Rust workspace under `crates/` plus a separate `dashboard/` crate:

| Crate | Role |
| --- | --- |
| `soma-crypto` | Envelope encryption: AES-GCM DEKs, AES-KW key wrapping, zeroize on drop |
| `soma-storage` | Postgres access layer (`sqlx`), `DataStore` trait, EAV schema |
| `soma-api` | axum router, request handlers, auth middleware |
| `soma-cli` | `soma` binary: `init`, `import`, `run`, `export`, `keygen`, `login`, CRUD subcommands |
| `soma-server` | Entry point: wires crates together, serves embedded portal, runs migrations on boot |
| `dashboard` | Leptos (CSR) admin portal, embedded into `soma-server` at compile time |

The server depends on three sibling crates from the soma-platform suite:

- [`soma-schema`](https://github.com/chaitugsk07/soma-schema) — the migration runner (migrate-on-boot, advisory-locked, full-file checksum drift detection)
- [`soma-ui`](https://github.com/chaitugsk07/soma-ui) — shared Leptos components (Palantir slate/blue light+dark theme)
- [`soma-infra`](https://github.com/chaitugsk07/soma-infra) — shared utilities (pool config, telemetry, testing helpers)

All four repos must be checked out side by side under the same parent directory. See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## How it compares

HashiCorp Vault is the reference for depth and ecosystem; Doppler set the bar for developer experience; Infisical demonstrated that an open-source secrets product can be both approachable and enterprise-ready. soma-vault's focus is different: a single memory-safe binary written in async Rust, with secrets and typed config in one place, and pods that scale horizontally without any manual unseal ceremony. It is not trying to replace those products — if you need Vault's full plugin ecosystem today, use Vault. soma-vault is for teams that want lower operational overhead and a smaller footprint. See [`docs/appendix-competitive-analysis.md`](docs/appendix-competitive-analysis.md) for a detailed side-by-side.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for dev setup, build commands, and the PR process.

---

## License

The core is licensed under **Apache-2.0**. See [LICENSE](LICENSE).

The managed cloud service and advanced enterprise capabilities are commercial. The OSS core (this repository) will always remain Apache-2.0.
