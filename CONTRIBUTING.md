# Contributing to soma-vault

Thank you for your interest in contributing. This document covers how to get set up, build the project, run tests, and submit changes.

## Prerequisites

- **Rust stable** — install via [rustup](https://rustup.rs/)
- **wasm32 target** — required to build the dashboard:
  ```sh
  rustup target add wasm32-unknown-unknown
  ```
- **trunk** — the Leptos/WASM bundler:
  ```sh
  cargo install trunk
  ```
- **Docker** — used to run the test Postgres instance:
  ```sh
  docker compose -f deploy/docker-compose.yml up -d
  ```

## Sibling path dependencies

soma-vault depends on three sibling crates by path. They must be checked out **next to** this repo, all under the same parent directory:

```
parent/
  soma-vault/       ← this repo
  soma-schema/      ← https://github.com/chaitugsk07/soma-schema
  soma-ui/          ← https://github.com/chaitugsk07/soma-ui
  soma-infra/       ← https://github.com/chaitugsk07/soma-infra
```

`cargo build` will fail with a "path not found" error if any sibling is missing.

## Build and check

```sh
# Type-check the whole workspace
cargo check --workspace

# Format check
cargo fmt --all --check

# Lint (all warnings are errors in CI)
cargo clippy --workspace --all-targets -- -D warnings

# Run tests (requires a running Postgres — see above)
TEST_DATABASE_URL=postgres://soma:soma@localhost:5432/soma_vault \
  cargo test --workspace

# Build the dashboard (outputs to dashboard/dist/)
cd dashboard && trunk build
```

The CI workflow (`.github/workflows/ci.yml`) runs all of the above. A PR cannot be merged unless all checks pass.

## UI components

New UI components go into `soma-ui`, not into the `dashboard` crate. The dashboard imports from `soma-ui` so that components stay reusable across the soma-platform suite. If a component is genuinely dashboard-specific, discuss it in the issue first.

## Pull request process

1. Fork the repository and create a branch from `main`.
2. Make your changes. If you are adding or changing behaviour, add or update tests.
3. Run the checks above locally before opening a PR.
4. Open a pull request against `main` with a clear description of what changes and why.
5. A maintainer will review and may request changes before merging.

For significant features or design changes, open an issue first to discuss the approach before writing code.

## Code of conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). Please read it before participating.
