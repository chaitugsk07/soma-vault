# CLAUDE.md

Behavioral guidelines to reduce common LLM coding mistakes. Merge with project-specific instructions as needed.

**Tradeoff:** These guidelines bias toward caution over speed. For trivial tasks, use judgment.

## 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:
```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.

## 5. Ponytail — Lazy Senior Dev Mode (always on)

**You are a lazy senior developer. Lazy means efficient, not careless. The best code is the code never written.**

Before writing any code, stop at the first rung that holds:

1. Does this need to be built at all? (YAGNI)
2. Does the standard library already do this? Use it.
3. Does a native platform feature cover it? Use it.
4. Does an already-installed dependency solve it? Use it.
5. Can this be one line? Make it one line.
6. Only then: write the minimum code that works.

Rules:

- No abstractions that weren't explicitly requested.
- No new dependency if it can be avoided.
- No boilerplate nobody asked for.
- Deletion over addition. Boring over clever. Fewest files possible.
- Question complex requests: "Do you actually need X, or does Y cover it?"
- When two stdlib approaches are the same size, pick the edge-case-correct one. Lazy means less code, not the flimsier algorithm.
- Mark intentional simplifications with a `ponytail:` comment. If the shortcut has a known ceiling (global lock, O(n²) scan, naive heuristic), the comment names the ceiling and the upgrade path.

**Not lazy about:** input validation at trust boundaries, error handling that prevents data loss, security, accessibility, the calibration real hardware needs (the platform is never the spec ideal — a clock drifts, a sensor reads off), and anything explicitly requested. Lazy code without its check is unfinished: non-trivial logic leaves ONE runnable check behind — the smallest thing that fails if the logic breaks (an assert-based demo/self-check or one small test file; no frameworks, no fixtures). Trivial one-liners need no test.

## 6. gstack — Automatic Skill Selection

Use gstack skills as needed — the system determines which to run from *what you're building*, without being told the skill name:

- **End-user products:** `/plan-design-review` (before) → `/design-review` (after)
- **Developer tools:** `/plan-devex-review` (before) → `/devex-review` (after)
- **Architecture:** `/plan-eng-review` (before) → `/review` (after)
- **Everything:** `/autoplan` auto-detects the applicable reviews and surfaces only taste decisions needing approval.

Other gstack skills (auto-routed by intent): `/office-hours`, `/spec`, `/design-shotgun`, `/design-html`, `/qa`, `/investigate`, `/ship`, `/land-and-deploy`.

## 7. Global Rules (always apply)

The global rules in `~/.claude/CLAUDE.md` and their skills apply to every change in this repo — they are the source of truth, do not duplicate them here:

- **Rust — `/rust-skills`**: 179 rules across 14 categories (ownership, error handling, async, API design, memory, performance, testing, anti-patterns). ALL Rust written, reviewed, or refactored here must follow these. Consult before and during any Rust work.
- **Ponytail** (§5): the lazy-senior-dev ladder for every line; review the diff with `/ponytail-review` and the repo with `/ponytail-audit` after building.
- **gstack workflow** (§6): plan review up front for non-trivial features, `/review` before a PR, `/design-review` for UI.
- **db-standards — `/db-standards`**: if/when this project talks to a database.
- **humanizer — `/humanizer`**: applied to any user-facing prose or narration.

## 8. This Project — soma-vault

**soma-vault is a cloud-native secrets *and* configuration platform.** One place to manage both encrypted **secrets** (API keys, DB credentials, tokens, certificates) and application **config** (typed, non-sensitive values with per-environment overrides) for an organization's services. It ships as **both a managed cloud SaaS and a self-host single binary** from day one, under **open-core** licensing (OSS core + self-host; advanced/enterprise capabilities and the managed cloud are paid).

North star: **extremely low memory/CPU and memory-safe** — async Rust (axum + tokio) on **PostgreSQL** (the only datastore), targeting a sub-20 MB idle footprint and compile-time memory-safety guarantees. With a **Leptos** dashboard and first-class **CLI + SDKs**. Target indie devs and startups first (Doppler/Infisical/Replane-grade DX), credible for enterprise later.

It is part of the **soma-platform** suite and is a SEPARATE product from **soma-iam** (the suite's IAM). soma-vault does **not** reimplement identity: human users, organizations, RBAC, and identity-level audit come from soma-iam; soma-vault authenticates and authorizes principals against it. soma-iam isn't built yet, so the contract soma-vault needs from it is something we define here as a requirement.

### Non-negotiable tenets (designed in from day one)

- **Multi-tenant, multi-workspace.** Hierarchy `tenant/org → workspace → project → environment → secret|config`. Every row is tenant-scoped; no query crosses a tenant boundary.
- **Kubernetes/HPA-native, stateless pods.** A pod comes up ready with **no human unseal and no unseal secret handed to it**. soma-vault pods prove their identity to a KMS and the key is unwrapped for them — no pre-shared unseal secret ever touches a pod. Pods scale to N and back to 1 with zero coordination.
- **Auto-unseal by workload identity, never a shared secret.** The root key is wrapped by an external **KMS** (AWS / GCP / Azure). On boot a pod proves its **identity** (K8s projected ServiceAccount token → IRSA / GKE Workload Identity / Azure Workload Identity / SPIFFE-SPIRE) and the KMS unwraps it. The pod holds an identity, never persistent key material. Self-host without a cloud KMS gets a documented software-KMS / age fallback.
- **Envelope encryption end to end.** Per-secret DEK; AEAD ciphertext + wrapped DEK live in Postgres; plaintext keys exist in pod memory only for the active request, then are zeroized. A Postgres dump is useless without KMS access.
- **Secrets ≠ config at the schema level.** Config is typed, schema-validated, loggable, delivered in real time (SSE + in-process SDK cache, not polling), and may hold a `$ref` to a secret; secret values never inline into config responses.
- **Two identity planes, never conflated.** **App principals** (humans / service accounts) authenticate via **soma-iam**; soma-vault's own **pods** authenticate to the **KMS** via cloud **workload identity** for auto-unseal.

### Stack & layout

- **Rust workspace** under `crates/` (provisional, finalized in `docs/`): an axum/tokio API server, a crypto/seal crate, a Postgres storage crate (`sqlx`), and the CLI. Plain-Postgres-portable schema per **`/db-standards`** (snake_case, UUID/text PKs, `created_at`/`updated_at`, no vendor-specific SQL; tenant isolation enforced in the access layer). Latest stable crates via `cargo add` — never pin a version in this file; let `Cargo.lock` be the source of truth.
- **Dashboard** — Leptos (CSR), reusing **soma-ui** components and the Palantir slate/blue light+dark theme.
- **SDKs** — Rust first, then TypeScript/Python; injection CLI (`soma run -- <cmd>`, `.env` export) for Doppler-grade onboarding.
- **Verify:** `cargo check --workspace` (+ `cargo test`); migrations are plain SQL.

### Source of truth

The full PRD lives under **`docs/`** — vision/positioning, Phase-1 scope, architecture + crypto/auto-unseal, REST API, data model + soma-iam boundary, config management, CLI/SDK, dashboard, Kubernetes/cloud-native deployment, pricing/licensing, roadmap, and competitive/domain appendices. Keep `docs/` and this section in sync. Apply **YAGNI**: smallest credible Phase 1, with the tenets above as the foundation.

### Shared components — consume soma-infra, do NOT re-implement plumbing

Platform-wide rule: `../CLAUDE.md` ("Shared components"). As it applies to soma-vault:

- **All reusable backend plumbing comes from `soma-infra`** (`../soma-infra`, path dep). Already consumed for: Postgres pool (`soma_infra::connect_from_env`), telemetry (`telemetry::init`), graceful shutdown (`signal::shutdown_signal`), crypto primitives (`crypto::hkdf_sha256` / `hmac_sha256_hex` / `sha256_hex`), env helpers (`config::env_or`), SDK/CLI HTTP client (`http::client`). All UI comes from `soma-ui`.
- **Do NOT hand-roll** a Postgres pool, a `tracing_subscriber` init, a `shutdown_signal`, an `Hkdf`/`Hmac`/`Sha256`-to-hex, an AEAD encrypt/Argon2 hash, or a `reqwest::Client` builder. Need a primitive soma-infra lacks? Add the generic primitive there (vault supplying its own parameters), not a local copy.
- **Stays in soma-vault (logic, correctly local):** the 3-layer envelope/KEK scheme + AES-KW wrapping in `soma-crypto`; the HKDF salt/info strings (`"soma-vault-tenant-kek-v1"`, `"soma-vault-audit-hmac-v1"`) passed *into* the infra primitive; `MasterKek::from_hex`; `map_sqlx` (SQLSTATE → domain errors incl. `WhitelistViolation`); the `Migrator` wiring (schema `01_vault`, its advisory lock key). The short root-token fingerprint `hex::encode(&digest[..4])` is NOT `sha256_hex` — leave it.

---

**These guidelines are working if:** fewer unnecessary changes in diffs, fewer rewrites due to overcomplication, and clarifying questions come before implementation rather than after mistakes.