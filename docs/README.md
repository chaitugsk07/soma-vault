# soma-vault

soma-vault is a cloud-native, multi-tenant platform for managing both encrypted secrets (API keys, credentials, certificates, tokens) and typed application configuration (schema-validated, non-sensitive values with per-environment inheritance and real-time delivery). It ships as a single self-hosting binary (Rust, axum, Postgres) and as a managed SaaS. The design goals: a sub-20 MB idle memory footprint, full Rust memory safety, zero operational ceremony, and a developer experience that matches Doppler and Infisical — with stateless pods, workload-identity auto-unseal, and a Postgres-only data tier.

---

## North Star

**Lean, memory-safe, trivial to operate.** A single statically linked Rust binary, one Postgres database, and a cloud KMS are all an operator needs. Pods are stateless and scale under HPA with no coordination. There is no unseal ceremony, no Raft quorum to manage, and no second stateful dependency. Every secret is envelope-encrypted end-to-end; a Postgres dump is cryptographically useless without KMS access. Config and secrets are separated at the schema level, not just the UI, enabling safe audit logging, safe real-time push, and typed schema validation — capabilities that cannot be retrofitted onto a unified-blob data model without a full migration.

---

## Five Non-Negotiable Tenets

These are load-bearing architectural requirements. Retrofitting any of them after launch is infeasible.

| # | Tenet | What it means in practice |
|---|-------|---------------------------|
| 1 | **Multi-tenant, multi-workspace** | Hard tenant isolation. Every row carries `tenant_id UUID NOT NULL`. Postgres RLS as a defense-in-depth backstop. No cross-tenant read or write is possible at the data layer. |
| 2 | **Stateless, HPA-native pods** | Kubernetes `Deployment`, never `StatefulSet`. No PVCs, no Raft, no per-pod state. Any pod serves any request. HPA scales freely. |
| 3 | **Auto-unseal by workload identity** | The root KEK is wrapped by a cloud KMS (AWS KMS via IRSA; GCP/Azure in Phase 2). Pods prove their identity; the KMS unwraps the key. No shared unseal secret ever touches a pod. |
| 4 | **Envelope encryption end-to-end** | Per-secret-version DEK (AES-256-GCM), wrapped DEK and ciphertext stored in Postgres. Plaintext DEK lives in pod RAM only for the active request, then is zeroized. A DB dump without KMS access reveals nothing. |
| 5 | **Secrets and config are separate at the data model** | `secrets` / `secret_versions` tables have no typed-value columns. `config_keys` / `config_versions` tables have no ciphertext columns. The schema makes conflation structurally impossible — not just policy-forbidden. |

---

## Target Users and Positioning

**Primary:** indie developers and early-stage startups who need Doppler/Infisical-grade developer experience (one-command CLI, env-var injection, real-time config push, fast onboarding) with a credible self-host story and pricing that treats machine identities generously — not as a per-unit cost that grows with every K8s service account or CI pipeline.

**Secondary:** platform engineering teams at growth-stage companies who need the operational simplicity of a managed SaaS with an open-source self-host fallback for regulated or air-gapped environments.

**Future:** enterprises requiring SOC 2, FedRAMP, dynamic secrets, PKI, and multi-region HA.

### Positioning vs. Main Competitors

| Competitor | Where soma-vault differs | soma-vault's answer |
|------------|--------------------------|---------------------|
| HashiCorp Vault / OpenBao | StatefulSet + Raft optimizes for strong consistency, not HPA elasticity; manual unseal is the CE default; no typed config; 200–400 MB idle RSS; multi-tenancy is Enterprise-only | Stateless Deployment, workload-identity auto-unseal, first-class typed config, <20 MB idle, multi-tenancy in OSS core |
| Infisical | Static env-var root key at pod startup; no typed config; no real-time push; per-machine-identity billing adds up quickly for teams with many K8s service accounts | KMS workload-identity unseal; separate typed config tier with SSE push; machine identities bundled generously |
| Doppler | No per-secret DEKs; no typed schema; no self-host OSS; K8s Operator bootstraps via a service token rather than workload identity | Per-secret envelope encryption; schema-validated typed config; open-core single binary; IRSA workload identity for Operator |
| AWS Secrets Manager | AWS-only; no typed config; no env injection CLI; per-secret pricing creates incentives against good hygiene | Cloud-agnostic; unified secrets+config; `soma run -- cmd`; flat per-seat pricing |
| Replane | Config-only, no encryption, no secrets | Full secrets+config in one platform; envelope encryption; same real-time SSE push model |
| Akeyless | SaaS-only; no config management; opaque pricing; path-based folder RBAC rather than row-level tenant isolation | Open-core self-host; hard row-level tenant isolation; transparent pricing |

---

## soma-platform and soma-iam Relationship

soma-vault is one product in the soma-platform suite. **It does not own identity.**

There are two distinct identity planes:

- **Application principals** (human users, service accounts, CI agents) authenticate via **soma-iam**. soma-vault validates soma-iam-issued RS256/ES256 JWTs at login, issues its own short-lived session tokens for the hot path, and never calls soma-iam on every secret read. This decouples soma-vault read availability from soma-iam availability.

- **soma-vault's own pods** authenticate to the KMS via **cloud workload identity** (Kubernetes projected ServiceAccount JWT → AWS STS IRSA, GKE Workload Identity, Azure Workload Identity). This is the auto-unseal plane and is entirely separate from the application identity plane.

soma-iam does not yet exist. soma-vault defines the contract soma-iam must satisfy: an OIDC discovery endpoint, a JWKS endpoint, and short-lived JWTs carrying `sub` (principal UUID), `tid` (tenant UUID), `roles[]`, and `aud == ["soma-vault"]`. soma-iam is built to satisfy that contract; soma-vault is the source of truth for the requirement.

---

## Phase 1 Scope (in brief)

Phase 1 ships when a solo developer can deploy soma-vault on EKS or bare metal in under 10 minutes, run `soma run -- node server.js`, and demonstrate that a Postgres dump without KMS access reveals nothing. All five tenets must be demonstrably working on day one.

**Included in Phase 1:**

- Multi-tenant Postgres schema: 5-level hierarchy (tenant → workspace → project → environment → secret | config), RLS + `TenantId` newtype compile-time enforcement
- Envelope encryption: 4-layer key hierarchy, AES-256-GCM, zeroize-on-drop, per-secret-version DEK
- KMS auto-unseal via AWS IRSA with circuit-breaker grace period (default 30 min); software-KMS (age) fallback for self-host without cloud KMS
- Separate secrets and config table families with schema-enforced sensitivity split
- Typed config (string | int | float | bool | json | secret_ref) with write-time JSON Schema validation
- SSE real-time config delivery: tokio broadcast channel per (project, environment), Postgres LISTEN/NOTIFY cross-pod fan-out, DashMap SDK cache
- Environment inheritance (inherits_from FK, depth ≤ 3, child overrides win)
- RBAC + path-capability authorization, deny-by-default, Rust type-state compile-time enforcement
- soma-iam JWT integration with session-token exchange; Universal Auth (Argon2id) for local dev
- HMAC-SHA256 hash-chained audit log with `reason` field and `/audit/verify` endpoint
- Secret versioning: max_versions, soft-delete, destroy, CAS, single-version rollback
- Static secret rotation infrastructure: 4-stage lifecycle, SKIP LOCKED workers
- CLI: `soma run -- <cmd>`, `soma secrets export`, full CRUD for secrets and config
- Kubernetes Operator: SomaSecret CRD, native K8s Secret reconciliation, optional rolling restart
- Rust SDK: `secrets.get()` → `Secret<String>`, `config.get::<T>()`, SSE background cache
- Leptos CSR web dashboard: CRUD, version history, audit log viewer, service account management
- Single-binary self-host + Helm chart: Deployment, ServiceAccount with IRSA annotation, HPA, PDB

**Explicit Phase 1 non-goals:** dynamic secrets, PKI/CA, Transit EaaS, GCP/Azure KMS backends, TypeScript/Python SDKs, SPIFFE/SPIRE, mutating admission webhook, external SIEM streaming, approval workflows, multi-region active-active, BYOK per project, Redis as any dependency.

---

## Open Questions for the Founder

1. **Pricing model:** Pro tier price point and machine-identity bundle size. Suggested starting point: $20/human seat/month with 25 machine identities included, then $2/month per additional. Needs founder validation before any public pricing page.

2. **soma-iam timeline:** soma-vault's dashboard login requires soma-iam to issue JWTs. Decision needed: (a) build a minimal stub soma-iam for Phase 1 development, or (b) ship Phase 1 CLI + Rust SDK only (Universal Auth, no dashboard login) until soma-iam is ready.

3. **Phase 1 rotation scope:** Should Phase 1 include at least one working rotation adapter (e.g., Postgres DB password rotation) to validate the rotation infrastructure end-to-end, or is the job table + worker loop + lifecycle state machine alone sufficient for the Phase 1 gate?

4. **Leptos vs. React for the dashboard:** Leptos is consistent with soma-ui and the Rust-only build toolchain but has a thin hiring pool. Next.js would iterate faster and attract more contributors but splits the toolchain. Founder-level decision with real timeline impact.

5. **Managed cloud infrastructure:** The managed SaaS assumes AWS EKS (IRSA is the Phase 1 KMS backend). Is AWS the primary cloud, or should the managed offering be multi-cloud from day one (which pulls GCP KMS and Azure Key Vault backends into Phase 1)?

6. **Open-core license:** MIT is most permissive but allows a competitor to fork and run a managed SaaS without contributing back. Apache 2.0 adds patent protection. BSL-1.1 (timed release) blocks direct SaaS competition near-term. Infisical uses MIT. This is a strategic moat decision requiring founder input.

7. **soma-iam JWT contract:** The exact JWT schema (`sub`, `tid`, `roles[]`, `aud` format, how machine identities are represented) must be jointly agreed between soma-vault and soma-iam design sessions. soma-vault specifies the requirements; soma-iam confirms satisfiability.

---

## Table of Contents

| Document | Description |
|----------|-------------|
| [01-vision-and-positioning.md](./01-vision-and-positioning.md) | Product vision, north star, differentiation thesis, and market positioning in detail |
| [02-phase-1-scope.md](./02-phase-1-scope.md) | Phase 1 feature list with includes/excludes/rationale per feature; explicit non-goals |
| [03-architecture.md](./03-architecture.md) | System architecture: component topology, request flow, stateless pod model, key hierarchy |
| [04-api.md](./04-api.md) | REST API reference: endpoints, auth, request/response shapes, error codes |
| [05-data-model.md](./05-data-model.md) | Postgres schema: DDL, RLS policies, indexes, tenant isolation strategy, migration runner |
| [06-config-management.md](./06-config-management.md) | Typed config tier: value types, JSON Schema validation, environment inheritance, SSE delivery, $ref model |
| [07-cli-sdk-dx.md](./07-cli-sdk-dx.md) | CLI reference (`soma run`, `soma secrets`, `soma config`), Rust SDK API, onboarding walkthrough |
| [08-dashboard.md](./08-dashboard.md) | Leptos CSR dashboard: screens, component breakdown, soma-ui integration, auth flow |
| [09-cloud-native-kubernetes.md](./09-cloud-native-kubernetes.md) | Kubernetes deployment: Helm chart, IRSA setup, HPA, PDB, SomaSecret CRD operator |
| [10-pricing-and-licensing.md](./10-pricing-and-licensing.md) | Open-core licensing model, free tier limits, Pro/Enterprise tiers, OSS vs. paid feature split |
| [11-roadmap.md](./11-roadmap.md) | Phase 1 / 2 / 3 roadmap with gate criteria; explicit non-goals across all phases |
| [appendix-competitive-analysis.md](./appendix-competitive-analysis.md) | Detailed competitor analysis: Vault, OpenBao, Infisical, Doppler, AWS SM, GCP SM, Akeyless, Bitwarden SM, Replane, Configu, AppConfig, Azure App Configuration, Consul KV |
| [appendix-domain-research.md](./appendix-domain-research.md) | Foundational research: envelope encryption patterns, workload identity models, Postgres RLS behavior, SSE delivery architectures, rotation lifecycle patterns |
