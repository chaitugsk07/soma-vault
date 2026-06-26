# Appendix: Competitive Analysis — Secrets Managers and Config Platforms

soma-vault sits at the intersection of two markets that have historically ignored each other: secrets management and application configuration. This appendix profiles thirteen competitors across both spaces, identifies what each does well, and draws explicit design conclusions for soma-vault. The analysis is based on documented architecture, pricing, and public source material as of mid-2026.

---

## HashiCorp Vault

**Category:** Secrets | **License:** BSL-1.1 (CE) / proprietary (Enterprise)

**Positioning.** The incumbent. Vault owns the enterprise secrets management mindset and has the deepest feature set in the category: dynamic secrets, PKI, Transit encryption-as-a-service, 15+ auth methods, and a mature HCL policy engine. IBM acquired HashiCorp for $6.4B in February 2025.

**Architecture.** Go runtime (~200–400 MB idle RSS per standby node, 2 GB+ active). Deployed as a Kubernetes StatefulSet with integrated Raft storage. Active/standby model: one node serves writes, standbys redirect. Read scale-out (Performance Standby Nodes) is Enterprise-only.

**Key and seal model.** Single barrier key (AES-256-GCM) encrypts all data in the storage backend. No per-secret DEKs. On boot, Vault is sealed; it cannot serve traffic until the unseal ceremony completes. Community Edition default: Shamir's Secret Sharing requires operators to supply threshold key shards on every pod restart. Auto-unseal (AWS KMS, GCP KMS, Azure Key Vault, HSM) is available and recommended for production, but even with auto-unseal the pod transitions through a sealed state and the Raft state machine still lives on a persistent volume.

**Multi-tenancy.** Namespaces are the isolation primitive, but they are Enterprise-only. Community Edition has no tenant isolation whatsoever.

**Cloud-native and HPA story.** StatefulSet with Raft explicitly conflicts with HPA. Adding or removing a replica requires coordinated Raft membership changes. True horizontal autoscaling is not supported.

**Config capabilities.** None. Vault is a secrets store only. KV engine stores opaque blobs with no type system, no environment inheritance, and no real-time push.

**Strengths.** Deepest dynamic secrets ecosystem. Mature Transit/EaaS. Richest auth method library. Comprehensive fail-closed audit log. Auto-unseal via cloud KMS is well-established. Dev server mode.

**Tradeoffs.** Heavy Go runtime (8 GiB Kubernetes RAM recommendation). Stateful Raft requires coordinated membership changes and is not freely HPA-scalable. Manual unseal is the CE default. Multi-tenancy requires Enterprise. HCP Vault Secrets (the managed indie tier) reached end-of-sale June 30 2025 and EOL July 1 2026. Per-client pricing on HCP Vault Dedicated reaches ~$73/client/month; 50 clients on Standard ≈ $5,000/month. No config management.

**What we admire / learned from.** Auto-unseal via cloud workload identity as the default, not an afterthought. Dynamic secrets pattern (ephemeral credentials, TTL, auto-revoke). Transit/EaaS API. PKI secrets engine concept. Fail-closed audit log (request rejected if audit device fails). Named key versioning and rotation. Dev server mode (`soma-vault dev`). Multiple auth methods per service.

**Choices soma-vault makes differently.** soma-vault uses a stateless Deployment on Postgres rather than StatefulSet + Raft, which is what enables free HPA scaling. soma-vault never requires Shamir manual unseal; pods authenticate via workload identity. soma-vault uses per-secret-version DEKs rather than a single barrier key. Multi-tenancy is in the OSS core. Config and secrets are separate data types. Machine identity pricing is bundled rather than per-unit.

---

## OpenBao

**Category:** Secrets | **License:** MPL-2.0

**Positioning.** Linux Foundation-governed fork of HashiCorp Vault 1.14 (last MPL-licensed release). Preserves the full Vault feature surface — namespaces, Transform engine, PKCS#11 auto-unseal — under a truly open license with no BUSL restriction. GitLab uses it as its internal secrets manager.

**Architecture.** Go runtime. Storage: integrated Raft (preferred) or PostgreSQL (beta). Same active/standby model as Vault. Standbys serve read-only requests locally as of v2.5.0 (horizontal read scalability). Deployed as a StatefulSet.

**Key and seal model.** Three-layer hierarchy: unseal key → root key → keyring (one or more versioned AES-256-GCM barrier keys). No per-secret DEKs — all data in a namespace shares the active barrier key. With auto-unseal (AWS/GCP/Azure KMS, PKCS#11/HSM), pods call the KMS on startup and unseal automatically. Static seal (v2.4.0) stores a 32-byte key in a Kubernetes Secret — pragmatic fallback but the K8s Secret becomes the single trust anchor.

**Multi-tenancy.** Namespaces are GA in v2.3.1 (June 2025) and free — a direct improvement over Vault CE. Each namespace is a fully isolated partition with its own auth methods, engines, policies, and tokens. No native tenant/workspace/project/environment hierarchy — operators build this from namespace conventions.

**Cloud-native and HPA story.** Same as Vault: StatefulSet, Raft quorum, HPA not compatible. Write scaling is single-active-node only. Planned future: per-namespace leaders.

**Config capabilities.** None. No typed config, no environment inheritance, no real-time push. Agent is pull-and-poll only.

**Strengths.** Full Vault feature parity, free. Namespaces and Transform engine (FPE, tokenization) free. PKCS#11/HSM auto-unseal free. Auto-unseal eliminates manual ceremony in K8s. Dynamic secrets, PKI, Transit all present. PostgreSQL as a supported storage backend.

**Tradeoffs.** Not HPA-compatible. Single barrier key — no per-secret DEK isolation. Go runtime GC makes mlock guarantees weaker. High operational overhead. No managed SaaS. SDK gap (Go only; other languages use community Vault libraries). No first-class workspace/project/environment model. No config management.

**What we admire / learned from.** Auto-unseal via KMS as the primary path. Fail-closed audit. Lease-based secret lifecycle. Path-based routing for secret engines. CEL for fine-grained policy expressions. Standby-node read distribution (serve reads from any pod, writes to leader — adopt for soma-vault's Postgres backend with read replicas). Static seal as a self-host fallback with documented tradeoffs.

**Choices soma-vault makes differently.** soma-vault never requires manual Shamir unseal; pods authenticate via workload identity. soma-vault uses per-secret-version DEKs rather than a single barrier key. Rust's ownership model enforces key zeroization at compile time rather than relying on GC behavior. Secrets and config are separate data types with separate delivery semantics. soma-vault provides first-class workspace/project/environment hierarchy and SSE real-time push. Pods run as a stateless Deployment, not a StatefulSet.

---

## Infisical

**Category:** Secrets + limited config | **License:** MIT (core) / proprietary (Enterprise)

**Positioning.** Open-core secrets platform combining static secrets, internal PKI, SSH certificates, and PAM under one roof. Targets teams migrating from HashiCorp Vault or .env files. TypeScript/Node.js backend; Postgres + Redis datastore. Stateless pods — HPA-friendly.

**Architecture.** TypeScript backend, PostgreSQL primary, Redis for caching and queuing. Self-hosted via Docker Compose or Helm, or managed SaaS at infisical.com. Operationally lighter than Vault: no Consul, no Raft.

**Key and seal model.** Three-tier hierarchy: Root Encryption Key (REK) — loaded from `ENCRYPTION_KEY` environment variable at pod startup (a static 16-byte hex string stored as a Kubernetes Secret) — → Project KMS Keys → per-entity DEKs. AES-GCM-256. There is no unseal ceremony: the pod reads `ENCRYPTION_KEY` from its environment and is immediately ready. However, the REK is a shared static secret injected as an env var. This is exactly the pattern soma-vault's Tenet 3 forbids: the pod needs a secret to unlock the secrets. HSM and external KMS (CMEK via AWS KMS or GCP KMS) are available on Enterprise only.

**Multi-tenancy.** Instance → Organization → (optional Sub-Organization) → Project → Environment → Folder → Secret. Organizations share the same Postgres database with application-layer isolation only — no documented per-tenant key derivation or cryptographic tenant isolation.

**Cloud-native and HPA story.** Pods are stateless and HPA-friendly. No Raft cluster. External stateful dependencies: Postgres, Redis, S3 for backups. Critical gap: no Workload Identity / IRSA / SPIFFE-based auto-unseal. The REK is always an env var.

**Config capabilities.** Absent. All values are encrypted string key-value pairs. No typed schema, no schema validation, no environment inheritance model, no real-time push. SDK fetches at startup or on a polling interval — no SSE or WebSocket delivery.

**Strengths.** Simple operational footprint (Postgres + Redis). Strong developer UX: `infisical run -- <cmd>`. Broad SDK coverage. MIT-licensed core. Stateless pods scale freely. Internal PKI and SSH certificate management. Kubernetes Operator watches for changes. Project-level hard isolation.

**Tradeoffs.** Shared-secret unseal (ENCRYPTION_KEY env var). No config management: no typed values, no schema, no real-time push. TypeScript/Node.js — no memory safety. Dynamic secrets and KMIP are Enterprise-only. No per-tenant cryptographic isolation. Self-hosting requires three stateful dependencies. Per-machine-identity billing counts CI pipelines and K8s service accounts equally with human users.

**What we admire / learned from.** `infisical run -- <cmd>` CLI UX. SDK breadth and .NET IConfigurationProvider pattern. Kubernetes Operator that watches and reconciles. Identity-based pricing model. Free tier structure (CLI + SDK + K8s Operator on free with no feature gates). Internal PKI and SSH certificate management. Structured audit log with streamable event types. Secret referencing and overrides across environments. Point-in-time recovery via a versions table.

**Choices soma-vault makes differently.** soma-vault uses cloud workload identity for unseal rather than a static env-var root key. soma-vault performs server-side DEK management rather than client-side-only encryption, which enables server-side schema validation and audit logging of config values. soma-vault ships typed config and real-time SSE push as first-class features. Machine identities are bundled rather than billed per-unit. Postgres is the only required datastore (no Redis). Rust rather than TypeScript/Node.js.

---

## Doppler

**Category:** Secrets + config (unified string KV) | **License:** Proprietary SaaS

**Positioning.** Best developer experience in the category. SaaS-first (GCP us-central1), on-prem Enterprise beta launched June 2026. Workplace → Project → Environment → Config hierarchy. 50+ push-sync integrations. `doppler run -- <cmd>` eliminates .env files in one command.

**Architecture.** Go backend, SaaS-only until mid-2026 on-prem Enterprise beta. Tokenization service as a cryptographic boundary: plaintext secrets never touch the DB, only opaque tokens. Workspace-level AES-256-GCM key encrypted by an HSM-backed GCP KMS root key.

**Key and seal model.** Workspace-level AES-256-GCM key with random IV per encryption. No per-secret DEK. Enterprise Key Management (EKM) adds a second envelope using the customer's own cloud KMS. No unseal concept — Doppler is a SaaS and owns the KMS infrastructure.

**Multi-tenancy.** Logical only. Top-level container is the Workplace. No technical isolation beyond application-layer RBAC and scoped service tokens. The on-prem product is single-tenant per deployment.

**Cloud-native and HPA story.** Doppler is SaaS — pods/containers do not exist from the operator's perspective. The Kubernetes Operator requires a Doppler Service Token stored as a Kubernetes Secret to authenticate — a shared static credential rather than a workload-identity path. No IRSA / GKE WI / SPIFFE path.

**Config capabilities.** Secrets and config values are the same data type: untyped string key-value pairs. No schema, no typing, no sensitivity-tier separation at the data model level. Environment inheritance via Config Inheritance (parent → child with child-override precedence). No real-time push to running processes — change delivery is CLI re-run, K8s Operator sync + optional pod restart, or outbound webhook.

**Strengths.** Best developer onboarding — under 5 minutes to first secret injected. `doppler run --` replaces .env with zero code changes. 50+ native push-sync integrations. Config Inheritance with environment override cascade. K8s Operator with auto-reload. Personal Configs and Branch Configs. Webhook-based notifications. Transparent AES-256-GCM with HSM-backed GCP KMS root key. EKM for BYOK. Accessible pricing for indie teams.

**Tradeoffs.** No per-secret data keys — one workspace key encrypts all secrets. Secrets and config are the same untyped string blob — no schema, typing, validation, or sensitivity-tier separation. No SSE/push SDK for live in-process reload. K8s Operator requires a service token (secret to get secrets) — no workload identity path. Dynamic secrets gated behind Enterprise beta. No Transit EaaS. No PKI. RBAC is project/environment-level only. SaaS-only until June 2026 on-prem Enterprise beta — no open-source community edition. Single GCP region for cloud.

**What we admire / learned from.** `doppler run -- <cmd>` CLI env-injection pattern. Project → Environment → Config hierarchy. Config Inheritance with parent-override cascade. Branch Configs for ephemeral environments. Personal Configs for per-developer local overrides. Change request workflow for gated production mutations. Missing-secret detection. Webhook outbound notifications with request signing. K8s Operator pattern — but replace the service-token auth with workload identity. 5-minute onboarding story. Expiring E2E-encrypted secret-sharing links. Activity log forwarding to multiple destinations.

**Choices soma-vault makes differently.** soma-vault separates secrets and typed config at the schema level rather than treating both as untyped strings. soma-vault uses per-secret-version DEKs rather than a single workspace key. The Kubernetes Operator authenticates via workload identity rather than a service token. soma-vault ships an open-source self-hosted binary from day one. The SDK delivers config via SSE rather than polling. Multi-region deployment is a planned phase.

---

## AWS Secrets Manager

**Category:** Secrets | **License:** Proprietary managed SaaS

**Positioning.** AWS's managed, pay-per-secret, rotation-first secrets store. Tightly integrated into the AWS IAM/KMS/CloudTrail stack. AWS-only; no self-host option.

**Architecture.** Fully managed AWS SaaS; closed-source. Storage backend is opaque. Secrets addressed by name, ARN, or tag. Values are opaque blobs up to 10 KB. Envelope encryption: per-secret AES-256 DEK wrapped by AWS KMS (managed or customer-managed key); DEK zeroized from memory after use.

**Key and seal model.** Per-secret DEK (AES-256), encrypted by AWS KMS. DEK zeroized immediately after use. No manual unseal ceremony — the AWS control plane handles KMS calls transparently. Correct model, no ceremony.

**Multi-tenancy.** None native. Isolation unit is the AWS account and/or IAM resource path prefix. No workspace, project, or environment hierarchy in the data model.

**Cloud-native and HPA story.** Fully HPA-friendly for AWS-native runtimes. On EKS, pods authenticate via IRSA or EKS Pod Identity — no shared bootstrap secret. This is architecturally equivalent to soma-vault's SPIFFE/IRSA auto-unseal tenet; AWS Secrets Manager pioneered this pattern. The CSI driver does not support AWS Fargate.

**Config capabilities.** None. Secrets-only. For typed config, AWS recommends Systems Manager Parameter Store (separate product, separate billing). No unified secrets+config experience in the AWS ecosystem.

**Strengths.** Zero operational burden. Per-secret AES-256 DEK — correct envelope encryption. Deep AWS-native integration. IRSA/Pod Identity for zero-secret bootstrap on EKS. CloudTrail logs every API call with encryption context. Managed rotation for RDS and common databases. Cross-region replication and cross-account access. Compliance certifications.

**Tradeoffs.** AWS-only. No typed configuration. No real-time delivery. No dynamic secrets. No workspace or project hierarchy — flat namespace per AWS account/region. Per-secret pricing ($0.40/month) can create incentives against good hygiene (more secrets = higher cost). Rotation requires Lambda for custom scenarios. 10 KB secret size limit. No developer-first DX (no env-var injection CLI). Fargate exclusion from CSI driver. No self-host. Costs multiply with environment/region duplication.

**What we admire / learned from.** Envelope encryption model: per-secret DEK (AES-256), DEK encrypted by KMS root key, DEK zeroized immediately after use. Workload-identity bootstrap on Kubernetes: IRSA / Pod Identity gives pods an IAM identity with zero shared bootstrap secret. Encryption context binding (SecretARN + SecretVersionId): cryptographically bind the ciphertext to its identity. CloudTrail-style per-call audit log. Batch secret retrieval API. Client-side caching library pattern.

**Choices soma-vault makes differently.** soma-vault adds typed config alongside secrets in a unified platform with real-time SSE delivery. soma-vault provides a workspace/project/environment hierarchy rather than a flat per-account namespace. soma-vault ships a self-hosted open-source binary. Rotation is built into the server rather than delegated to Lambda. Flat per-seat pricing rather than per-secret billing.

---

## GCP Secret Manager

**Category:** Secrets | **License:** Proprietary managed SaaS

**Positioning.** Google Cloud's fully managed, GCP-native key-value secrets store. IAM-based access control, versioning, envelope encryption. Companion service Parameter Manager handles structured config (JSON/YAML, up to 1 MiB per version). GCP-only.

**Architecture.** Fully managed SaaS hosted exclusively on Google Cloud. No self-host. Server-managed AES-256 envelope encryption (DEK per secret version, KEK managed inside Google's hardened KMS). CMEK available via Cloud KMS. Global resource model: secrets live in a GCP project; replication is automatic or user-managed.

**Key and seal model.** Each secret version gets a DEK; DEKs are wrapped by a KEK managed inside Google's infrastructure. With CMEK, the KEK is a customer-managed Cloud KMS key; revoke it to deny all access. No manual unseal ceremony. Correct model.

**Multi-tenancy.** GCP-project-level isolation only. No explicit workspace, environment, or tenant concept. Teams must simulate hierarchy via naming conventions or separate GCP projects.

**Cloud-native and HPA story.** Fully HPA-friendly. GKE pods scale to any N with no coordination; each pod authenticates independently via Kubernetes Workload Identity Federation. No manual unseal, no quorum. This is the reference implementation of the identity-based auto-unseal model soma-vault must replicate.

**Config capabilities.** Parameter Manager (companion service): JSON/YAML/text formats up to 1 MiB per version; can embed `$ref`-style references to Secret Manager secrets rendered at fetch time; versioned. No schema validation, no type enforcement, no environment inheritance or override model. No real-time push — applications must poll or restart.

**Strengths.** Zero operational overhead. Workload Identity Federation for GKE — gold standard for zero-secret auth on GKE. Deep GCP ecosystem integration. CMEK with Cloud KMS. VPC Service Controls. Generous free tier (6 active versions + 10,000 access ops/month). Extremely simple API. Parameter Manager adds structured config with secret references.

**Tradeoffs.** GCP-only — no multi-cloud, no on-premises, no self-host. No built-in env-var injection CLI. No project/environment separation in the data model. No dynamic secrets. Rotation is notification-only. No real-time config push. Parameter Manager has no schema validation, no environment inheritance. No transit EaaS. No PKI. Costs can surprise: all non-destroyed versions are "active" and billed.

**What we admire / learned from.** Workload identity as the ONLY authentication primitive for pod auto-unseal. CMEK envelope encryption model: DEK per secret version, KEK in external KMS, revoke KEK = instant access denial. Per-resource IAM bindings at the individual secret level. Version aliases (named aliases like 'current', 'previous'). VPC Service Controls concept. Cloud Audit Logs model. Free tier generosity. `$ref`-style secret references in config values — validated by GCP's own Parameter Manager.

**Choices soma-vault makes differently.** soma-vault provides multi-cloud portability and a self-hosted open-source binary rather than GCP lock-in. soma-vault ships an env-injection CLI (`soma run -- cmd`). soma-vault provides a first-class multi-environment model with inheritance. Config delivery is SSE push rather than polling. Schema validation runs at write time. Rotation executes server-side rather than being notification-only.

---

## Akeyless

**Category:** Secrets | **License:** Proprietary SaaS (closed source)

**Positioning.** Enterprise SaaS secrets platform built on Distributed Fragments Cryptography (DFC): the encrypted key never fully assembles on any server, anywhere, ever. Optional customer-held key fragment for true zero-knowledge. No self-host binary; stateless Gateway pods are customer-deployed.

**Architecture.** Closed-source SaaS. Stateless Gateway (Docker/Helm/K8s) for private-network access and local caching. All cryptographic state lives in Akeyless-managed Key Fragment Managers (KFMs). No traditional vault seal to break.

**Key and seal model.** DFC fragments keys across multiple KFMs in isolated regions. No "full key" ever assembles on a server. With the Customer Fragment (CF) option, no operation can complete without the CF's participation — true zero-knowledge. No unseal ceremony. The analog for soma-vault is envelope encryption with a customer-owned KMS key.

**Multi-tenancy.** Not true multi-tenancy. One account per organization. Tenants are path-based folder namespaces with folder-scoped RBAC. No cryptographic boundary between "tenants". A misconfigured wildcard path grants cross-"tenant" access.

**Cloud-native and HPA story.** Strongly HPA-friendly for Gateways: explicitly stateless, HPA + Metrics Server documented, pod anti-affinity for AZ distribution. No unseal concept — Gateways boot without ceremony. Weakness: live key derivation requires SaaS reachability when CF is not in use.

**Config capabilities.** None whatsoever. Secrets-only. Zero typed config management, no schema validation, no environment inheritance, no real-time push.

**Strengths.** No-unseal-ceremony — Gateways are stateless. True zero-knowledge possible with CF. HPA-friendly Gateways. Broad dynamic secrets producers. Strong workload identity support. Complete audit log with SIEM streaming. Compliance-ready. Dynamic secrets first-class.

**Tradeoffs.** No OSS core, no self-host — entirely proprietary closed SaaS. No config platform. Multi-tenancy is path-based folder RBAC rather than cryptographic row-level isolation. Opaque pricing, no public numbers. Free tier is 5 clients / 500 static secrets / 3-day audit retention — sized for evaluation rather than production workloads. SaaS dependency on every key derivation. Undisclosed runtime.

**What we admire / learned from.** Zero-knowledge framing: "plaintext key never assembles on any server" — soma-vault makes this concrete with DEK+KMS wrapping. Stateless gateway / local cache pattern. Dynamic secrets as first-class citizens. Workload identity auth breadth (IRSA, GKE WI, AzWI, K8s SA tokens, OIDC). SIEM streaming on audit logs. Event Center pattern: layered real-time alerting (Slack/Teams/webhook) on top of audit events. Path-based RBAC with wildcards and sub-claims (ABAC). Customer-fragment / bring-your-own-key option. Compliance cert positioning.

**Choices soma-vault makes differently.** soma-vault ships an open-source self-hosted binary with transparent pricing. soma-vault adds typed config alongside secrets. soma-vault enforces hard row-level cryptographic tenant isolation rather than path-based folder RBAC. Audit log retention on the free tier is 30 days rather than 3. Key derivation is local (HKDF in pod RAM) rather than requiring a SaaS round-trip. Rust provides a memory-safe runtime.

---

## Bitwarden Secrets Manager

**Category:** Secrets | **License:** Open-source (server: AGPL-adjacent; SDK: Rust, various)

**Positioning.** Open-source, zero-knowledge, client-side-encrypted secrets store for developer teams. Natural extension of the Bitwarden password manager brand into machine secrets. Rust SDK core with 8-language bindings. The server is a dumb ciphertext store — all crypto happens on the client.

**Architecture.** Go-based server backed by Microsoft SQL Server (primary), PostgreSQL, or MySQL. Rust SDK and CLI. Client-server model where ALL encryption/decryption happens on the client. Deployed as Docker Compose or Helm on Kubernetes. Managed cloud runs on Azure; self-host is Enterprise-only.

**Key and seal model.** Multi-layer client-side envelope encryption. Master password → PBKDF2 → Stretched Master Key (never leaves client) → encrypts a per-user Symmetric Key stored on server as ciphertext → encrypts per-item DEKs → encrypts ciphertext. AES-256 + HMAC-SHA256. No server-side unsealing — server boots freely as it stores only ciphertext. No KMS integration on the server side. Machine accounts authenticate with opaque access tokens, not asymmetric workload identity.

**Multi-tenancy.** Organization is the top-level isolation boundary. No workspace, tenant, or environment tier above Organization. Every entity carries an `OrganizationId` FK; cross-org reads are prevented at the access policy layer.

**Cloud-native and HPA story.** Application server is stateless at the app layer and can HPA freely — it holds no key material. Kubernetes Operator polls on a minimum 180-second interval. No concept of a pod proving identity to unlock a root key, because there is no server-side root key to unlock.

**Config capabilities.** None. No typed configuration, no schema validation, no environment inheritance, no real-time push. Everything is an opaque encrypted string. Environments are roadmap-only as of mid-2026; the community has been requesting them since 2023.

**Strengths.** Zero-knowledge / client-side encryption — cryptographically enforced. Rust SDK core — memory-safe, WASM-capable, 8-language bindings. Open-source codebase. Brand trust from Bitwarden password manager. Unlimited secrets at all paid tiers. `bws run` for env injection. Kubernetes Operator. Solid audit trail and SIEM integrations. Machine account access tokens are narrow-scoped.

**Tradeoffs.** No environment/environment-inheritance concept (roadmap only since 2023). Secrets-only — no typed configuration. No real-time push (K8s Operator polls every 180s minimum). No dynamic secrets. No PKI. No transit EaaS. Self-host is Enterprise-only. Primary DB is SQL Server. Machine account hard caps (3 / 20 / 50). K8s Operator maps by UUID, not secret name. No multi-workspace or tenant-above-org model. No cloud KMS auto-unseal for server-side key material.

**What we admire / learned from.** Zero-knowledge framing and envelope-encryption story (extend it to server-side DEK wrapping via KMS). Rust SDK as the lingua franca: single Rust core, compile to WASM, expose as FFI for all language bindings. `bws run` UX. Machine account / service account model with narrow-scoped access tokens. Unlimited secrets at all paid tiers. Open-source core + enterprise self-host model. Audit log on machine account events and secret access. SIEM integration story. 7-day trial with no credit card.

**Choices soma-vault makes differently.** soma-vault builds environments and inheritance into the Phase 1 data model rather than treating them as a future roadmap item. soma-vault separates typed config and secrets at the schema level. Machine identities are bundled rather than capped. Config delivery is SSE push rather than polling. Postgres is the only required database. soma-vault performs server-side DEK management and KMS-backed auto-unseal rather than client-side-only crypto. Self-host is available under MIT from day one. `soma run -- cmd` works before any dashboard setup.

---

## Replane

**Category:** Config only | **License:** MIT

**Positioning.** MIT-licensed, self-hosted dynamic configuration manager: feature flags, typed config, and real-time SSE delivery. Explicitly NOT a secrets vault — config is stored in plaintext. 82 GitHub stars, TypeScript/Node.js, single Docker image.

**Architecture.** TypeScript/Node.js backend; Next.js + React frontend; PostgreSQL 14+ primary (SQLite fallback). Single Docker image. ~256 MB RAM on the smallest shared CPU.

**Key and seal model.** Not applicable. No encryption model, no master key, no seal/unseal. Config values are stored in PostgreSQL as plaintext. `SECRET_KEY` in env is only for session signing.

**Multi-tenancy.** Workspace → Project → Config → Environment hierarchy. Workspace-level RBAC. No cryptographic tenant isolation — all data shares the same PostgreSQL instance and encryption domain.

**Cloud-native and HPA story.** Nodes are stateless (each caches from Postgres via local SQLite), so horizontal scaling is straightforward. No Kubernetes manifests or Helm charts provided. No workload identity integration. No encryption, so no unseal.

**Config capabilities.** This is the core product. Typed config values with JSON Schema validation and auto-generated TypeScript types. Environment-based values. Context-aware per-request overrides by user ID, plan tier, or region. Real-time delivery via SSE with SDK-side in-memory cache (reads are local, sub-millisecond). Change proposal + review workflow. Version history with rollback. No `$ref` pointer to secrets — the docs correctly warn against putting secrets in Replane.

**Strengths.** Extremely low operational footprint. Single Docker image; SQLite fallback. SSE-push real-time delivery with local SDK cache. MIT license with no seat/workspace/usage caps on self-hosted tier. JSON Schema validation first-class. Context-aware override rules. Zero-dependency SDKs. Change proposal + approval workflow. Clean, minimal codebase.

**Tradeoffs.** No secrets management — no encryption at rest, no KMS, no DEK model. No CLI for env-injection. No Kubernetes manifests or Helm charts. No Rust / memory-safe runtime. No dynamic secrets, no PKI, no Transit EaaS. Single-tenant self-host model. 82 GitHub stars — tiny ecosystem. Enterprise tier is contact-sales via a personal Gmail address. No FIPS 140-2/3, no SOC 2, no ISO 27001.

**What we admire / learned from.** SSE-push real-time delivery as the default config delivery primitive — SDK-side in-memory cache makes reads a local operation. Change proposal + approval workflow. Context-aware override rules (per-user, per-plan, per-region). JSON Schema validation with auto-generated typed client code. Kill-switch pattern as a named first-class use case. Single-binary / minimal-infra first-run story. Explicit, documented separation between config (here) and secrets (elsewhere) with a `$ref` pointer model in soma-vault.

**Choices soma-vault makes differently.** soma-vault unifies secrets and config in one platform, with envelope encryption for secrets and plaintext typed delivery for config. soma-vault ships an env-injection CLI (`soma run -- cmd`) and Kubernetes manifests. soma-vault enforces multi-tenant isolation at the row level. Auto-unseal via workload identity is a core design tenet. Rust provides a memory-safe runtime. Dynamic secrets, PKI, and Transit EaaS are on the Phase 2 roadmap.

---

## Configu

**Category:** Config orchestration (brings your own secrets store) | **License:** MIT (Orchestrator)

**Positioning.** Open-source "GitHub for configurations" — a Configuration-as-Code orchestration layer that unifies management of env vars, secret references, and feature flags across any storage backend. Orchestrates over secrets managers rather than replacing them. 1.7k GitHub stars, TypeScript monorepo, Node.js runtime.

**Architecture.** TypeScript/Node.js. Three delivery interfaces: `@configu/cli`, `@configu/proxy` (stateless multi-protocol server: HTTP/gRPC/GraphQL/WebSocket/SSE), `@configu/sdk`. Storage is pluggable via a `ConfigStore` abstraction (20+ integrations: Vault, AWS SM, GCP SM, Postgres, SQLite, Kubernetes Secrets, LaunchDarkly, etc.). Configu itself is stateless.

**Key and seal model.** Not applicable. Configu stores no master key and performs no KMS-backed unsealing. It delegates all key management to whichever backend is configured.

**Multi-tenancy.** Configu Cloud provides org-level tenancy with RBAC tokens per org. OSS Orchestrator has no enforced multi-tenant isolation — all isolation delegated to the backend. No hard row-level tenant scoping.

**Cloud-native and HPA story.** Proxy is stateless and horizontally scalable. No K8s Operator, no CRD, no mutating admission webhook. HPA-friendly for the Proxy itself. No workload identity / auto-unseal concept — not applicable since it stores no sensitive key material.

**Config capabilities.** Core competency. Typed config via `.cfgu.json` schema files checked into source control: types (String, Number, Boolean, URL, RegEx, JSONSchema, enum), cross-key expression references, required/default/const/lazy constraints. ConfigSet path-based hierarchy (slash-separated context tree) for environment inheritance and override with implicit parent propagation. Eval → Export pipeline: evaluate from store, render to env vars / ConfigMap YAML / Helm values / .env file. Multi-protocol Proxy for real-time delivery (SSE/WebSocket/gRPC). Approval Queue, audit/activity log, webhooks (Slack/Discord/GitHub Actions hooks) in the Cloud tier.

**Strengths.** Strong developer ergonomics — `.cfgu` schema lives in source control alongside code, git-native workflow, no migration of existing stores required. Pluggable backend model — teams keep existing secrets manager and add Configu on top. Typed, schema-validated config. ConfigSet path-based hierarchy elegantly handles per-environment overrides. Stateless Proxy with SSE/WebSocket/gRPC. MIT Orchestrator with no feature paywalls on core functionality. Extensive CI/CD integrations. Approval Queue and audit log in Cloud tier.

**Tradeoffs.** Config-only — does not store or encrypt secrets itself; always requires a separate secrets store. No first-class secrets tier with sensitivity classification. No dynamic secrets, no PKI, no transit EaaS. Minimal multi-tenancy in the OSS tier. No Kubernetes Operator or mutating webhook. TypeScript/Node.js runtime. Real-time delivery via Proxy is architecturally present but thinly documented. Relatively small community.

**What we admire / learned from.** ConfigSet path-based hierarchy (slash-separated context tree with implicit parent inheritance). `.cfgu` schema-as-code in source control. Eval → Export pipeline idiom. Approval Queue for config changes. Multi-protocol Proxy (HTTP + SSE + gRPC) for real-time delivery. Webhooks on config change events. Config compare / config history / config explorer as first-class UI features. Cross-key expression context in schema (`$.value`, `configs.key.value`).

**Choices soma-vault makes differently.** soma-vault separates secrets and config at the data model level, giving each its own delivery semantics (SSE for config, pull-only for secrets). soma-vault stores and encrypts secrets natively rather than delegating to an external store. soma-vault ships a Kubernetes Operator with workload-identity auth. Multi-tenant isolation is enforced at the row level in the OSS core. Dynamic secrets, PKI, and transit EaaS are on the Phase 2 roadmap.

---

## AWS AppConfig

**Category:** Config + feature flags | **License:** Proprietary managed SaaS

**Positioning.** AWS-native managed config and feature-flag service (part of Systems Manager). Safe, gradually-rolled-out application configuration with CloudWatch-backed auto-rollback. Explicitly NOT a secrets store. Agent-based local cache on localhost:2772.

**Architecture.** Fully managed AWS SaaS; no self-hosted option; no open-source core. Delivery via the AppConfig Agent — a sidecar/DaemonSet/Lambda extension process that polls the data plane and exposes a localhost HTTP API on port 2772.

**Key and seal model.** Not applicable — AppConfig is a config service, not a vault. Data at rest is encrypted via AWS KMS. The agent authenticates using the pod/instance IAM role (IRSA, instance profile, task role). No shared secret, no manual unseal.

**Multi-tenancy.** No built-in multi-tenant isolation. Hierarchy is Application → Environment → Configuration Profile → Deployment. Tenant isolation strategies are: separate AWS accounts per tenant, or separate Application resources per tenant with IAM resource policies. Neither is enforced by AppConfig.

**Cloud-native and HPA story.** HPA-friendly by design for workloads consuming configuration. Agent runs as a sidecar or DaemonSet — one agent fetches config on behalf of all pods; HPA can scale workload pods without proportional AppConfig traffic. Agent authenticates via IRSA/Pod Identity — no shared bootstrap secret.

**Config capabilities.** Two profile types: (1) Feature Flags — typed JSON document with per-flag boolean/number/string constraints, context-based rules for targeting, percentage rollout, entity-based gradual deployments; (2) Freeform — arbitrary JSON/YAML with optional JSON Schema v4 or Lambda validator. No native environment inheritance. No typed config SDK (raw JSON, app must parse). Real-time delivery is polling-only (default 45s). Validator runs at deploy time, not write time. Alarm-triggered auto-rollback via CloudWatch/Datadog/Dynatrace.

**Strengths.** Safe-deployment mechanics — gradual rollout + bake time + automatic alarm rollback is best-in-class. Agent abstracts polling, caching, and token refresh. Sticky entity-based deployments. A/B experimentation built in. Deep AWS-native integration. Serverless-friendly Lambda extension. Workload identity authentication — no human secret hand-off at startup.

**Tradeoffs.** Config-only — secrets live in a separate service (Secrets Manager). Not self-hostable or open-source. No first-class multi-tenant isolation. Awkward session-based API. No CLI for developers beyond AWS CLI. Config delivery is polling only (45s default). No dynamic secrets, no PKI, no transit EaaS. High-frequency polling adds cost. AWS-only. Five-step onboarding before hello world.

**What we admire / learned from.** Workload-identity bootstrap model — pod/function authenticates via cloud IAM role; no human unseal secret. Agent sidecar pattern: managed process on localhost that owns caching, polling, and token refresh. Sticky entity-based canary deployments (user/entity ID gets config version N and keeps it through rollout). Alarm-triggered auto-rollback with configurable bake time. Exponential + Linear rollout strategies as named, reusable objects. Validator-at-deploy-time pattern. Context-based flag rules evaluated server-side so SDK gets a resolved value.

**Choices soma-vault makes differently.** soma-vault unifies secrets and config in one platform, one auth flow, one billing line. soma-vault ships an open-source self-hosted binary. soma-vault enforces multi-tenant isolation at the row level. Config delivery is SSE push rather than polling. `soma run -- cmd` provides an env-injection CLI with a short onboarding path. Multi-cloud rather than AWS-only.

---

## Azure App Configuration

**Category:** Config + feature flags | **License:** Proprietary managed SaaS

**Positioning.** Azure-native managed service for centralizing typed application configuration and feature flags. Explicitly NOT a secrets vault — secrets live in Azure Key Vault and are referenced by URI pointer from App Configuration. Kubernetes Provider projects config as ConfigMaps/Secrets.

**Architecture.** Fully managed, multi-region SaaS hosted exclusively on Azure. Proprietary closed-source; no self-host. REST API + provider/SDK layer. TLS 1.2/1.3 in transit; AES-256 at rest. CMK via Azure Key Vault (Standard/Premium only).

**Key and seal model.** Per-store AES-256 DEK managed by Microsoft by default. With CMK (Standard/Premium): store's DEK is wrapped by a customer-provided KEK stored in Azure Key Vault; the store's managed identity calls Key Vault to unwrap the DEK, cached in memory for 1 hour. No unseal concept — fully managed SaaS. Application pods authenticate via Entra managed identity.

**Multi-tenancy.** No native multi-tenant hierarchy. Service unit is a "store." Multi-tenancy via store-per-tenant (strong isolation, high operational complexity) or shared store with key-prefix/label conventions (weak isolation, all-or-nothing access control). No row-level or namespace-level access policy within a single store.

**Cloud-native and HPA story.** HPA-friendly for consuming workloads. Kubernetes Provider runs as a single in-cluster controller, pulls config, and publishes as Kubernetes ConfigMaps and Secrets. HPA can scale workload pods without proportional App Configuration traffic. Pods authenticate via Kubernetes Workload Identity (Azure AD Workload Identity on AKS).

**Config capabilities.** Two content types: Feature Flags (per-flag boolean/number/string constraints, targeting filters, time-window filters, percentage rollout) and key-value stores (opaque strings with content-type hints; no schema registry). Label-stacking pattern for environment inheritance: load default (unlabeled) keys, overlay environment-labeled keys. Push model (opt-in): Event Grid → Service Bus → SDK `ProcessPushNotification` for near-real-time delivery; operationally heavy (requires two additional managed services). Configuration snapshots for immutable point-in-time config sets. Revision history (7 days Free/Dev; 30 days Standard/Premium).

**Strengths.** Zero operational overhead. Tight Azure ecosystem integration. Feature flag system is first-class with a dedicated portal UI, targeting filters, and multi-language SDK (Microsoft.FeatureManagement schema is language-agnostic). Kubernetes Provider is HPA-friendly. Geo-replication with per-replica request quotas. Push model via Event Grid eliminates polling (though operationally heavy). Configuration snapshots. Availability zone redundancy at no extra cost. CMK with Azure Key Vault. Soft-delete + purge protection. Label-stacking for environment inheritance. SDKs in 6+ languages.

**Tradeoffs.** Config-only — Microsoft explicitly says "do not store secrets here; use Key Vault." No self-host option. Multi-tenancy is not first-class. Push refresh requires provisioning Event Grid + Service Bus just to avoid polling. No typed schema validation beyond content-type hints. Request-quota throttling at Standard tier is a real operational concern. Free and Developer tiers have no SLA. No dynamic secrets, no PKI, no transit EaaS. No immutable audit trail for reads. Local development experience is awkward. CMK and Private Link gated behind Standard/Premium.

**What we admire / learned from.** Label-stacking pattern for environment inheritance. Feature flag schema and UI as a first-class store citizen. Sentinel key pattern for atomic multi-key config refresh. Configuration snapshots for immutable, named point-in-time config sets. Kubernetes Provider model (single in-cluster controller, projects to ConfigMaps and Secrets). Per-replica read quotas. Content-type field on key-values for encoding hints. Azure Monitor AACAudit structure (caller identity + IP + action + target per write). Event-driven push delivery via event bus as an opt-in complement to polling. Soft-delete with configurable purge protection.

**Choices soma-vault makes differently.** soma-vault unifies secrets and typed config in one platform rather than splitting across two services. soma-vault is multi-cloud and self-hostable rather than Azure-only. soma-vault enforces multi-tenant isolation at the row level. Real-time delivery is built into the SSE endpoint without requiring Event Grid + Service Bus. JSON Schema validation runs at write time. Audit logs include data-plane reads by default. Flat per-seat pricing rather than per-request overage.

---

## HashiCorp Consul KV

**Category:** Config (KV store bundled with service mesh) | **License:** MPL-2.0 (CE) / proprietary (Enterprise)

**Positioning.** A distributed key-value store bundled inside Consul (a service-mesh and service-discovery platform), repurposed for configuration management via Go templates and long-poll watchers. KV is explicitly declared feature-complete with no new development planned. HCP Consul Dedicated reached end-of-life November 12, 2025 with no replacement.

**Architecture.** Go runtime; stateful Consul server cluster (3 or 5 nodes) using Raft with write-ahead log. Data is unencrypted in memory and in Raft snapshots on disk. Production servers require 8–16 cores / 32–64 GB RAM / 200+ GB SSD. Deployed as Kubernetes StatefulSets with PersistentVolumeClaims; clients as DaemonSets.

**Key and seal model.** None. Values are stored unencrypted in Raft snapshots on disk and in memory. ACLs control access at the API layer, but anyone with filesystem access to the data directory or a valid snapshot can read all values in plaintext. Consul's own documentation says "for sensitive data, use HashiCorp Vault instead."

**Multi-tenancy.** Consul OSS: single namespace, single admin partition — effectively no multi-tenancy. Consul Enterprise Standard: namespaces and admin partitions, both Enterprise-only features.

**Cloud-native and HPA story.** Consul servers deploy as StatefulSets with PVCs; they require quorum to elect a leader before becoming ready. Server pods cannot be freely HPA-scaled — adding servers changes quorum requirements. Client agents are stateless and can scale freely, but they only proxy requests to the stateful servers. No unseal ceremony, but stateful server cluster means Consul KV is NOT HPA-friendly as a whole.

**Config capabilities.** No type system: all values are opaque bytes. No schema validation. Environment model is pure convention: path prefixes like `config/{env}/{service}/{key}`; no inheritance, no override chain. Real-time delivery: blocking queries (long-poll on `X-Consul-Index`) for KV keys or prefixes; consul-template re-renders files on change. No SSE or WebSocket push; no in-process SDK cache with push invalidation. Performance note: excessive watchers degrade Consul's core service discovery — watch usage must be limited.

**Strengths.** Zero additional infrastructure if you already run Consul for service mesh. Blocking queries give genuine long-poll push semantics. Battle-hardened Raft replication. consul-template covers a huge class of "render a config file on change" use cases. Large ecosystem: integrations with Terraform, Nomad, Vault, Kubernetes, Envoy all mature. Open-source core (MPL-2.0).

**Tradeoffs.** KV is feature-complete with no new development planned — effectively in maintenance mode. Not a secrets tool: keys stored in plaintext. No envelope encryption or DEK per entry. No type system, schema validation, or typed config. Multi-tenancy is Enterprise-only. Managed cloud offering (HCP Consul Dedicated) reached EOL November 2025 with no replacement. Heavy operational footprint: 32–64 GB RAM per server node at scale. Stateful server pods require coordinated scaling (HPA is not free). No per-entry versioning history (OSS). No first-class environment inheritance model. No real-time push to an SDK-embedded in-process cache. Developer onboarding is significantly more involved than tools like Doppler or Infisical.

**What we admire / learned from.** Blocking queries (long-poll on a monotonic index) for near-real-time key/prefix change notification without a message broker. Path-as-hierarchy convention for environment scoping. consul-template's `keyOrDefault` fallback pattern. consul-template's file-rendering / sidecar daemon pattern for legacy apps. ACL prefix-based policy model as a starting point. Separation of "config watchers" (real-time delivery) from "secret reads" (one-shot, zeroized).

**Choices soma-vault makes differently.** soma-vault is a purpose-built secrets and config platform rather than a KV store bundled inside a service mesh. Values are typed and schema-validated. Secrets are envelope-encrypted with per-secret DEKs. soma-vault uses a stateless Deployment on Postgres (HPA-compatible) rather than a stateful Raft server cluster. Multi-tenancy is in the OSS core. soma-vault offers a managed cloud SaaS with transparent pricing. Rust provides a memory-safe, low-footprint runtime. Secrets and typed config live in one platform.

---

## Positioning Summary

The table uses the following shorthand. **Self-host**: genuinely free self-hosted binary or open-source core available. **Multi-tenant**: hard tenant isolation enforced at the data or API layer, not just naming conventions. **Auto-unseal/HPA**: pods start without human intervention AND horizontal autoscaling (HPA) works freely (stateless pods, no Raft quorum). **Config**: typed, schema-validated, non-sensitive configuration with environment inheritance and real-time delivery — not just a KV store. **Secrets**: encrypted secret storage with per-secret DEK (envelope encryption), access audit, and rotation. **DX**: one-command onboarding (CLI env-injection, under 5 minutes to first secret).

| Product | Category | Self-host | Multi-tenant | Auto-unseal / HPA | Config | Secrets | DX |
|---|---|---|---|---|---|---|---|
| **HashiCorp Vault** | Secrets | Yes (CE, BUSL) | Enterprise only | Auto-unseal yes; HPA no | No | Yes (single barrier key) | Low |
| **OpenBao** | Secrets | Yes (MPL-2.0) | Yes (MPL, GA v2.3) | Auto-unseal yes; HPA no | No | Yes (single barrier key) | Low |
| **Infisical** | Secrets | Yes (MIT core) | App-layer only | No (env var root key); HPA yes | No | Yes (DEKs, no WI unseal) | High |
| **Doppler** | Secrets + config | Enterprise only (Jun 2026) | Logical only | N/A (SaaS); K8s needs service token | Untyped strings | Yes (workspace key) | Best-in-class |
| **AWS Secrets Manager** | Secrets | No | No (naming conventions) | IRSA yes; HPA yes | No | Yes (per-secret DEK) | Low |
| **GCP Secret Manager** | Secrets | No | No (GCP project) | GKE WI yes; HPA yes | Companion (no push) | Yes (per-version DEK) | Low |
| **Akeyless** | Secrets | No (SaaS only) | Path RBAC (no isolation) | No unseal (SaaS); Gateway HPA yes | No | Yes (DFC, no OSS) | Medium |
| **Bitwarden SM** | Secrets | Enterprise only | Org-level only | No (client-side model); HPA yes | No | Yes (client-side DEK) | Medium |
| **Replane** | Config | Yes (MIT) | Logical only | N/A (no encryption) | Yes (typed, SSE push) | No | High |
| **Configu** | Config orchestration | Yes (MIT) | None (delegates) | N/A (no key material) | Yes (typed, SSE proxy) | No | High |
| **AWS AppConfig** | Config | No | No | WI yes; HPA yes | Typed (poll only) | No | Low |
| **Azure App Config** | Config | No | No | WI yes; HPA yes | Typed (push via Event Grid) | No | Medium |
| **Consul KV** | Config | Yes (MPL-2.0) | Enterprise only | N/A (plaintext); Raft blocks HPA | Untyped (long-poll) | No | Low |
| **soma-vault (target)** | Secrets + config | Yes (open-core) | Hard isolation (row-level) | WI auto-unseal; HPA yes (stateless) | Yes (typed, SSE push, schema) | Yes (per-secret DEK, KMS) | Target: high |

**Gap this table exposes.** No single competitor combines all six columns with a checkmark. Vault/OpenBao have the deepest secrets feature set but are not optimized for HPA elasticity and do not have typed config. Doppler has the best developer onboarding and config hierarchy but no self-hosted OSS core, no typed config schema, no per-secret DEKs, and no workload-identity unseal. Infisical is the closest overall but uses a static env-var root key and has no typed config plane. AWS/GCP managed services have workload-identity auto-unseal but are cloud-locked and config-light. Replane and Configu are excellent on typed config and real-time delivery but have no secrets story. soma-vault's target is the row where every column is satisfied simultaneously: hard multi-tenancy, workload-identity auto-unseal, per-secret envelope encryption, typed config with SSE push, open-core self-host, and a developer UX that competes with Doppler.
