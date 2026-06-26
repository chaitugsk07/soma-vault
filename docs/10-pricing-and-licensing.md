# Pricing and Licensing

soma-vault is open-core: the server binary, CLI, Rust SDK, Kubernetes Operator, and every non-negotiable architectural tenet ship as MIT-licensed OSS. Managed cloud and advanced enterprise capabilities are paid. This document explains what sits on each side of that line, why, and what the competitive landscape taught us.

---

## Lessons from the ecosystem

### HashiCorp Vault

Vault has a technically sound open-core structure — a genuinely functional OSS tier with enterprise features behind a license. The 2023 BUSL switch (BSL 1.1) was a significant shift: it forked the community (producing OpenBao under MPL-2.0), generated tension in the ecosystem, and gave competitors a sustained opening. The lesson for soma-vault isn't that Vault was wrong to have a paid tier, but that unilateral license changes are costly to ecosystem trust.

**Vault gated multi-tenancy (namespaces) behind Enterprise**, which means OSS users running multi-tenant workloads must either run one cluster per tenant or purchase Enterprise. soma-vault keeps hard tenant isolation in the OSS core from the start.

The per-client pricing on HCP Vault Dedicated (~$73/client/month) could produce five-figure monthly bills for modest deployments; HCP Vault Secrets reached end-of-life on July 1, 2026.

**Lessons:** Keep multi-tenancy free. Keep the license stable. Per-client pricing that counts every pod replica or CI job is a deal-breaker for the indie/startup segment.

### Infisical

Infisical draws the open-core line well: MIT-licensed server on GitHub, full self-host at any tier, no feature gates on core secrets management. The OSS core is genuinely functional. The pricing structure worth noting: `$18/identity/month` where "identity" counts human users and machine identities equally. A startup with 5 engineers, 10 Kubernetes service accounts, and 8 CI pipeline tokens pays for 23 identities — $414/month on Pro before they have ten employees. That model adds up quickly for teams running many automated workloads.

Infisical also has no typed config or SSE push. Everything is an encrypted string. There is no schema validation, no environment inheritance model, and no real-time delivery to running processes.

**Lessons:** Separate human seat pricing from machine identity pricing. Generous machine identity bundles are a concrete differentiator. Ship typed config and real-time delivery where Infisical has a gap.

### Doppler

Doppler's UX is best-in-class for onboarding. The `doppler run -- <cmd>` pattern, the project/environment hierarchy, and the 50+ sync integrations are directly inspiring. The open-core story is different: Doppler has no OSS core, and no self-hosted tier until the June 2026 enterprise on-prem beta (commercial, not open-source). That means regulated industries and security-conscious operators who need a self-hostable option don't have a Doppler path today.

Doppler's per-user pricing ($21/user/month Team) is reasonable for small teams but scales uncomfortably at 50+ engineers, and service tokens are not separately priced, so large teams with many automated runners face the same billing wall as Infisical.

**Lessons:** Ship self-hosted OSS from day one. The "SaaS-only until enterprise" path leaves the entire self-hosted/regulated market to competitors. Doppler's DX (one-command CLI, project/environment hierarchy, change request workflow) is the bar to meet or beat.

### Replane

Replane is the best real-time config platform in the category and the most honest about its scope: it explicitly tells users to put secrets in Vault or AWS Secrets Manager, not in Replane. MIT-licensed, self-hosted, no artificial caps. The SSE push delivery model and in-process SDK cache with sub-100ms propagation are exactly what soma-vault's config plane implements.

Replane has no open-core/enterprise split to analyze — it is pure MIT with a contact-sales enterprise tier. It has no secrets, no encryption, no KMS, and no managed cloud SaaS.

**Lessons:** The SSE push + in-process cache model is proven and worth building. Honesty about product scope builds trust; soma-vault's separation of secrets and config at the schema level is the integrated version of what Replane does explicitly.

---

## Open-core split

### MIT-licensed OSS (self-hostable, no caps)

The following ship in the single binary under MIT. There are no feature flags, no license checks, and no artificial usage limits in self-hosted mode.

| Capability | Notes |
|---|---|
| Full soma-vault-server binary | axum API, SSE delivery, Leptos dashboard, embedded migrations |
| All five non-negotiable tenets | Multi-tenancy, stateless pods, KMS auto-unseal, envelope encryption, secrets-vs-config split |
| Multi-tenant hierarchy | Tenant → workspace → project → environment. Not gated, unlike Vault namespaces |
| AWS KMS auto-unseal via IRSA | The product's primary positioning claim — not paywalled |
| Software-KMS fallback | age-encrypted master KEK for self-host without cloud KMS; tradeoffs documented |
| Envelope encryption | Per-secret DEK, AES-256-GCM, zeroize-on-drop |
| Separate secrets and config tables | Schema-level enforcement, not a UI label |
| Typed config with JSON Schema validation | string, int, float, bool, json, secret_ref; write-time validation |
| SSE real-time config delivery | tokio broadcast + Postgres LISTEN/NOTIFY fan-out; SDK in-process cache |
| Environment inheritance | inherits_from FK, depth 3, child overrides win |
| RBAC + path-capability authorization | deny-by-default, radix-trie, Rust type-state enforcement |
| soma-iam JWT integration | session-token exchange, JWKS cache |
| Universal Auth | client_id + Argon2id secret for local dev and machine identities |
| HMAC-chained audit log | seq_num, prev_entry_hash, reason field, INSERT-only role, /audit/verify |
| Secret versioning | max_versions, soft-delete, destroy, CAS, rollback |
| Static rotation infrastructure | rotation_jobs table, four-stage lifecycle, SKIP LOCKED workers |
| CLI binary (soma) | soma run --, soma secrets export, soma config get/set |
| Kubernetes Operator | SomaSecret CRD, native Kubernetes Secret reconciliation |
| Rust SDK (soma-sdk) | secrets.get() → Secret<String>, config.get::<T>(), SSE background task |
| Helm chart | Deployment, ServiceAccount with IRSA annotation, HPA, PDB |

The rationale for keeping all of this in OSS: the five tenets are foundational and cannot be retrofitted. Gating any of them — multi-tenancy, auto-unseal, envelope encryption — would be a Vault-era mistake and would eliminate the indie/startup target market before the product has customers.

### Paid cloud and enterprise

The following are either managed-cloud-only, enterprise-gated, or Phase 2+ capabilities.

| Capability | Tier | Phase | Rationale |
|---|---|---|---|
| Managed cloud SaaS (soma-vault.com) | Pro / Enterprise | 1 | Hosted infrastructure, SLA, support |
| GCP Cloud KMS backend | Cloud initially, later OSS | 2 | Trait defined; implementation deferred until concrete demand |
| Azure Key Vault backend | Cloud initially, later OSS | 2 | Same as GCP |
| External SIEM streaming | Enterprise | 2 | Datadog, Splunk, S3 audit export; async batch delivery |
| Approval / change-request workflow | Pro+ | 2 | proposal/approved/rejected/merged state machine |
| Dynamic secrets | Pro+ | 2 | CredentialProvider trait; DB and cloud IAM adapters |
| PKI / internal CA engine | Enterprise | 2 | rcgen CA, ACME endpoint, CRL, short-lived certs |
| Transit EaaS API | Pro+ | 2 | /v1/transit/* over Phase 1 key management |
| Per-project BYOK/CMEK | Enterprise | 2 | KmsBackend trait supports it; one key per deployment in Phase 1 |
| SCIM provisioning / directory sync | Enterprise | 2 | soma-iam's concern; SCIM here means vault-side role sync |
| Cedar policy-as-code engine | Enterprise | 2 | Phase 1 path-glob policies migrate cleanly; Cedar strings stored for forward compat |
| 99.9%+ SLA, dedicated infrastructure | Enterprise | 1 | Managed cloud only |
| Priority support | Pro / Enterprise | 1 | Managed cloud only |

---

## Free tier (managed cloud)

The managed cloud free tier (soma-vault.com) requires no credit card.

| Dimension | Limit | Comparison |
|---|---|---|
| Workspaces | 3 | Infisical: 3 projects |
| Human identities (soma-iam seats) | 5 | Infisical: 5 |
| Machine identities / service accounts | 10 | Infisical: charges these at $18/identity on Pro |
| Secrets | 1,000 | Infisical: unspecified |
| Config keys | Unlimited | Doppler: unlimited on Developer |
| Environments per project | 3 | Infisical: 3 |
| Audit log retention | 30 days | Doppler: 3 days; Infisical: unspecified |
| SSE real-time config delivery | Included | Not offered by Infisical or Doppler |
| CLI + Rust SDK | Included | All competitors include CLI on free |
| Kubernetes Operator | Included | Infisical: included; Doppler: included |

The 30-day audit retention on the free tier is a deliberate differentiator. Doppler gives 3 days on Developer, which is insufficient for any real incident investigation. Infisical does not publish a retention number for the free tier. A developer who wants to audit what happened to a secret two weeks ago should not need to upgrade first.

The 10 machine identity allowance on the free tier is sized to cover a small-to-mid microservices setup (a handful of Kubernetes service accounts plus a few CI pipelines) without hitting an upgrade wall. Machine identities do not count against human seat limits. This is the direct inversion of Infisical's $18/identity model.

---

## Paid tiers (managed cloud)

Exact price points require founder validation before publication. The structure is:

**Pro** — flat per-human-seat monthly fee (annual discount), with a bundled machine identity allowance (suggested starting point: 25 included, $2/additional/month). Adds:
- Unlimited workspaces and projects
- Unlimited environments per project
- 90-day audit log retention
- RBAC custom roles
- Approval workflow for config mutations
- Dynamic secrets (Phase 2, available when shipped)
- SAML/OIDC SSO (via soma-iam)
- Priority support (business hours)

**Enterprise** — custom annual contract. Adds:
- Dedicated infrastructure per account
- 99.9%+ SLA with penalty credits
- PKI / internal CA engine (Phase 2)
- Transit EaaS (Phase 2)
- Per-project BYOK/CMEK
- SCIM and directory sync
- Cedar policy engine (Phase 2)
- External SIEM streaming
- Unlimited audit log retention
- White-glove onboarding and migration support

---

## License choice

The OSS core is MIT. The alternatives and their tradeoffs:

**Apache 2.0** — equivalent developer-friendliness to MIT but includes explicit patent grants. A reasonable alternative; the practical difference for soma-vault's early stage is negligible. The patent grant becomes meaningful if the company files patents.

**BUSL 1.1 (timed release to Apache 2.0)** — prevents a competitor from forking soma-vault and offering a competing managed SaaS in the near term. The tradeoff: this is what HashiCorp did, and it generated the OpenBao fork, damaged ecosystem trust, and gave competitors a sustained opening. Starting with the same license would undermine the community credibility soma-vault is trying to build.

**MIT** — what Infisical uses. No viral effect, no patent protection, maximally permissive. A SaaS competitor could fork soma-vault and run it as a managed service without contributing back. In practice, the managed cloud's operational differentiation (SLA, support, domain expertise, the soma-platform integration layer) is the moat, not the license. MIT also signals to the indie/startup segment that soma-vault is not planning a BUSL switch — this trust is worth more than the narrow protection BUSL provides.

**Decision:** MIT for the OSS core. If the patent portfolio grows or a specific SaaS competitor behavior becomes a problem, Apache 2.0 is a non-breaking migration for users.

---

## Advanced engines: likely paid tiers

The following capabilities are deliberately deferred and will be paid features when shipped, not because they are artificially withheld but because they require significant engineering effort and ongoing maintenance that self-sustaining revenue must support:

**Dynamic secrets** (Phase 2, Pro+) — per-backend CredentialProvider adapters require outbound connectivity from vault pods to target systems, thorough testing against multiple database versions, and ongoing maintenance as target systems change APIs. The lease sweeper and rotation infrastructure exist in Phase 1; the adapters do not.

**PKI / internal CA** (Phase 2, Enterprise) — operating a certificate authority correctly involves revocation (CRL/OCSP), intermediate CA management, expiry alerting, and regulatory requirements that make this a distinct product effort. The certificate_authorities schema row and KMS wrapping path are reserved from day one.

**Transit EaaS** (Phase 2, Pro+) — the internal envelope encryption plumbing already exists; the external API surface (/v1/transit/encrypt, /decrypt, /sign) is additive. Priced at Pro+ because it expands the attack surface and requires careful rate limiting to prevent abuse.

**SCIM / advanced SSO** (Phase 2, Enterprise) — identity federation at scale is an enterprise concern. OIDC SSO itself flows through soma-iam and is not gated; what Enterprise adds is automated provisioning/deprovisioning via SCIM and directory connector.

**Cedar policy engine** (Phase 2, Enterprise) — RBAC + path-capability policies in OSS cover the vast majority of use cases. Cedar's attribute-based control (time-of-day restrictions, IP range conditions, complex role hierarchies) is an enterprise governance requirement. The Phase 1 policies table stores policy strings in a Cedar-forward schema so migration is additive, not destructive.

**GCP and Azure KMS backends** — will initially be managed-cloud-only when implemented, then open-sourced once the implementations are stable and the maintenance burden is understood. The KmsBackend trait is defined abstractly from day one; adding implementations is mechanical.

---

## Self-host is not a second-class citizen

The single-binary self-host model is a structural moat over managed-only competitors (Doppler pre-2026 on-prem, Akeyless). The binary is identical to what runs on soma-vault.com: same code, same tenets, same CLI, same SDK. There are no "self-host edition" feature gaps in Phase 1.

Self-hosters who do not need the managed cloud's SLA, support, or operational convenience run the full product at zero cost. This is the community moat. The OSS tier is not a lead-generation tool with artificial caps designed to force upgrades — it is the real product, and the managed cloud is a convenience layer on top of it.
