# Plan: Atomic audit in soma-vault

Upgrade vault's audit from **best-effort** (`record()` after the storage tx
commits) to **atomic** (`record_in_tx()` inside the storage tx) so a privileged
write and its audit row commit together or not at all.

Builds on the committed drop-in (`feat/soma-audit-dropin`). This is a separate,
follow-up change.

## Decisions (locked)

- **Shape:** `AuditedDataStore` wrapper — a newtype around `Arc<dyn DataStore>`
  that records success audit atomically. The `DataStore` trait stays clean.
- **Denials:** also audit `Outcome::Denied` for 403s, at the **API layer**
  (those never reach storage).

## The honest shape: two audit sites, by design

Because the wrapper sits at the storage boundary but 403 denials happen in the
API layer (before storage is called), audit lives in two places — and that is
correct, not a leak:

| Outcome | Where it's recorded | How |
|---|---|---|
| **Success** | storage layer | `record_in_tx` inside the op's transaction (atomic) |
| **Denied** (403) | API layer | `record()` in the `principal.require(...)` Err arm |
| **Error** (storage failure) | nowhere | the storage tx rolls back; its audit row rolls back too — same as today |

This matches the goal: success is atomic; denials are visible; storage errors
produce no record (a rolled-back action correctly has no audit).

## The two tiers of work (from the storage map)

**Tier 1 — 9 single-transaction ops (easy, safe):**
`create_token`, `revoke_token`, `create_project`, `create_environment`,
`get_secret` (read audit), `rollback_secret`, `delete_secret`, `rollback_config`,
`delete_config`. Each is a clean `tenant_tx → work → commit`. Audit slots in
before `commit()`.

**Tier 2 — 2 ledger-split ops (`put_secret`, `put_config`):**
These span **three** transactions; the real write is inside
`ledger::advance_secret_version` / `advance_config_version` (own tx). Making
audit atomic here requires threading the sink + audit event into those ledger
functions. **Bonus:** doing so also closes a pre-existing 3-transaction
atomicity gap in these two methods (a crash between the sub-transactions can
half-write a secret today).

## Design: how the wrapper gets the transaction

The wrapper can't be a pure outer newtype for the atomic case, because to be
atomic the audit write must be *inside* the op's own transaction — which lives
inside `PgDataStore`. So the real mechanism:

1. `PgDataStore` gains an optional `audit: Option<Arc<LocalSink>>` field. When
   set, each of the 11 concrete methods calls
   `self.record_audit_in_tx(&mut tx, ctx)` just before its `commit()`.
2. The audit context (actor_id, actor_role, event_type, resource_type,
   resource_id) is passed **into** the concrete `PgDataStore` methods. Two
   sub-options for *how*:
   - **(a)** Add an `audit_ctx: Option<AuditCtx>` parameter to the 11 concrete
     methods (not the trait — only the impl). The trait stays unchanged; the API
     layer calls the concrete methods through a typed handle that carries the ctx.
   - **(b)** Keep the trait, add 11 new trait methods like
     `create_token_audited(&self, ..., ctx: AuditCtx)` that wrap the existing
     ones. More surface, but object-safe and explicit.

   → **Plan picks (a)** with a small `AuditCtx` struct, because it's the smallest
   change that keeps the trait clean. The "AuditedDataStore wrapper" you chose is
   realized as: the API layer holds the store, builds an `AuditCtx` from the
   `Principal` + operation, and the concrete store records it atomically. (If (a)
   proves awkward against the `dyn DataStore` boundary during build, fall back to
   (b) — noted as the contingency.)

3. `make_audit_event` is split: the **envelope** (idempotency_key, occurred_at,
   source_service, metadata) is built inside the sink/storage; the **caller data**
   (actor, role, event_type, resource) comes from `AuditCtx`.

## Step-by-step

### Phase A — plumbing (no behavior change yet)
1. Define `AuditCtx { actor_id: Uuid, actor_role: String, event_type: &'static str, resource_type: &'static str, resource_id: String }` in soma-storage.
2. Add `audit: Option<Arc<LocalSink>>` to `PgDataStore`; constructor variant
   `with_audit(pool, kek, sink)`. Wire it in `main.rs` (the sink already exists
   in `AppState`; move/clone it into the store).
3. Add a private `PgDataStore::record_audit_in_tx(&self, tx: &mut Transaction, ctx: &AuditCtx)`
   that builds the `AuditEvent` (Outcome::Success) and calls
   `sink.record_in_tx(&event, tx)`. No-op if `audit` is None (keeps tests/other
   callers working).

### Phase B — Tier 1 (the 9 clean ops)
4. For each of the 9, change the concrete method to accept `audit_ctx: Option<AuditCtx>`
   and call `record_audit_in_tx` before `commit()`. Update the API call sites to
   pass the ctx and DROP the now-redundant `state.audit.record(&ev)` call.

### Phase C — Tier 2 (put_secret, put_config + the latent bug)
5. Refactor `advance_secret_version` / `advance_config_version` to accept the
   optional sink + ctx and record before their `commit()`. Where feasible, merge
   the header-upsert tx and the ledger tx into one `tenant_tx` so the secret/config
   write + audit are a single atomic transaction (closes the latent 3-tx gap).
   This is the riskiest step — do it last, isolated.

### Phase D — denials (API layer)
6. In each handler's `principal.require(min_role)` Err arm (and any other
   pre-storage 403/validation rejection), record an `Outcome::Denied` event via
   `state.audit.record(&ev)` before returning the 403. Helper to keep call sites
   small.

### Phase E — cleanup + verify
7. Remove `make_audit_event`'s success-path duplication from the API layer where
   it moved to storage; keep a denial variant.
8. Update tests: the ported `test_audit_rbac` should now assert the audit row
   exists **after a rolled-back business tx does NOT** (a new atomicity test:
   force a storage error mid-op, assert no audit row). Add a denial test (403 →
   one Denied audit row).
9. `cargo build` + `cargo clippy -D warnings` + run the vault test suite against
   Postgres.

## Acceptance criteria

- All 11 success events recorded **inside** the storage transaction (atomic).
- A storage op that errors/rolls back leaves **no** audit row (proven by test).
- 403 denials produce exactly one `Outcome::Denied` audit row.
- `/v1/audit` + `/v1/audit/verify` still work; chain verifies.
- `put_secret`/`put_config` write secret + version + audit in one transaction.
- Build + clippy clean; vault tests green.

## Risk & sequencing

- **Tier 1 (Phase B) is low-risk** and delivers most of the value — could even
  be committed before Tier 2.
- **Tier 2 (Phase C) is the risk** — it restructures `ledger.rs`. Isolated, done
  last, with its own test.
- **No DB right now (Docker down)** — Phases verified by `cargo build`/`clippy`
  during the work; the full DB test run is the final gate once Postgres is back.
  The plan does NOT consider itself done until the DB tests pass.
- Contingency: if `AuditCtx`-as-parameter fights the `dyn DataStore` boundary,
  fall back to explicit `*_audited` trait methods (sub-option b).

## Out of scope

- Forwarding vault's events to a central soma-audit-server (the Remote/Both
  mode) — separate, later.
- Capturing `actor_ip` (currently always None) — a small separate improvement.
