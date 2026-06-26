# soma-vault Phase 1 Dashboard

The soma-vault dashboard is a Leptos CSR single-page application embedded in the `soma-vault-server` binary. It provides secret CRUD, typed config CRUD with live SSE updates, workspace member management, an audit log viewer, and a health/seal-status page — all using the `soma-ui` design system (Palantir slate/blue, Outfit + Rajdhani, light and dark themes). The binary serves it as static WASM/JS from `GET /*` after API route matching; no separate web server is required.

---

## 1. Technology Constraints

| Constraint | Detail |
|---|---|
| Framework | Leptos 0.7.x CSR, `wasm32-unknown-unknown` |
| Build | Trunk + Tailwind CSS; output embedded via `include_dir!` |
| Design primitives | `soma-ui` crate only — no new tokens or primitives in the dashboard crate |
| Dashboard-specific components | `dashboard/src/components/` — thin compositions of `soma-ui` primitives |
| Browser APIs | `web_sys` / `leptos::web_sys` only; zero hand-written JS |
| Session token storage | httpOnly + Secure + SameSite=Strict cookie set by the server at `/v1/auth/login`; the WASM client never reads the token directly |

The httpOnly cookie choice (rather than `sessionStorage`) is mandatory for a secrets management dashboard. An XSS payload that reads `sessionStorage` would immediately have token access to all secrets the principal can reach. CSRF protection uses the Double Submit Cookie pattern: the server also sets a non-httpOnly `sv_csrf` cookie; every mutating request echoes it in the `X-CSRF-Token` header; the axum middleware validates the match.

---

## 2. Authentication Flow

### 2.1 OIDC Path (soma-iam, production)

1. Dashboard loads, checks for a valid soma-vault session cookie via `GET /v1/auth/session` (200 = proceed, 401 = redirect to `/login`).
2. `/login` renders a "Sign in with soma-iam" button that initiates Authorization Code + PKCE redirect to soma-iam's authorization endpoint.
3. soma-iam redirects back to `/auth/callback?code=...&state=...`.
4. `AuthCallbackPage` calls `POST /v1/auth/login` with the code; the server validates the soma-iam JWT (RS256/ES256, `aud=["soma-vault"]`, `tid` claim required), issues a soma-vault session token as an httpOnly cookie, and responds 200.
5. Dashboard navigates to `/secrets`.

### 2.2 Universal Auth Path (local dev, machine identities)

`/login` also exposes a collapsible "Use Universal Auth" form with Client ID and Client Secret inputs. On submit it calls `POST /v1/auth/universal`; the server validates with Argon2id and sets the same httpOnly session cookie. This path remains available in production for service accounts that do not have a soma-iam machine identity.

### 2.3 Development Stub

While soma-iam is not yet built, a minimal `soma-vault-auth-stub` binary (approximately 100-line axum handler) signs RS256 JWTs with a hardcoded key pair, satisfying the `aud`, `iss`, `tid`, and `sub` claims required by soma-vault's JWT validator. This stub is a dev-only tool, not shipped in the production binary.

---

## 3. Route Structure

All routes are client-side routes managed by `leptos_router`. The persistent `AppShell` mounts once and never full-page-reloads on navigation.

```
/login                         LoginPage         (unauthenticated)
/auth/callback                 AuthCallbackPage  (OIDC code exchange)

/                              → redirect to /secrets (auth'd) or /login

/secrets                       SecretsListPage
/secrets/new                   SecretCreatePage
/secrets/:secret_id            SecretDetailPage  (version history, edit, rollback)

/config                        ConfigListPage    (SSE-live)
/config/new                    ConfigCreatePage
/config/:config_key_id         ConfigDetailPage  (versions, overrides, diff)

/access                        AccessPage        (members + service accounts)
/access/service-accounts/new   ServiceAccountCreatePage

/audit                         AuditLogPage
/health                        HealthStatusPage
```

### Active Context

Workspace, project, and environment context lives in a reactive global provided at `AppShell` level. Project and environment IDs appear in the URL for deep-linking and back-button support; workspace selection is stored in the reactive signal only (persisted to `localStorage` as the last-used workspace ID across sessions).

```rust
#[derive(Clone, Debug, PartialEq)]
pub struct ActiveContext {
    pub tenant_id:   Uuid,
    pub workspace:   WorkspaceSummary,
    pub project:     ProjectSummary,
    pub environment: EnvironmentSummary,  // includes inherits_from: Option<Uuid>
}
```

---

## 4. AppShell Layout

Two-column flex layout: fixed 240 px sidebar on the left, scrollable main content area on the right. Below 768 px the sidebar collapses to a slide-in Drawer triggered by a hamburger button in the mobile topbar.

```
┌──────────────────────────────────────────────────────┐
│ Sidebar (240px, fixed, bg-card, border-e)            │
│   Brand: soma-vault logo + version badge             │
│   WorkspaceSwitcher (Popover + Command)              │
│   ─────────────────────────────────────────────      │
│   ProjectSelector  (Select)                          │
│   EnvironmentSelector (Select, inherited badge)      │
│   ─────────────────────────────────────────────      │
│   Nav: SECRETS → Secrets                             │
│   Nav: CONFIGURATION → Config                        │
│   Nav: MANAGEMENT → Access / Audit Log / Health      │
│   ─────────────────────────────────────────────      │
│   User row (Avatar + name, dropdown: sign out)       │
│   ThemeToggle                                        │
├──────────────────────────────────────────────────────┤
│ Main (flex-1, overflow-y-auto, bg-background)        │
│   PageHeader (Breadcrumb + title + action slot)      │
│   ─────────────────────────────────────────────      │
│   Page content                                       │
└──────────────────────────────────────────────────────┘
```

A single `Toaster` is mounted at the AppShell root, providing the `ToastHandle` context for imperative notifications throughout the app.

---

## 5. Workspace and Context Switchers

### 5.1 WorkspaceSwitcher

Rendered in the sidebar header. Opens a `Popover` containing a `Command`-style searchable list populated from `GET /v1/workspaces` (tenant-scoped). Selecting a workspace:

1. Updates `active_context.workspace`.
2. Clears project and environment, triggering `ProjectSelector` reset.
3. Navigates to `/secrets`.

### 5.2 ProjectSelector and EnvironmentSelector

Two `Select` components stacked below the workspace switcher. Selecting a project resets the environment to the first in that project. The environment selector shows an "inherits" `Badge` (outline variant) next to names with a non-null `inherits_from`. Switching either selector navigates to the current page type within the new context.

---

## 6. Pages and Core Flows

### 6.1 Login Page (`/login`)

- soma-vault logo and product name.
- "Sign in with soma-iam" primary `Button` → OIDC PKCE redirect.
- "Use Universal Auth" collapsible inline form (Client ID + Client Secret `Input` fields).
- `ThemeToggle` in the top-right corner.

### 6.2 Auth Callback (`/auth/callback`)

No visible UI while processing (shows `Spinner`). On error: `Alert` (destructive variant) with the error reason and a "Return to login" link.

### 6.3 Secrets List (`/secrets`)

`PageHeader` with "Secrets" title and "New Secret" primary `Button`.

| Column | Sortable | Notes |
|---|---|---|
| path | yes | Monospace; clicking navigates to `SecretDetailPage` |
| current_version | no | Integer `Badge` |
| updated_at | yes | Relative time; full timestamp in `Tooltip` |
| actions | no | Reveal button + `DropdownMenu` (Copy path, Delete) |

**Reveal flow.** The "Reveal" button fires `GET /v1/secrets/:id/value`. On response, the plaintext is written directly into a readonly `Input` via a `NodeRef` — never assigned to a Rust signal that could be cloned or retained across reactive boundaries. A copy-to-clipboard button appears. A 30-second `gloo_timers::callback::Timeout` clears the field and returns it to masked state.

**Delete flow.** `AlertDialog` (destructive) with confirmation. On confirm: `DELETE /v1/secrets/:id`. Success/error `Toast`.

**Search.** Debounced 300 ms filter drives a server-side query parameter via a `Resource` refresh.

### 6.4 Secret Create/Edit (`/secrets/new`, `/secrets/:id`)

Two-panel layout: form on the left, version history on the right (detail page only).

**Create form:**

| Field | Component | Notes |
|---|---|---|
| Path | `Input` | Validates no leading slash |
| Value | `Textarea` | Password-style; no clipboard sniffing |
| Max Versions | `Input` (number) | Default 20 |
| CAS Required | `Switch` | Default off |

Submit: `POST /v1/secrets` → navigate to `/secrets/:id`.

**Detail page additions:**

- Current value: masked by default; "Reveal" uses the same inline flow as the list page.
- "Edit Value": inline `Textarea` with Save; passes `expected_version` for CAS. A 409 mismatch shows a destructive `Toast` explaining the conflict.
- Version history panel (`ScrollArea`): version number, `created_at`, `created_by`, soft-delete/destroy state. Per row:
  - "Rollback to this version" → `AlertDialog` confirmation → `POST /v1/secrets/:id/rollback?to_version=N`. The server always generates a fresh DEK and nonce for the new version; it never copies the source version's `wrapped_dek` or nonce.
  - "Soft Delete" → `DELETE /v1/secrets/:id/versions/:v` (recoverable).
  - "Destroy" → `AlertDialog` (destructive) requiring the user to type `DESTROY` in an `Input` before the confirm button enables.

### 6.5 Config List (`/config`)

| Column | Sortable | Notes |
|---|---|---|
| path | yes | Clicking navigates to `ConfigDetailPage` |
| value_type | yes | `Badge` (outline): string / int / float / bool / json / secret_ref |
| value_preview | no | Truncated 60 chars; `secret_ref` shows shield icon + UUID only |
| updated_at | yes | Relative time |
| actions | no | Edit `Button` + `DropdownMenu` (Delete) |

**Inherited values.** When the active environment inherits from a parent, rows resolved from the parent show an "inherited" `Badge` (secondary variant) in the path column. Rows with a local override show no badge.

**SSE live updates.** On mount, a `leptos::spawn_local` task opens `web_sys::EventSource` to `GET /v1/config/stream?project_id=X&env_id=Y`. On each `ConfigChangeEvent`:

- The matching row in the config signal is updated reactively.
- A `Toast` (info, auto-dismiss 3 s) shows "Config updated: `path`".
- `secret_ref` events carry only `secret_id: Uuid` — never a resolved plaintext value.

On EventSource error, a "polling fallback" badge appears and the page falls back to 60-second polling until reconnection.

```rust
// ponytail: one EventSource per (project_id, env_id) for the lifetime of the page.
// Ceiling: one open HTTP/2 connection per browser tab.
// Upgrade path: SharedWorker if browser connection limits are hit.
Effect::new(move |_| {
    let url = format!("/v1/config/stream?project_id={}&env_id={}", proj_id, env_id);
    let es = web_sys::EventSource::new(&url).expect("EventSource");
    // on message: update relevant row in config_rows signal
    // on error: set sse_connected = false
    on_cleanup(move || es.close());
});
```

### 6.6 Config Create/Edit (`/config/new`, `/config/:id`)

**Create form:**

| Field | Component | Notes |
|---|---|---|
| Path | `Input` | e.g. `feature/dark-mode` |
| Value Type | `Select` | string, int, float, bool, json, secret_ref |
| Value | Dynamic (see below) | |
| JSON Schema | `Textarea` | Shown when value_type=json; validated client-side on blur |
| Is Sensitive | `Switch` | Redacts value in audit log; does not encrypt |

**Dynamic value field by type:**

- `string` → `Input` (text)
- `int`, `float` → `Input` (number)
- `bool` → `Switch`
- `json` → `Textarea` (monospace); client-side JSON parse on blur
- `secret_ref` → `Select` populated from `GET /v1/secrets?path_prefix=` search; displays secret path, stores UUID. Secret refs are restricted to secrets within the **same environment** — the server enforces this; the selector only fetches secrets for the active environment.

**Schema validation feedback.** When the server rejects a write due to JSON Schema validation, the response body includes `schema_path`, `instance_path`, and `error_message`. These are rendered in an `Alert` (destructive variant) below the value field.

**Detail page additions:**

- Versions tab (`Tabs`): typed value per version (no reveal needed — config is plaintext). Selecting two versions shows a `ConfigVersionDiff` — a side-by-side before/after `Card` pair.
- Overrides tab: read-only `Table` of (environment name, resolved value, is_override) across all environments in the project. Environments inheriting the value show a secondary badge. Editing in another environment requires switching to that environment first.

### 6.7 Access Page (`/access`)

Two tabs via `Tabs`: "Members" and "Service Accounts".

**Members tab.** `DataTable` from `GET /v1/workspaces/:id/members`. Columns: Avatar + name, email, role `Badge`, last active, remove button (disabled for current user). Role is an inline `Select` (ws:admin / ws:developer / ws:reader) for ws:admin users. "Add Member" opens a `Dialog` with an email `Input` and role `Select`; submits to `POST /v1/workspaces/:id/members`.

**Service Accounts tab.** `DataTable` from `GET /v1/service-accounts`. Columns: name, `created_at`, `last_used_at` (or "Never"), actions (view credentials, rotate secret, revoke).

**ServiceAccountCreatePage.** Name `Input` + description `Textarea`. On submit: `POST /v1/service-accounts`. The response contains `client_id` and `client_secret` (one-time display). The page transitions to a full-panel `ServiceAccountCredentialReveal` card:

```
┌──────────────────────────────────────────────────────┐
│ Service account created                              │
│                                                      │
│ Save these credentials now. They cannot be           │
│ retrieved again.                                     │
│                                                      │
│ Client ID      [uuid]                    [Copy]      │
│ Client Secret  [••••••••••••••••••] [Reveal][Copy]   │
│                                                      │
│ ○ I have saved these credentials                     │
│                                                      │
│ [ Continue ]  ← disabled until Switch is on          │
└──────────────────────────────────────────────────────┘
```

The Continue button remains disabled until the user toggles the `Switch`. This gate is non-negotiable — it is the only opportunity to view the secret.

**Secret rotation.** Each service account row includes a "Rotate Secret" action that calls `POST /v1/workspaces/:id/service-accounts/:sa_id/rotate-secret`. The response triggers the same one-time credential reveal card for the new secret only.

**Path-Capability Policies.** A collapsible `Accordion` below the tabs shows workspace path-glob policies from `GET /v1/policies` — read-only in Phase 1. Each row shows path_glob, capabilities (`Badge` list), and principal.

### 6.8 Audit Log (`/audit`)

`PageHeader` with "Audit Log" title and "Verify Chain" action `Button`.

**Filter bar:**

| Filter | Component | API parameter |
|---|---|---|
| Event Type | `Select` (multi) | `event_type` |
| Actor | `Input` (search) | `actor_id` |
| Date range | `DatePicker` | `from`, `to` |
| Outcome | `Select` | `outcome` |

**DataTable columns:**

| Column | Notes |
|---|---|
| created_at | Full timestamp in `Tooltip` on hover |
| event_type | `Badge` by group: secret=primary, config=secondary, auth=outline |
| actor | actor_type icon + display name (email for humans, name for service accounts) |
| resource | resource_type + resource_name (HMAC-hashed path, displayed as-is in Phase 1) |
| outcome | `Badge`: success=success, denied/error=destructive |
| reason | Plain text if present; "—" if null |

Resource names are displayed as their HMAC-hashed values without any client-side resolution attempt. Resolving to a human-readable path is a server-side feature deferred to Phase 2.

**Polling.** A `leptos::Interval` at 30 s re-fetches with `cursor` (last `seq_num` seen) and prepends new rows.

**Verify Chain.** Fires `GET /v1/audit/verify?from=&to=` using the current filter's date range (or last 24 h if unfiltered). Opens an `AuditChainVerifyDialog`: either "Chain intact — N events verified" (`Alert` success variant) or "Tamper detected at seq_num X" (`Alert` destructive). The button shows a `Spinner` during the request and is disabled for 60 s after completion (server-side rate limit enforced independently).

### 6.9 Health Status (`/health`)

Polled every 30 s via `GET /health/ready`. No SSE needed for this page.

**Seal status card:**

| Metric | Component | Notes |
|---|---|---|
| Seal Backend | `Badge` | aws_kms (success) / software_kms (warning) |
| KMS Status | `Badge` | reachable (success) / unreachable (destructive) |
| Grace Period Mode | `Alert` (warning) | Shown only when `degraded: true` |
| Active Alerts | `Badge` list | e.g. kms_unreachable |

When `seal_backend: software_kms`, a persistent `Alert` (warning variant) appears at the top:

> **Software KMS active.** The master key is protected by a mounted Kubernetes Secret environment variable, not a cloud HSM. This provides lower security assurance than AWS KMS / GCP KMS auto-unseal. Upgrade instructions: [link to docs].

This banner is never dismissible. It remains visible for the lifetime of the session while software KMS is active.

**System card:**

| Metric | Display |
|---|---|
| Database | connected / degraded `Badge` |
| Leptos build hash | Monospace string from build-time env var |

---

## 7. Component Inventory

### 7.1 soma-ui Primitives (used as-is, no modification)

| Component | Category | Used in |
|---|---|---|
| `Button` | inputs | Every page — primary, destructive, ghost, icon-size |
| `Input` | inputs | Forms, search, secret reveal, DESTROY confirmation |
| `Textarea` | inputs | Secret value, config JSON, description |
| `Select` | inputs | Workspace/project/environment/type selectors |
| `Switch` | inputs | CAS, is_sensitive, service account credential gate |
| `Checkbox` | inputs | DataTable row selection |
| `Card` | data_display | Health metrics, one-time credential reveal |
| `Badge` | data_display | Event types, seal status, value_type labels, outcome |
| `DataTable` | data_display | Secrets, config, members, service accounts, audit log |
| `Table` | data_display | Per-environment override display (simple, no pagination) |
| `Avatar` | data_display | User row in sidebar, members table |
| `Empty` | data_display | Empty states on all list pages |
| `Accordion` | disclosure | Policies section on Access page |
| `Alert` | feedback | Health warnings, auth errors, chain verify result |
| `Spinner` | feedback | Auth callback, async loads |
| `Skeleton` | feedback | DataTable loading states (avoids layout shift) |
| `Toast` / `Toaster` | feedback | Success/error/info notifications |
| `Tabs` | navigation | Access page, Config detail (Versions / Overrides / Diff) |
| `Breadcrumb` | navigation | PageHeader: Workspace > Project > Environment |
| `Pagination` | navigation | DataTable built-in |
| `Separator` | layout | Sidebar section dividers |
| `ScrollArea` | layout | Sidebar nav, version history panel |
| `Dialog` | overlays | Chain verify result, Add Member |
| `AlertDialog` | overlays | Destructive confirmations (delete, destroy, rollback) |
| `Popover` | overlays | WorkspaceSwitcher |
| `Command` | overlays | Searchable list inside WorkspaceSwitcher |
| `Tooltip` | overlays | Full timestamp on audit rows, truncated paths |
| `DropdownMenu` | overlays | Row action menus in DataTable |
| `ThemeToggle` | interaction | Login page + sidebar footer |

### 7.2 Dashboard-Specific Compound Components

In `dashboard/src/components/`. Each is a thin composition of the primitives above.

| Component | Description |
|---|---|
| `AppShell` | Sidebar + main area layout, mobile Drawer toggle |
| `PageHeader` | `Breadcrumb` + title (font-heading) + optional action slot |
| `WorkspaceSwitcher` | `Popover` + `Command`; reads/writes `ActiveContext` |
| `EnvironmentBadge` | `Badge` with optional "inherits" indicator |
| `SecretRevealRow` | Reveal button + masked/revealed `Input` + copy + `NodeRef`-based auto-hide |
| `VersionHistoryPanel` | `ScrollArea` list: rollback / soft-delete / destroy per row |
| `ConfigVersionDiff` | Before/after `Card` pair for two selected config versions |
| `SealStatusBanner` | Persistent `Alert` for software_kms or degraded state |
| `ServiceAccountCredentialReveal` | One-time credential card with `Switch` gate |
| `AuditChainVerifyDialog` | `Dialog` + inner `Alert` for verify result |

---

## 8. Reactive Data Patterns

### 8.1 Server Resources

Standard pattern for all API reads:

```rust
let secrets = Resource::new(
    move || (ctx.project.id, ctx.environment.id, filter.get()),
    move |(proj, env, f)| async move { fetch_secrets(proj, env, f).await },
);

view! {
    <Suspense fallback=|| view! { <DataTableSkeleton /> }>
        {move || secrets.get().map(|r| match r {
            Ok(rows) => view! { <SecretsTable rows /> }.into_any(),
            Err(e)   => view! {
                <Alert variant=AlertVariant::Destructive>
                    <AlertTitle>{e.to_string()}</AlertTitle>
                </Alert>
            }.into_any(),
        })}
    </Suspense>
}
```

### 8.2 Secret Reveal — Security-Critical Pattern

Secret plaintext never enters a Rust signal. The reveal writes directly to the DOM:

```rust
// NEVER: let plaintext = create_signal(value); // would be Clone-able, Debug-printable
// CORRECT:
let input_ref: NodeRef<Input> = NodeRef::new();
spawn_local(async move {
    if let Ok(value) = fetch_secret_value(secret_id).await {
        if let Some(el) = input_ref.get() {
            el.set_value(&value);
            // value drops here — no Rust binding survives
        }
        gloo_timers::callback::Timeout::new(30_000, move || {
            if let Some(el) = input_ref.get() { el.set_value(""); }
        }).forget();
    }
});
```

### 8.3 Global Context Initialization

On first authenticated load:

1. `GET /v1/workspaces` → pick first (or `localStorage` last-used) workspace.
2. `GET /v1/projects?workspace_id=X` → pick first project.
3. `GET /v1/environments?project_id=Y` → pick first environment.

Subsequent navigation within the session preserves the selected context.

---

## 9. Security Constraints

These are behavioral requirements enforced in the WASM layer, not optional UX polish.

| Constraint | Implementation |
|---|---|
| Secret plaintext never in a Rust signal | `NodeRef`-based reveal; `gloo_timers` auto-clear at 30 s |
| Secret plaintext never in SSE stream | `ConfigChangeEvent` carries typed scalar only; `secret_ref` events carry `secret_id: Uuid` only |
| Secret plaintext never in config API response | `secret_ref` config keys show a "Fetch Secret" button that triggers a separate `GET /v1/secrets/:id/value`; the config fetch itself returns only the UUID |
| Tenant isolation is server-enforced | Dashboard has no client-side tenant filtering; all scoping is determined by the server based on the session cookie |
| Audit resource names displayed as-is | `resource_name` column renders the HMAC hash without any client-side resolution |
| Destroy requires typed confirmation | `AlertDialog` `Input` must match the literal string `"DESTROY"` before the confirm button enables |
| Session token XSS-immune | httpOnly cookie; WASM client never reads or stores the token |
| CSRF protection | Double Submit Cookie (`sv_csrf` non-httpOnly cookie echoed in `X-CSRF-Token` header on all mutations) |
| One-time service account secret | `Switch` gate blocks Continue until explicitly acknowledged |

---

## 10. Responsive Design

| Breakpoint | Behavior |
|---|---|
| < 768 px | Sidebar hidden; hamburger `Button` opens Drawer; workspace/project/environment selectors inside Drawer |
| 768–1024 px | Sidebar visible at 240 px; DataTable hides lower-priority columns (updated_at, actor details) |
| > 1024 px | Full layout; all DataTable columns visible |

All page content uses `max-w-7xl mx-auto px-4 sm:px-6 lg:px-8` inside the main area.

---

## 11. Theme

`ThemeToggle` from `soma-ui` interaction category writes `class="dark"` to `<html>` and persists the preference in `localStorage`. All color values reference the CSS custom properties defined in `soma-ui`'s token set. The dashboard imports only the `soma-ui` stylesheet:

```css
/* dashboard/style/main.css */
@import "../../../../soma-ui/playground/style/main.css";
```

No new design tokens are defined in the dashboard crate.

---

## 12. Cargo Dependencies

```toml
[dependencies]
leptos        = { version = "0.7", features = ["csr"] }
leptos_router = { version = "0.7", features = ["browser"] }
soma-ui       = { path = "../soma-ui/packages/ui" }
serde         = { version = "1", features = ["derive"] }
serde_json    = "1"
uuid          = { version = "1", features = ["serde", "js"] }
wasm-bindgen  = "0.2"
web-sys       = { version = "0.3", features = [
    "EventSource", "EventSourceInit",
    "Storage", "Window", "HtmlInputElement"
] }
gloo-timers   = "0.3"   # Timeout for secret auto-clear
```

No HTTP client crate: `GET` calls use `leptos::Resource` with `spawn_local` + `wasm_bindgen_futures`. `POST`/`PUT`/`DELETE` use `leptos::server` actions. The session cookie is attached by the browser automatically; no manual Authorization header handling in WASM.

---

## 13. Build and Embedding

```toml
# dashboard/Trunk.toml
[build]
target = "index.html"
dist   = "../server/static"
```

```rust
// soma-vault-server/build.rs
let static_dir = include_dir!("$CARGO_MANIFEST_DIR/static");
```

The server mounts the static directory on `GET /*` using `axum::Router::nest_service` with `tower_http::services::ServeDir`, after all `/v1/*` and `/health/*` routes are matched. `index.html` references the WASM bundle and CSS; all requests are same-origin, so CORS is not required.

---

## 14. Phase 1 Out-of-Scope

These features must not be partially implemented or scaffolded in the dashboard codebase.

| Feature | Phase |
|---|---|
| Approval / change-request workflow UI | 2 |
| Path-capability policy editor (create / edit / delete) | 2 |
| A/B flag targeting rules UI | 2 |
| SIEM streaming configuration UI | 2 |
| Secret auto-refresh in the reveal UI | 2 |
| Per-secret granular permission grant UI | 2 |
| Rotation job trigger and status UI | 2 |
| Per-environment KMS key (BYOK) configuration UI | 2 |
| Dynamic secrets issuance UI | 2 |
| Multi-region failover configuration UI | 3 |
| Honey token creation UI | 3 |
| Dashboard login via SAML | soma-iam concern |
| Per-CI-provider OIDC configuration | soma-iam concern |
| Notification preferences or webhook configuration | 2 |
| Usage metrics or billing dashboard | 2 / SaaS-only |

---

## 15. Verification Gate

Phase 1 dashboard is shippable when a solo developer can complete all of the following without consulting the CLI or any external tool:

1. Open the dashboard, complete Universal Auth login (or OIDC if the stub is running), and reach the Secrets list page within 30 seconds.
2. Create a secret with a path, value, and CAS enabled; confirm the version shows as 1.
3. Reveal the secret value; confirm it auto-hides after 30 seconds.
4. Create a JSON config key with an attached JSON Schema; submit an invalid value and confirm a schema error appears.
5. Change a config value in one browser tab; confirm the other tab's list updates within 2 seconds via SSE push.
6. Create a service account, acknowledge the `Switch` gate, copy the one-time credentials, and confirm they cannot be retrieved again from the service account detail page.
7. View the audit log and confirm the reveal action from step 3 appears as a `secret_read` event with no plaintext in any column.
8. Open the Health page and confirm the seal status shows the correct KMS backend and no active alerts.
