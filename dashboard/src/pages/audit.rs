use crate::api::{get_audit, get_me, verify_audit, AuditEvent, AuditVerifyResult, Page};
use crate::util::relative_time;
use leptos::prelude::*;
use soma_ui::{
    Alert, AlertDescription, AlertTitle, AlertVariant, Badge, BadgeVariant, Button, ButtonSize,
    ButtonVariant, Empty, PageHeader, Select, SelectContent, SelectItem, Spinner, Table,
    TableBody, TableCell, TableHead, TableHeader, TableRow,
};

const EVENT_TYPES: &[&str] = &[
    "secret.write",
    "secret.read",
    "secret.delete",
    "secret.rollback",
    "config.write",
    "config.read",
    "config.delete",
    "project.create",
    "environment.create",
    "token.create",
    "token.revoke",
];

fn outcome_badge(outcome: &str) -> impl IntoView {
    let label = outcome.to_string();
    let variant = match outcome {
        "success" => BadgeVariant::Success,
        "denied" => BadgeVariant::Destructive,
        _ => BadgeVariant::Secondary,
    };
    view! { <Badge variant=variant>{label}</Badge> }
}

fn event_type_badge(event_type: &str) -> impl IntoView {
    let label = event_type.to_string();
    let variant = if event_type.contains("delete") || event_type.contains("revoke") {
        BadgeVariant::Destructive
    } else if event_type.contains("write") || event_type.contains("create") {
        BadgeVariant::Default
    } else {
        BadgeVariant::Secondary
    };
    view! { <Badge variant=variant>{label}</Badge> }
}

fn short_id(id: &str) -> String {
    if id.len() > 8 {
        format!("{}…", &id[..8])
    } else {
        id.to_string()
    }
}

#[component]
pub fn AuditPage() -> impl IntoView {
    // Check role first; non-admins get a 403 from the API anyway, but we surface it cleanly.
    let me = LocalResource::new(|| async { get_me().await });

    let event_type_filter = RwSignal::new(String::new());
    let cursor: RwSignal<Option<String>> = RwSignal::new(None);
    let events: RwSignal<Vec<AuditEvent>> = RwSignal::new(vec![]);
    let next_cursor: RwSignal<Option<String>> = RwSignal::new(None);
    let load_err: RwSignal<Option<String>> = RwSignal::new(None);
    let loading = RwSignal::new(false);
    let initial_loaded = RwSignal::new(false);

    let verify_result: RwSignal<Option<Result<AuditVerifyResult, String>>> = RwSignal::new(None);
    let verifying = RwSignal::new(false);

    // Load initial page
    let load_events = move |append: bool| {
        let et = event_type_filter.get();
        let cur = if append { cursor.get() } else { None };
        loading.set(true);
        load_err.set(None);
        leptos::task::spawn_local(async move {
            match get_audit(
                if et.is_empty() { None } else { Some(et) },
                cur,
                50,
            )
            .await
            {
                Ok(Page { items, next_cursor: nc }) => {
                    if append {
                        events.update(|v| v.extend(items));
                    } else {
                        events.set(items);
                    }
                    next_cursor.set(nc.clone());
                    cursor.set(nc);
                    initial_loaded.set(true);
                }
                Err(e) => {
                    load_err.set(Some(e.message));
                    initial_loaded.set(true);
                }
            }
            loading.set(false);
        });
    };

    // Trigger initial load when me resolves (so we know role)
    let load_once = move || {
        if !initial_loaded.get() && !loading.get() {
            load_events(false);
        }
    };

    let on_verify = move |_| {
        verifying.set(true);
        verify_result.set(None);
        leptos::task::spawn_local(async move {
            let r = verify_audit().await.map_err(|e| e.message);
            verify_result.set(Some(r));
            verifying.set(false);
        });
    };

    let on_filter_change = move || {
        cursor.set(None);
        events.set(vec![]);
        next_cursor.set(None);
        initial_loaded.set(false);
        load_events(false);
    };

    view! {
        <div class="space-y-6">
            <PageHeader title="Audit Log".to_string()>
                <Button
                    variant=ButtonVariant::Outline
                    size=ButtonSize::Sm
                    on:click=on_verify
                >
                    {move || if verifying.get() {
                        view! { <span class="flex items-center gap-2"><Spinner />"Verifying…"</span> }.into_any()
                    } else {
                        view! { <span>"Verify chain"</span> }.into_any()
                    }}
                </Button>
            </PageHeader>

            // Chain verification result
            {move || verify_result.get().map(|result| match result {
                Ok(v) => if v.ok {
                    view! {
                        <Alert variant=AlertVariant::Default>
                            <AlertTitle>
                                <span class="text-green-600 dark:text-green-400">
                                    "✓ Audit log verified"
                                </span>
                            </AlertTitle>
                            <AlertDescription>
                                {format!("{} entries intact, chain unbroken.", v.entries_checked)}
                            </AlertDescription>
                        </Alert>
                    }.into_any()
                } else {
                    view! {
                        <Alert variant=AlertVariant::Destructive>
                            <AlertTitle>
                                "✗ Chain integrity failure"
                            </AlertTitle>
                            <AlertDescription>
                                {match v.first_broken_seq {
                                    Some(seq) => format!("Chain broken at entry #{seq} — possible tampering. Checked {} entries.", v.entries_checked),
                                    None => format!("Integrity check failed after {} entries.", v.entries_checked),
                                }}
                            </AlertDescription>
                        </Alert>
                    }.into_any()
                },
                Err(e) => view! {
                    <Alert variant=AlertVariant::Destructive>
                        <AlertTitle>"Verification failed"</AlertTitle>
                        <AlertDescription>{e}</AlertDescription>
                    </Alert>
                }.into_any(),
            })}

            // Access-denied state for non-admins
            <Suspense fallback=|| view! { <></> }>
                {move || me.get().map(|r| {
                    let is_admin = r.ok()
                        .and_then(|m| m.role)
                        .map(|role| role == "admin")
                        .unwrap_or(false);

                    if !is_admin {
                        // If not admin, skip loading and show gate
                        view! {
                            <Alert variant=AlertVariant::Warning>
                                <AlertTitle>"Admin access required"</AlertTitle>
                                <AlertDescription>
                                    "You need admin access to view the audit log."
                                </AlertDescription>
                            </Alert>
                        }.into_any()
                    } else {
                        // Trigger initial load for admins
                        load_once();
                        ().into_any()
                    }
                })}
            </Suspense>

            // Filters
            <div class="flex items-center gap-3">
                <div class="w-52">
                    <Select
                        value=event_type_filter
                        placeholder="All event types".to_string()
                    >
                        <SelectContent>
                            <SelectItem value="">"All event types"</SelectItem>
                            {EVENT_TYPES.iter().map(|et| {
                                let et = *et;
                                view! { <SelectItem value=et>{et}</SelectItem> }
                            }).collect::<Vec<_>>()}
                        </SelectContent>
                    </Select>
                </div>
                <Button
                    variant=ButtonVariant::Outline
                    size=ButtonSize::Sm
                    on:click=move |_| on_filter_change()
                >
                    "Apply"
                </Button>
            </div>

            // Load error
            {move || load_err.get().map(|e| {
                let is_forbidden = e.contains("403") || e.to_lowercase().contains("forbidden");
                view! {
                    <Alert variant=AlertVariant::Destructive>
                        <AlertTitle>{if is_forbidden { "Access denied" } else { "Failed to load audit log" }}</AlertTitle>
                        <AlertDescription>
                            {if is_forbidden {
                                "You need admin access to view the audit log.".to_string()
                            } else {
                                e
                            }}
                        </AlertDescription>
                    </Alert>
                }
            })}

            // Table / empty / loading
            {move || {
                if !initial_loaded.get() && loading.get() {
                    return view! { <div class="flex justify-center py-8"><Spinner /></div> }.into_any();
                }
                if initial_loaded.get() && events.get().is_empty() && load_err.get().is_none() {
                    return view! {
                        <Empty
                            title="No audit events yet".to_string()
                            description="Events will appear here as users and services interact with the vault.".to_string()
                        >
                            <svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="text-muted-foreground/40">
                                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                                <polyline points="14 2 14 8 20 8"/>
                                <line x1="16" y1="13" x2="8" y2="13"/>
                                <line x1="16" y1="17" x2="8" y2="17"/>
                                <polyline points="10 9 9 9 8 9"/>
                            </svg>
                        </Empty>
                    }.into_any();
                }
                if events.get().is_empty() {
                    return ().into_any();
                }
                view! {
                    <div class="space-y-4">
                        <Table>
                            <TableHeader>
                                <TableRow>
                                    <TableHead class="w-12".to_string()>"#"</TableHead>
                                    <TableHead>"Time"</TableHead>
                                    <TableHead>"Event"</TableHead>
                                    <TableHead>"Actor"</TableHead>
                                    <TableHead>"Resource"</TableHead>
                                    <TableHead>"Outcome"</TableHead>
                                </TableRow>
                            </TableHeader>
                            <TableBody>
                                <For
                                    each=move || events.get()
                                    key=|e| e.id.clone()
                                    children=move |ev| {
                                        let ts = ev.created_at.clone();
                                        let rel = relative_time(&ts);
                                        let actor_display = match (&ev.actor_token_id, &ev.actor_role) {
                                            (Some(id), Some(role)) => format!("{} ({})", short_id(id), role),
                                            (Some(id), None) => short_id(id),
                                            _ => "—".to_string(),
                                        };
                                        let resource_display = match (&ev.resource_type, &ev.resource_id) {
                                            (Some(rt), Some(rid)) => format!("{}/{}", rt, rid),
                                            (Some(rt), None) => rt.clone(),
                                            _ => "—".to_string(),
                                        };
                                        let event_type = ev.event_type.clone();
                                        let outcome = ev.outcome.clone();
                                        view! {
                                            <TableRow>
                                                <TableCell class="text-xs text-muted-foreground font-mono".to_string()>
                                                    {ev.seq_num}
                                                </TableCell>
                                                <TableCell class="text-xs text-muted-foreground".to_string()>
                                                    <span title=ts>{rel}</span>
                                                </TableCell>
                                                <TableCell>
                                                    {event_type_badge(&event_type)}
                                                </TableCell>
                                                <TableCell class="text-xs font-mono text-muted-foreground".to_string()>
                                                    {actor_display}
                                                </TableCell>
                                                <TableCell class="text-xs text-muted-foreground max-w-[200px] truncate".to_string()>
                                                    <span title=resource_display.clone()>{resource_display.clone()}</span>
                                                </TableCell>
                                                <TableCell>
                                                    {outcome_badge(&outcome)}
                                                </TableCell>
                                            </TableRow>
                                        }
                                    }
                                />
                            </TableBody>
                        </Table>

                        {move || next_cursor.get().map(|_| view! {
                            <div class="flex justify-center pt-2">
                                <Button
                                    variant=ButtonVariant::Outline
                                    size=ButtonSize::Sm
                                    on:click=move |_| load_events(true)
                                >
                                    {move || if loading.get() {
                                        view! { <span class="flex items-center gap-2"><Spinner />"Loading…"</span> }.into_any()
                                    } else {
                                        view! { <span>"Load more"</span> }.into_any()
                                    }}
                                </Button>
                            </div>
                        })}
                    </div>
                }.into_any()
            }}
        </div>
    }
}
