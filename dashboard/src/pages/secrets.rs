use crate::api::{del, get_json, put_json, Environment, Page, Project, SecretMeta, SecretPlaintext};
use crate::util::{copy_to_clipboard, relative_time};
use leptos::html;
use leptos::prelude::*;

/// Percent-encode a secret path so `/` within the path becomes `%2F`
/// and doesn't get parsed as a URL segment separator.
pub fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            b => {
                out.push('%');
                let hi = (b >> 4) & 0xF;
                let lo = b & 0xF;
                out.push(char::from_digit(hi as u32, 16).unwrap().to_ascii_uppercase());
                out.push(char::from_digit(lo as u32, 16).unwrap().to_ascii_uppercase());
            }
        }
    }
    out
}

use leptos_router::hooks::{use_navigate, use_params_map};
use serde::{Deserialize, Serialize};
use soma_ui::{
    Alert, AlertDescription, AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
    AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertTitle,
    AlertVariant, Badge, BadgeVariant, Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbPage,
    BreadcrumbSeparator, Button, ButtonSize, ButtonVariant, Dialog, DialogContent, DialogFooter,
    DialogHeader, DialogTitle, Empty, Input, Label, Spinner, Table, TableBody, TableCell, TableHead,
    TableHeader, TableRow, Textarea,
};

/// Body for PUT .../secrets/{path}
#[derive(Serialize, Deserialize)]
struct PutSecretReq {
    value: String,
}

/// Shared env tab bar: Secrets | Config, preserving pid/eid.
#[component]
pub fn EnvTabBar(pid: String, eid: String, active: &'static str) -> impl IntoView {
    let secrets_href = format!("/projects/{}/envs/{}/secrets", pid, eid);
    let config_href = format!("/projects/{}/envs/{}/config", pid, eid);

    let tab_cls = |is_active: bool| {
        if is_active {
            "px-4 py-2 text-sm font-medium border-b-2 border-primary text-foreground"
        } else {
            "px-4 py-2 text-sm font-medium border-b-2 border-transparent text-muted-foreground hover:text-foreground hover:border-border"
        }
    };

    view! {
        <div class="flex border-b border-border">
            <a href=secrets_href class=tab_cls(active == "secrets")>"Secrets"</a>
            <a href=config_href class=tab_cls(active == "config")>"Config"</a>
        </div>
    }
}

#[component]
pub fn SecretsPage() -> impl IntoView {
    let params = use_params_map();
    let pid = Memo::new(move |_| params.read().get("pid").unwrap_or_default());
    let eid = Memo::new(move |_| params.read().get("eid").unwrap_or_default());

    let base_url = Memo::new(move |_| {
        format!("/v1/projects/{}/environments/{}/secrets", pid.get(), eid.get())
    });

    // Fetch project + env names for breadcrumbs.
    let project = LocalResource::new(move || {
        let id = pid.get();
        async move {
            let page = get_json::<Page<Project>>("/v1/projects").await?;
            Ok::<Option<Project>, crate::api::ApiError>(page.items.into_iter().find(|p| p.id == id))
        }
    });
    let environment = LocalResource::new(move || {
        let p = pid.get();
        let e = eid.get();
        async move {
            let list = get_json::<Vec<Environment>>(&format!("/v1/projects/{}/environments", p)).await?;
            Ok::<Option<Environment>, crate::api::ApiError>(list.into_iter().find(|env| env.id == e))
        }
    });

    let reload = RwSignal::new(0u32);
    let secrets = LocalResource::new(move || {
        let _ = reload.get();
        let url = base_url.get();
        async move { get_json::<Page<SecretMeta>>(&url).await }
    });

    let show_dialog = RwSignal::new(false);
    let new_path = RwSignal::new(String::new());
    let new_value = RwSignal::new(String::new());
    let create_err: RwSignal<Option<String>> = RwSignal::new(None);

    let on_create = move |_| {
        let url = base_url.get();
        let path = new_path.get();
        let value = new_value.get();
        if path.is_empty() {
            return;
        }
        leptos::task::spawn_local(async move {
            let put_url = format!("{}/{}", url, percent_encode(&path));
            match put_json::<PutSecretReq, serde_json::Value>(&put_url, &PutSecretReq { value })
                .await
            {
                Ok(_) => {
                    show_dialog.set(false);
                    new_path.set(String::new());
                    new_value.set(String::new());
                    reload.update(|n| *n += 1);
                }
                Err(e) => create_err.set(Some(e.message)),
            }
        });
    };

    let navigate = use_navigate();

    // Derive names for breadcrumb display.
    let project_name = Memo::new(move |_| {
        project
            .get()
            .and_then(|r| r.ok())
            .flatten()
            .map(|p| if p.name.is_empty() { p.code } else { p.name })
            .unwrap_or_default()
    });
    let env_name = Memo::new(move |_| {
        environment
            .get()
            .and_then(|r| r.ok())
            .flatten()
            .map(|e| if e.name.is_empty() { e.code } else { e.name })
            .unwrap_or_default()
    });

    view! {
        <div class="space-y-4">
            // Breadcrumb — hrefs are strings; use Signal::derive wrappers
            {move || {
                let proj_href = format!("/projects/{}", pid.get());
                view! {
                    <Breadcrumb>
                        <BreadcrumbItem>
                            <BreadcrumbLink href="/projects".to_string()>"Projects"</BreadcrumbLink>
                        </BreadcrumbItem>
                        <BreadcrumbSeparator />
                        <BreadcrumbItem>
                            <BreadcrumbLink href=proj_href>
                                {project_name.get()}
                            </BreadcrumbLink>
                        </BreadcrumbItem>
                        <BreadcrumbSeparator />
                        <BreadcrumbItem>
                            <BreadcrumbPage>{env_name.get()}</BreadcrumbPage>
                        </BreadcrumbItem>
                        <BreadcrumbSeparator />
                        <BreadcrumbItem>
                            <BreadcrumbPage>"Secrets"</BreadcrumbPage>
                        </BreadcrumbItem>
                    </Breadcrumb>
                }
            }}

            // Env tab bar
            {move || view! {
                <EnvTabBar pid=pid.get() eid=eid.get() active="secrets" />
            }}

            // Section header
            <div class="flex items-center justify-between pt-2">
                <h2 class="text-lg font-semibold text-foreground">"Secrets"</h2>
                <Button variant=ButtonVariant::Default size=ButtonSize::Sm on:click=move |_| show_dialog.set(true)>
                    "New secret"
                </Button>
            </div>

            <Dialog open=show_dialog>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>"New secret"</DialogTitle>
                    </DialogHeader>
                    <div class="space-y-4 my-4">
                        {move || create_err.get().map(|e| view! {
                            <Alert variant=AlertVariant::Destructive>
                                <AlertTitle>"Error"</AlertTitle>
                                <AlertDescription>{e}</AlertDescription>
                            </Alert>
                        })}
                        <div class="space-y-1">
                            <Label>"Path"</Label>
                            <Input value=new_path placeholder="database/password".to_string() />
                        </div>
                        <div class="space-y-1">
                            <Label>"Value"</Label>
                            <Textarea value=new_value placeholder="super-secret-value".to_string() rows=3 />
                        </div>
                    </div>
                    <DialogFooter>
                        <Button variant=ButtonVariant::Outline on:click=move |_| show_dialog.set(false)>
                            "Cancel"
                        </Button>
                        <Button variant=ButtonVariant::Default on:click=on_create>
                            "Create"
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>

            <Suspense fallback=|| view! { <div class="flex justify-center py-8"><Spinner /></div> }>
                {move || {
                    let nav = navigate.clone();
                    let pid_val = pid.get();
                    let eid_val = eid.get();
                    let base = base_url.get();
                    secrets.get().map(move |result| {
                        match result {
                            Err(e) => view! {
                                <Alert variant=AlertVariant::Destructive>
                                    <AlertTitle>"Failed to load secrets"</AlertTitle>
                                    <AlertDescription>{e.message}</AlertDescription>
                                </Alert>
                            }.into_any(),
                            Ok(page) if page.items.is_empty() => view! {
                                <Empty
                                    title="No secrets yet".to_string()
                                    description="Add a secret to store encrypted values for this environment.".to_string()
                                    class="py-12".to_string()
                                >
                                    <svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="text-muted-foreground/40">
                                        <circle cx="12" cy="16" r="1"/>
                                        <rect x="3" y="10" width="18" height="12" rx="2"/>
                                        <path d="M7 10V7a5 5 0 0 1 10 0v3"/>
                                    </svg>
                                    <Button variant=ButtonVariant::Default size=ButtonSize::Sm on:click=move |_| show_dialog.set(true)>
                                        "Add your first secret"
                                    </Button>
                                </Empty>
                            }.into_any(),
                            Ok(page) => view! {
                                <Table>
                                    <TableHeader>
                                        <TableRow>
                                            <TableHead>"Path"</TableHead>
                                            <TableHead>"Version"</TableHead>
                                            <TableHead>"Updated"</TableHead>
                                            <TableHead>"Value"</TableHead>
                                            <TableHead>"Actions"</TableHead>
                                        </TableRow>
                                    </TableHeader>
                                    <TableBody>
                                        <For
                                            each=move || page.items.clone()
                                            key=|s| s.path.clone()
                                            children=move |secret| {
                                                let path_display = secret.path.clone();
                                                let version = secret.current_version;
                                                let ts = secret.updated_at.clone();
                                                let rel = relative_time(&ts);
                                                let enc_path = percent_encode(&secret.path);
                                                let reveal_url = StoredValue::new(format!("{}/{}", base, enc_path));
                                                let delete_url = StoredValue::new(format!("{}/{}", base, enc_path));
                                                let nav_url = StoredValue::new(format!("/projects/{}/envs/{}/secrets/{}", pid_val, eid_val, path_display));
                                                let delete_msg = StoredValue::new(format!("Permanently delete \"{}\"?", path_display));
                                                let nav2 = nav.clone();
                                                let confirm_delete = RwSignal::new(false);
                                                let node_ref: NodeRef<html::Span> = NodeRef::new();
                                                // Copy label signal: starts as "Copy", flips to "Copied!" briefly.
                                                let copy_label = RwSignal::new("Copy");

                                                view! {
                                                    <TableRow>
                                                        <TableCell>
                                                            <span class="font-mono text-sm">{path_display}</span>
                                                        </TableCell>
                                                        <TableCell>
                                                            <Badge variant=BadgeVariant::Secondary>
                                                                {format!("v{}", version)}
                                                            </Badge>
                                                        </TableCell>
                                                        <TableCell class="text-muted-foreground text-xs".to_string()>
                                                            <span title=ts>{rel}</span>
                                                        </TableCell>
                                                        <TableCell>
                                                            <div class="flex items-center gap-1">
                                                                <span
                                                                    node_ref=node_ref
                                                                    class="font-mono text-sm text-muted-foreground"
                                                                >
                                                                    {"••••••"}
                                                                </span>
                                                                // Reveal button
                                                                <Button
                                                                    variant=ButtonVariant::Ghost
                                                                    size=ButtonSize::Icon
                                                                    on:click=move |_| {
                                                                        let url = reveal_url.get_value();
                                                                        let nr = node_ref;
                                                                        let cl = copy_label;
                                                                        leptos::task::spawn_local(async move {
                                                                            if let Ok(plain) = get_json::<SecretPlaintext>(&url).await {
                                                                                if let Some(el) = nr.get_untracked() {
                                                                                    let val = plain.value.clone();
                                                                                    el.set_text_content(Some(&val));
                                                                                    // store value for copy
                                                                                    el.set_attribute("data-value", &val).ok();
                                                                                    gloo_timers::future::TimeoutFuture::new(30_000).await;
                                                                                    el.set_text_content(Some("••••••"));
                                                                                    el.remove_attribute("data-value").ok();
                                                                                    cl.set("Copy");
                                                                                }
                                                                            }
                                                                        });
                                                                    }
                                                                >
                                                                    // Eye icon
                                                                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                                                        <path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/>
                                                                        <circle cx="12" cy="12" r="3"/>
                                                                    </svg>
                                                                </Button>
                                                                // Copy button
                                                                <Button
                                                                    variant=ButtonVariant::Ghost
                                                                    size=ButtonSize::Icon
                                                                    on:click=move |_| {
                                                                        // Read revealed value from DOM; if still masked, skip.
                                                                        if let Some(el) = node_ref.get_untracked() {
                                                                            if let Some(val) = el.get_attribute("data-value") {
                                                                                copy_to_clipboard(val, copy_label);
                                                                            }
                                                                        }
                                                                    }
                                                                >
                                                                    {move || if copy_label.get() == "Copied!" {
                                                                        view! {
                                                                            // Check icon
                                                                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="text-green-500">
                                                                                <polyline points="20 6 9 17 4 12"/>
                                                                            </svg>
                                                                        }.into_any()
                                                                    } else {
                                                                        view! {
                                                                            // Copy icon
                                                                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                                                                <rect width="14" height="14" x="8" y="8" rx="2" ry="2"/>
                                                                                <path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/>
                                                                            </svg>
                                                                        }.into_any()
                                                                    }}
                                                                </Button>
                                                            </div>
                                                        </TableCell>
                                                        <TableCell>
                                                            <div class="flex items-center gap-2">
                                                                <Button
                                                                    variant=ButtonVariant::Ghost
                                                                    size=ButtonSize::Sm
                                                                    on:click=move |_| nav2(&nav_url.get_value(), Default::default())
                                                                >
                                                                    "Versions"
                                                                </Button>
                                                                <Button
                                                                    variant=ButtonVariant::Ghost
                                                                    size=ButtonSize::Sm
                                                                    on:click=move |_| confirm_delete.set(true)
                                                                >
                                                                    "Delete"
                                                                </Button>
                                                            </div>
                                                            <AlertDialog open=confirm_delete>
                                                                <AlertDialogContent>
                                                                    <AlertDialogHeader>
                                                                        <AlertDialogTitle>"Delete secret?"</AlertDialogTitle>
                                                                        <AlertDialogDescription>
                                                                            {delete_msg.get_value()}
                                                                        </AlertDialogDescription>
                                                                    </AlertDialogHeader>
                                                                    <AlertDialogFooter>
                                                                        <AlertDialogCancel>"Cancel"</AlertDialogCancel>
                                                                        <AlertDialogAction on_click=Callback::new(move |_| {
                                                                            let url = delete_url.get_value();
                                                                            leptos::task::spawn_local(async move {
                                                                                let _ = del(&url).await;
                                                                                reload.update(|n| *n += 1);
                                                                            });
                                                                        })>
                                                                            "Delete"
                                                                        </AlertDialogAction>
                                                                    </AlertDialogFooter>
                                                                </AlertDialogContent>
                                                            </AlertDialog>
                                                        </TableCell>
                                                    </TableRow>
                                                }
                                            }
                                        />
                                    </TableBody>
                                </Table>
                            }.into_any()
                        }
                    })
                }}
            </Suspense>
        </div>
    }
}
