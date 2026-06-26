use crate::api::{get_json, post_json, put_json, Environment, Page, Project, SecretPlaintext, SecretVersion};
use crate::pages::secrets::{percent_encode, EnvTabBar};
use crate::util::{copy_to_clipboard, relative_time};
use leptos::html;
use leptos::prelude::*;
use leptos_router::hooks::use_params_map;
use serde::{Deserialize, Serialize};
use soma_ui::{
    Alert, AlertDescription, AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
    AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertTitle,
    AlertVariant, Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbPage, BreadcrumbSeparator,
    Button, ButtonSize, ButtonVariant, PageHeader, ScrollArea, Spinner, Table, TableBody, TableCell,
    TableHead, TableHeader, TableRow, Textarea,
};

#[derive(Serialize, Deserialize)]
struct RollbackReq {
    version: i32,
}

#[derive(Serialize, Deserialize)]
struct RollbackResp {}

#[derive(Serialize, Deserialize)]
struct PutSecretReq {
    value: String,
}

#[component]
pub fn SecretDetailPage() -> impl IntoView {
    let params = use_params_map();
    let pid = Memo::new(move |_| params.read().get("pid").unwrap_or_default());
    let eid = Memo::new(move |_| params.read().get("eid").unwrap_or_default());
    let path = Memo::new(move |_| params.read().get("path").unwrap_or_default());

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

    let versions_reload = RwSignal::new(0u32);
    let versions = LocalResource::new(move || {
        let _ = versions_reload.get();
        let url = format!(
            "/v1/projects/{}/environments/{}/secrets/{}/versions",
            pid.get(),
            eid.get(),
            percent_encode(&path.get())
        );
        async move { get_json::<Vec<SecretVersion>>(&url).await }
    });

    // Current-value reveal state
    let reveal_node: NodeRef<html::Span> = NodeRef::new();
    let copy_label = RwSignal::new("Copy");

    // Update-value form
    let update_value = RwSignal::new(String::new());
    let update_err: RwSignal<Option<String>> = RwSignal::new(None);
    let update_ok = RwSignal::new(false);

    let on_update = {
        let pid_ = pid;
        let eid_ = eid;
        let path_ = path;
        move |_| {
            let val = update_value.get();
            if val.is_empty() {
                return;
            }
            let url = format!(
                "/v1/projects/{}/environments/{}/secrets/{}",
                pid_.get(),
                eid_.get(),
                percent_encode(&path_.get())
            );
            leptos::task::spawn_local(async move {
                match put_json::<PutSecretReq, serde_json::Value>(&url, &PutSecretReq { value: val })
                    .await
                {
                    Ok(_) => {
                        update_value.set(String::new());
                        update_err.set(None);
                        update_ok.set(true);
                        versions_reload.update(|n| *n += 1);
                        gloo_timers::future::TimeoutFuture::new(2_000).await;
                        update_ok.set(false);
                    }
                    Err(e) => update_err.set(Some(e.message)),
                }
            });
        }
    };

    // Rollback dialog
    let confirm_rollback_ver: RwSignal<i32> = RwSignal::new(0);
    let rollback_open = RwSignal::new(false);

    let rollback_url = Memo::new(move |_| {
        format!(
            "/v1/projects/{}/environments/{}/secrets/{}/rollback",
            pid.get(),
            eid.get(),
            percent_encode(&path.get())
        )
    });

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
            // Breadcrumb — compute reactive hrefs inside move closure
            {move || {
                let proj_href = format!("/projects/{}", pid.get());
                let secrets_href = format!("/projects/{}/envs/{}/secrets", pid.get(), eid.get());
                let secrets_href2 = secrets_href.clone();
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
                            <BreadcrumbLink href=secrets_href>
                                {env_name.get()}
                            </BreadcrumbLink>
                        </BreadcrumbItem>
                        <BreadcrumbSeparator />
                        <BreadcrumbItem>
                            <BreadcrumbLink href=secrets_href2>
                                "Secrets"
                            </BreadcrumbLink>
                        </BreadcrumbItem>
                        <BreadcrumbSeparator />
                        <BreadcrumbItem>
                            <BreadcrumbPage>
                                <span class="font-mono">{path.get()}</span>
                            </BreadcrumbPage>
                        </BreadcrumbItem>
                    </Breadcrumb>
                }
            }}

            // Env tab bar
            {move || view! {
                <EnvTabBar pid=pid.get() eid=eid.get() active="secrets" />
            }}

            // Page header
            <PageHeader title=Signal::derive(move || path.get()).get()>
                <span />
            </PageHeader>

            // ── Current value reveal ─────────────────────────────────────────
            <div class="rounded-md border border-border bg-card p-4 space-y-3">
                <p class="text-sm font-medium text-foreground">"Current value"</p>
                <div class="flex items-center gap-2">
                    <span
                        node_ref=reveal_node
                        class="flex-1 font-mono text-sm bg-muted rounded px-3 py-2 text-muted-foreground overflow-hidden text-ellipsis whitespace-nowrap"
                    >
                        {"••••••••••••"}
                    </span>
                    // Reveal
                    <Button
                        variant=ButtonVariant::Ghost
                        size=ButtonSize::Icon
                        on:click=move |_| {
                            let url = format!(
                                "/v1/projects/{}/environments/{}/secrets/{}",
                                pid.get(), eid.get(), percent_encode(&path.get())
                            );
                            let nr = reveal_node;
                            let cl = copy_label;
                            leptos::task::spawn_local(async move {
                                if let Ok(plain) = get_json::<SecretPlaintext>(&url).await {
                                    if let Some(el) = nr.get_untracked() {
                                        let val = plain.value.clone();
                                        el.set_text_content(Some(&val));
                                        el.set_attribute("data-value", &val).ok();
                                        gloo_timers::future::TimeoutFuture::new(30_000).await;
                                        el.set_text_content(Some("••••••••••••"));
                                        el.remove_attribute("data-value").ok();
                                        cl.set("Copy");
                                    }
                                }
                            });
                        }
                    >
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/>
                            <circle cx="12" cy="12" r="3"/>
                        </svg>
                    </Button>
                    // Copy
                    <Button
                        variant=ButtonVariant::Ghost
                        size=ButtonSize::Icon
                        on:click=move |_| {
                            if let Some(el) = reveal_node.get_untracked() {
                                if let Some(val) = el.get_attribute("data-value") {
                                    copy_to_clipboard(val, copy_label);
                                }
                            }
                        }
                    >
                        {move || if copy_label.get() == "Copied!" {
                            view! {
                                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="text-green-500">
                                    <polyline points="20 6 9 17 4 12"/>
                                </svg>
                            }.into_any()
                        } else {
                            view! {
                                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                    <rect width="14" height="14" x="8" y="8" rx="2" ry="2"/>
                                    <path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/>
                                </svg>
                            }.into_any()
                        }}
                    </Button>
                </div>
            </div>

            // ── Update value form ────────────────────────────────────────────
            <div class="rounded-md border border-border bg-card p-4 space-y-3">
                <p class="text-sm font-medium text-foreground">"Update value"</p>
                {move || update_err.get().map(|e| view! {
                    <Alert variant=AlertVariant::Destructive>
                        <AlertTitle>"Error"</AlertTitle>
                        <AlertDescription>{e}</AlertDescription>
                    </Alert>
                })}
                {move || update_ok.get().then(|| view! {
                    <Alert variant=AlertVariant::Warning>
                        <AlertTitle>"Saved"</AlertTitle>
                        <AlertDescription>"New version created."</AlertDescription>
                    </Alert>
                })}
                <Textarea
                    value=update_value
                    placeholder="New secret value…".to_string()
                    rows=3
                />
                <div class="flex justify-end">
                    <Button variant=ButtonVariant::Default size=ButtonSize::Sm on:click=on_update>
                        "Save new version"
                    </Button>
                </div>
            </div>

            // ── Rollback dialog ──────────────────────────────────────────────
            <AlertDialog open=rollback_open>
                <AlertDialogContent>
                    <AlertDialogHeader>
                        <AlertDialogTitle>"Rollback secret?"</AlertDialogTitle>
                        <AlertDialogDescription>
                            {move || format!("Roll back to version v{}?", confirm_rollback_ver.get())}
                        </AlertDialogDescription>
                    </AlertDialogHeader>
                    <AlertDialogFooter>
                        <AlertDialogCancel>"Cancel"</AlertDialogCancel>
                        <AlertDialogAction on_click=Callback::new(move |_| {
                            let ver = confirm_rollback_ver.get_untracked();
                            let url = rollback_url.get();
                            leptos::task::spawn_local(async move {
                                let _ = post_json::<RollbackReq, RollbackResp>(
                                    &url,
                                    &RollbackReq { version: ver },
                                ).await;
                                versions_reload.update(|n| *n += 1);
                            });
                        })>
                            "Rollback"
                        </AlertDialogAction>
                    </AlertDialogFooter>
                </AlertDialogContent>
            </AlertDialog>

            // ── Versions table ───────────────────────────────────────────────
            <h3 class="text-sm font-medium text-foreground">"Version history"</h3>
            <Suspense fallback=|| view! { <div class="flex justify-center py-8"><Spinner /></div> }>
                {move || versions.get().map(|result| {
                    match result {
                        Err(e) => view! {
                            <Alert variant=AlertVariant::Destructive>
                                <AlertTitle>"Failed to load versions"</AlertTitle>
                                <AlertDescription>{e.message}</AlertDescription>
                            </Alert>
                        }.into_any(),
                        Ok(list) => view! {
                            <ScrollArea class="max-h-[400px]".to_string()>
                                <Table>
                                    <TableHeader>
                                        <TableRow>
                                            <TableHead>"Version"</TableHead>
                                            <TableHead>"Created"</TableHead>
                                            <TableHead>"Seal provider"</TableHead>
                                            <TableHead>"Actions"</TableHead>
                                        </TableRow>
                                    </TableHeader>
                                    <TableBody>
                                        <For
                                            each=move || list.clone()
                                            key=|v| v.version
                                            children=move |ver| {
                                                let v_num = ver.version;
                                                let ts = ver.created_at.clone();
                                                let rel = relative_time(&ts);
                                                view! {
                                                    <TableRow>
                                                        <TableCell class="font-mono".to_string()>
                                                            {format!("v{}", ver.version)}
                                                        </TableCell>
                                                        <TableCell class="text-xs text-muted-foreground".to_string()>
                                                            <span title=ts>{rel}</span>
                                                        </TableCell>
                                                        <TableCell class="text-xs text-muted-foreground".to_string()>
                                                            {ver.seal_provider.clone()}
                                                        </TableCell>
                                                        <TableCell>
                                                            <Button
                                                                variant=ButtonVariant::Ghost
                                                                size=ButtonSize::Sm
                                                                on:click=move |_| {
                                                                    confirm_rollback_ver.set(v_num);
                                                                    rollback_open.set(true);
                                                                }
                                                            >
                                                                "Rollback"
                                                            </Button>
                                                        </TableCell>
                                                    </TableRow>
                                                }
                                            }
                                        />
                                    </TableBody>
                                </Table>
                            </ScrollArea>
                        }.into_any()
                    }
                })}
            </Suspense>
        </div>
    }
}
