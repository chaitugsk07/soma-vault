use crate::api::{get_json, put_json, ConfigVersion, Environment, Page, Project};
use crate::pages::secrets::EnvTabBar;
use crate::util::{copy_to_clipboard, relative_time};
use leptos::prelude::*;
use leptos_router::hooks::use_params_map;
use serde::{Deserialize, Serialize};
use soma_ui::{
    Alert, AlertDescription, AlertTitle, AlertVariant, Breadcrumb, BreadcrumbItem, BreadcrumbLink,
    BreadcrumbPage, BreadcrumbSeparator, Button, ButtonSize, ButtonVariant, Input, Label, PageHeader,
    ScrollArea, Select, SelectContent, SelectItem, Spinner, Switch, Table, TableBody, TableCell,
    TableHead, TableHeader, TableRow, Tabs, TabsContent, TabsList, TabsTrigger, Textarea,
};

#[derive(Serialize, Deserialize)]
struct PutConfigReq {
    value: String,
    #[serde(rename = "type")]
    value_type: String,
}

#[component]
pub fn ConfigDetailPage() -> impl IntoView {
    let params = use_params_map();
    let key = Memo::new(move |_| params.read().get("key").unwrap_or_default());
    let pid = Memo::new(move |_| params.read().get("pid").unwrap_or_default());
    let eid = Memo::new(move |_| params.read().get("eid").unwrap_or_default());

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
            "/v1/projects/{}/environments/{}/config/{}/versions",
            pid.get(),
            eid.get(),
            key.get()
        );
        async move { get_json::<Vec<ConfigVersion>>(&url).await }
    });

    let active_tab = RwSignal::new("versions".to_string());
    let diff_a = RwSignal::new(String::new());
    let diff_b = RwSignal::new(String::new());

    // Edit form: derive type from latest version when it loads.
    let edit_value = RwSignal::new(String::new());
    let edit_type = RwSignal::new("string".to_string());
    let edit_bool = RwSignal::new(false);
    let edit_err: RwSignal<Option<String>> = RwSignal::new(None);
    let edit_ok = RwSignal::new(false);
    let copy_label = RwSignal::new("Copy");

    let on_save = {
        let pid_ = pid;
        let eid_ = eid;
        let key_ = key;
        move |_| {
            let vtype = edit_type.get();
            let value = if vtype == "bool" {
                edit_bool.get().to_string()
            } else {
                edit_value.get()
            };
            let url = format!(
                "/v1/projects/{}/environments/{}/config/{}",
                pid_.get(),
                eid_.get(),
                key_.get()
            );
            leptos::task::spawn_local(async move {
                match put_json::<PutConfigReq, serde_json::Value>(
                    &url,
                    &PutConfigReq { value, value_type: vtype },
                )
                .await
                {
                    Ok(_) => {
                        edit_err.set(None);
                        edit_ok.set(true);
                        versions_reload.update(|n| *n += 1);
                        gloo_timers::future::TimeoutFuture::new(2_000).await;
                        edit_ok.set(false);
                    }
                    Err(e) => edit_err.set(Some(e.message)),
                }
            });
        }
    };

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
                let config_href = format!("/projects/{}/envs/{}/config", pid.get(), eid.get());
                let config_href2 = config_href.clone();
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
                            <BreadcrumbLink href=config_href>
                                {env_name.get()}
                            </BreadcrumbLink>
                        </BreadcrumbItem>
                        <BreadcrumbSeparator />
                        <BreadcrumbItem>
                            <BreadcrumbLink href=config_href2>
                                "Config"
                            </BreadcrumbLink>
                        </BreadcrumbItem>
                        <BreadcrumbSeparator />
                        <BreadcrumbItem>
                            <BreadcrumbPage>
                                <span class="font-mono">{key.get()}</span>
                            </BreadcrumbPage>
                        </BreadcrumbItem>
                    </Breadcrumb>
                }
            }}

            // Env tab bar
            {move || view! {
                <EnvTabBar pid=pid.get() eid=eid.get() active="config" />
            }}

            // Page header
            <PageHeader title=Signal::derive(move || key.get()).get()>
                <span />
            </PageHeader>

            // ── Current value + edit form ─────────────────────────────────────
            <div class="rounded-md border border-border bg-card p-4 space-y-4">
                <p class="text-sm font-medium text-foreground">"Current value"</p>

                // Show latest value from versions for copy.
                <Suspense fallback=|| view! { <span class="text-muted-foreground text-sm">"Loading…"</span> }>
                    {move || versions.get().map(|result| {
                        let latest_val = result.ok()
                            .and_then(|list| list.into_iter().next())
                            .and_then(|v| v.value)
                            .unwrap_or_default();
                        let display = if latest_val.is_empty() { "—".to_string() } else { latest_val.clone() };
                        // Pre-populate edit form from latest value.
                        if edit_value.get_untracked().is_empty() && !latest_val.is_empty() {
                            edit_value.set(latest_val.clone());
                        }
                        view! {
                            <div class="flex items-center gap-2">
                                <span class="flex-1 font-mono text-sm bg-muted rounded px-3 py-2 text-muted-foreground overflow-hidden text-ellipsis whitespace-nowrap">
                                    {display}
                                </span>
                                <Button
                                    variant=ButtonVariant::Ghost
                                    size=ButtonSize::Icon
                                    on:click={
                                        let val = latest_val.clone();
                                        move |_| copy_to_clipboard(val.clone(), copy_label)
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
                        }
                    })}
                </Suspense>

                // Edit form
                <div class="space-y-3 border-t border-border pt-3">
                    <p class="text-sm font-medium text-foreground">"Update value"</p>
                    {move || edit_err.get().map(|e| view! {
                        <Alert variant=AlertVariant::Destructive>
                            <AlertTitle>"Error"</AlertTitle>
                            <AlertDescription>{e}</AlertDescription>
                        </Alert>
                    })}
                    {move || edit_ok.get().then(|| view! {
                        <Alert variant=AlertVariant::Warning>
                            <AlertTitle>"Saved"</AlertTitle>
                            <AlertDescription>"New version created."</AlertDescription>
                        </Alert>
                    })}
                    <div class="space-y-1">
                        <Label>"Type"</Label>
                        <Select value=edit_type placeholder="Select type".to_string()>
                            <SelectContent>
                                <SelectItem value="string">"string"</SelectItem>
                                <SelectItem value="int">"int"</SelectItem>
                                <SelectItem value="float">"float"</SelectItem>
                                <SelectItem value="bool">"bool"</SelectItem>
                                <SelectItem value="json">"json"</SelectItem>
                                <SelectItem value="secret_ref">"secret_ref"</SelectItem>
                            </SelectContent>
                        </Select>
                    </div>
                    {move || {
                        let vtype = edit_type.get();
                        match vtype.as_str() {
                            "bool" => view! {
                                <div class="flex items-center gap-2">
                                    <Label>"Value"</Label>
                                    <Switch checked=edit_bool />
                                </div>
                            }.into_any(),
                            "json" => view! {
                                <Textarea value=edit_value placeholder=r#"{"key": "value"}"#.to_string() rows=4 />
                            }.into_any(),
                            "int" | "float" => view! {
                                <Input value=edit_value input_type="number".to_string() placeholder="0".to_string() />
                            }.into_any(),
                            _ => view! {
                                <Input value=edit_value placeholder="value".to_string() />
                            }.into_any(),
                        }
                    }}
                    <div class="flex justify-end">
                        <Button variant=ButtonVariant::Default size=ButtonSize::Sm on:click=on_save>
                            "Save new version"
                        </Button>
                    </div>
                </div>
            </div>

            // ── Version history tabs ─────────────────────────────────────────
            <Tabs value=active_tab>
                <TabsList>
                    <TabsTrigger value="versions">"Versions"</TabsTrigger>
                    <TabsTrigger value="diff">"Diff"</TabsTrigger>
                </TabsList>

                <TabsContent value="versions">
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
                                    <ScrollArea class="max-h-[500px]".to_string()>
                                        <Table>
                                            <TableHeader>
                                                <TableRow>
                                                    <TableHead>"Version"</TableHead>
                                                    <TableHead>"Type"</TableHead>
                                                    <TableHead>"Value"</TableHead>
                                                    <TableHead>"Created"</TableHead>
                                                </TableRow>
                                            </TableHeader>
                                            <TableBody>
                                                <For
                                                    each=move || list.clone()
                                                    key=|v| v.version
                                                    children=|ver| {
                                                        let ts = ver.created_at.clone();
                                                        let rel = relative_time(&ts);
                                                        view! {
                                                            <TableRow>
                                                                <TableCell class="font-mono".to_string()>
                                                                    {format!("v{}", ver.version)}
                                                                </TableCell>
                                                                <TableCell class="text-xs".to_string()>
                                                                    {ver.value_type.clone()}
                                                                </TableCell>
                                                                <TableCell class="font-mono text-xs max-w-xs truncate".to_string()>
                                                                    {ver.value.clone()}
                                                                </TableCell>
                                                                <TableCell class="text-xs text-muted-foreground".to_string()>
                                                                    <span title=ts>{rel}</span>
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
                </TabsContent>

                <TabsContent value="diff">
                    <Suspense fallback=|| view! { <div class="flex justify-center py-8"><Spinner /></div> }>
                        {move || versions.get().map(|result| {
                            match result {
                                Err(e) => view! {
                                    <Alert variant=AlertVariant::Destructive>
                                        <AlertTitle>"Error"</AlertTitle>
                                        <AlertDescription>{e.message}</AlertDescription>
                                    </Alert>
                                }.into_any(),
                                Ok(list) => {
                                    let versions_sv = StoredValue::new(list);
                                    view! {
                                        <div class="space-y-4">
                                            <div class="flex gap-4">
                                                <div class="flex-1 space-y-1">
                                                    <span class="text-sm text-muted-foreground">"Version A"</span>
                                                    <Select value=diff_a placeholder="Select version".to_string()>
                                                        <SelectContent>
                                                            <For
                                                                each=move || versions_sv.get_value()
                                                                key=|v| v.version
                                                                children=|ver| view! {
                                                                    <SelectItem value=ver.version.to_string()>
                                                                        {format!("v{}", ver.version)}
                                                                    </SelectItem>
                                                                }
                                                            />
                                                        </SelectContent>
                                                    </Select>
                                                </div>
                                                <div class="flex-1 space-y-1">
                                                    <span class="text-sm text-muted-foreground">"Version B"</span>
                                                    <Select value=diff_b placeholder="Select version".to_string()>
                                                        <SelectContent>
                                                            <For
                                                                each=move || versions_sv.get_value()
                                                                key=|v| v.version
                                                                children=|ver| view! {
                                                                    <SelectItem value=ver.version.to_string()>
                                                                        {format!("v{}", ver.version)}
                                                                    </SelectItem>
                                                                }
                                                            />
                                                        </SelectContent>
                                                    </Select>
                                                </div>
                                            </div>
                                            <div class="flex gap-4">
                                                <pre class="flex-1 rounded-md border border-border bg-muted p-3 text-xs font-mono overflow-auto max-h-[400px]">
                                                    {move || {
                                                        let selected = diff_a.get();
                                                        versions_sv.get_value().into_iter()
                                                            .find(|v| v.version.to_string() == selected)
                                                            .and_then(|v| v.value)
                                                            .unwrap_or_default()
                                                    }}
                                                </pre>
                                                <pre class="flex-1 rounded-md border border-border bg-muted p-3 text-xs font-mono overflow-auto max-h-[400px]">
                                                    {move || {
                                                        let selected = diff_b.get();
                                                        versions_sv.get_value().into_iter()
                                                            .find(|v| v.version.to_string() == selected)
                                                            .and_then(|v| v.value)
                                                            .unwrap_or_default()
                                                    }}
                                                </pre>
                                            </div>
                                        </div>
                                    }.into_any()
                                }
                            }
                        })}
                    </Suspense>
                </TabsContent>
            </Tabs>
        </div>
    }
}
