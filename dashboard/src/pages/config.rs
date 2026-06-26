use crate::api::{del, get_json, put_json, ConfigEntry, Environment, Page, Project, SecretMeta};
use crate::pages::secrets::EnvTabBar;
use crate::util::relative_time;
use leptos::prelude::*;
use leptos_router::hooks::{use_navigate, use_params_map};
use serde::{Deserialize, Serialize};
use soma_ui::{
    Alert, AlertDescription, AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
    AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertTitle,
    AlertVariant, Badge, BadgeVariant, Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbPage,
    BreadcrumbSeparator, Button, ButtonSize, ButtonVariant, Dialog, DialogContent, DialogFooter,
    DialogHeader, DialogTitle, Empty, Input, Label, Select, SelectContent, SelectItem, Spinner,
    Switch, Table, TableBody, TableCell, TableHead, TableHeader, TableRow, Textarea,
};

/// B4: server reads field named `"type"` (serde rename from `value_type`).
#[derive(Serialize, Deserialize)]
struct PutConfigReq {
    value: String,
    #[serde(rename = "type")]
    value_type: String,
}

#[component]
pub fn ConfigPage() -> impl IntoView {
    let params = use_params_map();
    let pid = Memo::new(move |_| params.read().get("pid").unwrap_or_default());
    let eid = Memo::new(move |_| params.read().get("eid").unwrap_or_default());

    let base_url = Memo::new(move |_| {
        format!("/v1/projects/{}/environments/{}/config", pid.get(), eid.get())
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
    let configs = LocalResource::new(move || {
        let _ = reload.get();
        let url = base_url.get();
        async move { get_json::<Page<ConfigEntry>>(&url).await }
    });

    // Create dialog state
    let show_dialog = RwSignal::new(false);
    let new_key = RwSignal::new(String::new());
    let new_type = RwSignal::new("string".to_string());
    let new_value = RwSignal::new(String::new());
    let new_bool = RwSignal::new(false);
    let create_err: RwSignal<Option<String>> = RwSignal::new(None);

    // Delete dialog state
    let confirm_delete_key: RwSignal<Option<String>> = RwSignal::new(None);
    let confirm_delete_open = RwSignal::new(false);

    let secrets_url = Memo::new(move |_| {
        format!("/v1/projects/{}/environments/{}/secrets", pid.get(), eid.get())
    });
    let secret_paths = LocalResource::new(move || {
        let url = secrets_url.get();
        async move { get_json::<Page<SecretMeta>>(&url).await }
    });

    let on_create = move |_| {
        let url = base_url.get();
        let key = new_key.get();
        let vtype = new_type.get();
        if key.is_empty() {
            return;
        }
        let value = if vtype == "bool" {
            new_bool.get().to_string()
        } else {
            new_value.get()
        };
        leptos::task::spawn_local(async move {
            match put_json::<PutConfigReq, serde_json::Value>(
                &format!("{}/{}", url, key),
                &PutConfigReq { value, value_type: vtype },
            )
            .await
            {
                Ok(_) => {
                    show_dialog.set(false);
                    new_key.set(String::new());
                    new_type.set("string".to_string());
                    new_value.set(String::new());
                    reload.update(|n| *n += 1);
                }
                Err(e) => create_err.set(Some(e.message)),
            }
        });
    };

    let navigate = use_navigate();

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
            // Breadcrumb — re-evaluate reactive hrefs inside move closure
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
                            <BreadcrumbPage>"Config"</BreadcrumbPage>
                        </BreadcrumbItem>
                    </Breadcrumb>
                }
            }}

            // Env tab bar
            {move || view! {
                <EnvTabBar pid=pid.get() eid=eid.get() active="config" />
            }}

            // Section header
            <div class="flex items-center justify-between pt-2">
                <h2 class="text-lg font-semibold text-foreground">"Config"</h2>
                <Button variant=ButtonVariant::Default size=ButtonSize::Sm on:click=move |_| show_dialog.set(true)>
                    "New config"
                </Button>
            </div>

            // Create dialog
            <Dialog open=show_dialog>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>"New config entry"</DialogTitle>
                    </DialogHeader>
                    <div class="space-y-4 my-4">
                        {move || create_err.get().map(|e| view! {
                            <Alert variant=AlertVariant::Destructive>
                                <AlertTitle>"Error"</AlertTitle>
                                <AlertDescription>{e}</AlertDescription>
                            </Alert>
                        })}
                        <div class="space-y-1">
                            <Label>"Key"</Label>
                            <Input value=new_key placeholder="DATABASE_URL".to_string() />
                        </div>
                        <div class="space-y-1">
                            <Label>"Type"</Label>
                            <Select value=new_type placeholder="Select type".to_string()>
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
                            let vtype = new_type.get();
                            match vtype.as_str() {
                                "bool" => view! {
                                    <div class="flex items-center gap-2">
                                        <Label>"Value"</Label>
                                        <Switch checked=new_bool />
                                    </div>
                                }.into_any(),
                                "json" => view! {
                                    <div class="space-y-1">
                                        <Label>"Value (JSON)"</Label>
                                        <Textarea value=new_value placeholder=r#"{"key": "value"}"#.to_string() rows=4 />
                                    </div>
                                }.into_any(),
                                "int" | "float" => view! {
                                    <div class="space-y-1">
                                        <Label>"Value"</Label>
                                        <Input value=new_value input_type="number".to_string() placeholder="0".to_string() />
                                    </div>
                                }.into_any(),
                                "secret_ref" => view! {
                                    <div class="space-y-1">
                                        <Label>"Secret path"</Label>
                                        <Select value=new_value placeholder="Select secret".to_string()>
                                            <SelectContent>
                                                {move || secret_paths.get()
                                                    .and_then(|r| r.ok())
                                                    .map(|page| page.items.into_iter().map(|s| {
                                                        let p = s.path.clone();
                                                        view! { <SelectItem value=p.clone()>{p}</SelectItem> }
                                                    }).collect::<Vec<_>>())}
                                            </SelectContent>
                                        </Select>
                                    </div>
                                }.into_any(),
                                _ => view! {
                                    <div class="space-y-1">
                                        <Label>"Value"</Label>
                                        <Input value=new_value placeholder="value".to_string() />
                                    </div>
                                }.into_any(),
                            }
                        }}
                    </div>
                    <DialogFooter>
                        <Button variant=ButtonVariant::Outline on:click=move |_| show_dialog.set(false)>
                            "Cancel"
                        </Button>
                        <Button variant=ButtonVariant::Default on:click=on_create>
                            "Save"
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>

            // Delete confirmation dialog
            <AlertDialog open=confirm_delete_open>
                <AlertDialogContent>
                    <AlertDialogHeader>
                        <AlertDialogTitle>"Delete config entry?"</AlertDialogTitle>
                        <AlertDialogDescription>
                            {move || format!(
                                "Permanently delete \"{}\"?",
                                confirm_delete_key.get().unwrap_or_default()
                            )}
                        </AlertDialogDescription>
                    </AlertDialogHeader>
                    <AlertDialogFooter>
                        <AlertDialogCancel>"Cancel"</AlertDialogCancel>
                        <AlertDialogAction on_click=Callback::new(move |_| {
                            if let Some(key) = confirm_delete_key.get_untracked() {
                                let url = format!("{}/{}", base_url.get_untracked(), key);
                                leptos::task::spawn_local(async move {
                                    let _ = del(&url).await;
                                    reload.update(|n| *n += 1);
                                });
                            }
                        })>
                            "Delete"
                        </AlertDialogAction>
                    </AlertDialogFooter>
                </AlertDialogContent>
            </AlertDialog>

            <Suspense fallback=|| view! { <div class="flex justify-center py-8"><Spinner /></div> }>
                {move || {
                    let nav = navigate.clone();
                    let pid_val = pid.get();
                    let eid_val = eid.get();
                    configs.get().map(move |result| {
                        match result {
                            Err(e) => view! {
                                <Alert variant=AlertVariant::Destructive>
                                    <AlertTitle>"Failed to load config"</AlertTitle>
                                    <AlertDescription>{e.message}</AlertDescription>
                                </Alert>
                            }.into_any(),
                            Ok(page) if page.items.is_empty() => view! {
                                <Empty
                                    title="No config entries yet".to_string()
                                    description="Add typed config values for this environment — strings, numbers, booleans, or secret refs.".to_string()
                                >
                                    <svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="text-muted-foreground/40">
                                        <path d="M12 20h9"/>
                                        <path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4Z"/>
                                    </svg>
                                    <Button variant=ButtonVariant::Default size=ButtonSize::Sm on:click=move |_| show_dialog.set(true)>
                                        "Add your first config entry"
                                    </Button>
                                </Empty>
                            }.into_any(),
                            Ok(page) => view! {
                                <Table>
                                    <TableHeader>
                                        <TableRow>
                                            <TableHead>"Key"</TableHead>
                                            <TableHead>"Type"</TableHead>
                                            <TableHead>"Version"</TableHead>
                                            <TableHead>"Updated"</TableHead>
                                            <TableHead>"Actions"</TableHead>
                                        </TableRow>
                                    </TableHeader>
                                    <TableBody>
                                        <For
                                            each=move || page.items.clone()
                                            key=|c| c.key.clone()
                                            children=move |entry| {
                                                let key = entry.key.clone();
                                                let nav2 = nav.clone();
                                                let pid2 = pid_val.clone();
                                                let eid2 = eid_val.clone();
                                                let nav_url = format!("/projects/{}/envs/{}/config/{}", pid2, eid2, key);
                                                let version_label = format!("v{}", entry.current_version);
                                                let ts = entry.updated_at.clone();
                                                let rel = relative_time(&ts);
                                                let key_for_del = StoredValue::new(entry.key.clone());
                                                // Pre-clone nav for each closure that needs it.
                                                let nav_for_key = nav2.clone();
                                                let nav_for_edit = nav2.clone();
                                                let nav_url_sv = StoredValue::new(nav_url);
                                                view! {
                                                    <TableRow>
                                                        <TableCell>
                                                            <button
                                                                class="text-primary hover:underline text-sm font-mono"
                                                                on:click={
                                                                    let url = nav_url_sv.get_value();
                                                                    move |_| nav_for_key(&url, Default::default())
                                                                }
                                                            >
                                                                {entry.key.clone()}
                                                            </button>
                                                        </TableCell>
                                                        <TableCell>
                                                            <Badge variant=BadgeVariant::Outline>
                                                                {entry.value_type.clone()}
                                                            </Badge>
                                                        </TableCell>
                                                        <TableCell class="font-mono text-xs text-muted-foreground".to_string()>
                                                            {version_label}
                                                        </TableCell>
                                                        <TableCell class="text-xs text-muted-foreground".to_string()>
                                                            <span title=ts>{rel}</span>
                                                        </TableCell>
                                                        <TableCell>
                                                            <div class="flex items-center gap-1">
                                                                // Edit → navigate to detail page
                                                                <Button
                                                                    variant=ButtonVariant::Ghost
                                                                    size=ButtonSize::Sm
                                                                    on:click={
                                                                        let url = nav_url_sv.get_value();
                                                                        move |_| nav_for_edit(&url, Default::default())
                                                                    }
                                                                >
                                                                    "Edit"
                                                                </Button>
                                                                // Delete
                                                                <Button
                                                                    variant=ButtonVariant::Ghost
                                                                    size=ButtonSize::Sm
                                                                    on:click=move |_| {
                                                                        confirm_delete_key.set(Some(key_for_del.get_value()));
                                                                        confirm_delete_open.set(true);
                                                                    }
                                                                >
                                                                    "Delete"
                                                                </Button>
                                                            </div>
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
