use crate::api::{get_json, post_json, Environment, Page, Project};
use crate::util::relative_time;
use leptos::prelude::*;
use leptos_router::hooks::{use_navigate, use_params_map};
use serde::{Deserialize, Serialize};
use soma_ui::{
    Alert, AlertDescription, AlertTitle, AlertVariant, Breadcrumb, BreadcrumbItem, BreadcrumbLink,
    BreadcrumbPage, BreadcrumbSeparator, Button, ButtonSize, ButtonVariant, Dialog, DialogContent,
    DialogFooter, DialogHeader, DialogTitle, Empty, Input, Label, Spinner, Table, TableBody,
    TableCell, TableHead, TableHeader, TableRow,
};

#[derive(Serialize, Deserialize)]
struct CreateEnvReq {
    code: String,
    name: String,
}

#[component]
pub fn ProjectDetailPage() -> impl IntoView {
    let params = use_params_map();
    let pid = Memo::new(move |_| params.read().get("pid").unwrap_or_default());

    // Fetch project name for breadcrumb and header.
    let project = LocalResource::new(move || {
        let id = pid.get();
        async move {
            let page = get_json::<Page<Project>>("/v1/projects").await?;
            Ok::<Option<Project>, crate::api::ApiError>(page.items.into_iter().find(|p| p.id == id))
        }
    });

    let reload = RwSignal::new(0u32);
    let envs = LocalResource::new(move || {
        let _ = reload.get();
        let id = pid.get();
        async move { get_json::<Vec<Environment>>(&format!("/v1/projects/{}/environments", id)).await }
    });

    let show_dialog = RwSignal::new(false);
    let new_code = RwSignal::new(String::new());
    let new_name = RwSignal::new(String::new());
    let create_err: RwSignal<Option<String>> = RwSignal::new(None);

    let on_create = move |_| {
        let id = pid.get();
        let code = new_code.get();
        let name = new_name.get();
        if code.is_empty() || name.is_empty() {
            return;
        }
        leptos::task::spawn_local(async move {
            match post_json::<CreateEnvReq, Environment>(
                &format!("/v1/projects/{}/environments", id),
                &CreateEnvReq { code, name },
            )
            .await
            {
                Ok(_) => {
                    show_dialog.set(false);
                    new_code.set(String::new());
                    new_name.set(String::new());
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

    view! {
        <div class="space-y-6">
            // Breadcrumb
            <Breadcrumb>
                <BreadcrumbItem>
                    <BreadcrumbLink href="/projects".to_string()>"Projects"</BreadcrumbLink>
                </BreadcrumbItem>
                <BreadcrumbSeparator />
                <BreadcrumbItem>
                    <BreadcrumbPage>{move || project_name.get()}</BreadcrumbPage>
                </BreadcrumbItem>
            </Breadcrumb>

            <div class="flex items-center justify-between">
                <h1 class="text-2xl font-semibold tracking-tight text-foreground">
                    {move || project_name.get()}
                </h1>
                <Button variant=ButtonVariant::Default size=ButtonSize::Sm on:click=move |_| show_dialog.set(true)>
                    "New environment"
                </Button>
            </div>

            <Dialog open=show_dialog>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>"New environment"</DialogTitle>
                    </DialogHeader>
                    <div class="space-y-4 my-4">
                        {move || create_err.get().map(|e| view! {
                            <Alert variant=AlertVariant::Destructive>
                                <AlertTitle>"Error"</AlertTitle>
                                <AlertDescription>{e}</AlertDescription>
                            </Alert>
                        })}
                        <div class="space-y-1">
                            <Label>"Code (slug)"</Label>
                            <Input value=new_code placeholder="production".to_string() />
                        </div>
                        <div class="space-y-1">
                            <Label>"Name"</Label>
                            <Input value=new_name placeholder="Production".to_string() />
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
                    envs.get().map(move |result| {
                        match result {
                            Err(e) => view! {
                                <Alert variant=AlertVariant::Destructive>
                                    <AlertTitle>"Failed to load environments"</AlertTitle>
                                    <AlertDescription>{e.message}</AlertDescription>
                                </Alert>
                            }.into_any(),
                            Ok(list) if list.is_empty() => view! {
                                <Empty
                                    title="No environments yet".to_string()
                                    description="Add an environment (e.g. production, staging) to store secrets and config.".to_string()
                                >
                                    <svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="text-muted-foreground/40">
                                        <path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"/>
                                        <path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"/>
                                    </svg>
                                    <Button variant=ButtonVariant::Default size=ButtonSize::Sm on:click=move |_| show_dialog.set(true)>
                                        "Add your first environment"
                                    </Button>
                                </Empty>
                            }.into_any(),
                            Ok(list) => {
                                let pid_val = pid.get();
                                view! {
                                    <Table>
                                        <TableHeader>
                                            <TableRow>
                                                <TableHead>"Code"</TableHead>
                                                <TableHead>"Name"</TableHead>
                                                <TableHead>"Created"</TableHead>
                                            </TableRow>
                                        </TableHeader>
                                        <TableBody>
                                            <For
                                                each=move || list.clone()
                                                key=|e| e.id.clone()
                                                children=move |env| {
                                                    let eid = env.id.clone();
                                                    let pid2 = pid_val.clone();
                                                    let nav2 = nav.clone();
                                                    let ts = env.created_at.clone();
                                                    let rel = relative_time(&ts);
                                                    view! {
                                                        <TableRow>
                                                            <TableCell>
                                                                <button
                                                                    class="text-primary hover:underline text-sm font-mono"
                                                                    on:click=move |_| nav2(
                                                                        &format!("/projects/{}/envs/{}/secrets", pid2, eid),
                                                                        Default::default(),
                                                                    )
                                                                >
                                                                    {env.code.clone()}
                                                                </button>
                                                            </TableCell>
                                                            <TableCell>{env.name.clone()}</TableCell>
                                                            <TableCell class="text-muted-foreground text-xs".to_string()>
                                                                <span title=ts>{rel}</span>
                                                            </TableCell>
                                                        </TableRow>
                                                    }
                                                }
                                            />
                                        </TableBody>
                                    </Table>
                                }.into_any()
                            }
                        }
                    })
                }}
            </Suspense>
        </div>
    }
}
