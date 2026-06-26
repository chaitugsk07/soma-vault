use crate::api::{get_json, post_json, Page, Project};
use crate::util::relative_time;
use leptos::prelude::*;
use leptos_router::hooks::use_navigate;
use serde::{Deserialize, Serialize};
use soma_ui::{
    Alert, AlertDescription, AlertTitle, AlertVariant, Button, ButtonSize, ButtonVariant, Dialog,
    DialogContent, DialogFooter, DialogHeader, DialogTitle, Empty, Input, Label, PageHeader,
    Spinner, Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
};

#[derive(Serialize, Deserialize)]
struct CreateProjectReq {
    code: String,
    name: String,
}

#[component]
pub fn ProjectsPage() -> impl IntoView {
    let reload = RwSignal::new(0u32);
    let projects = LocalResource::new(move || {
        let _ = reload.get();
        async move { get_json::<Page<Project>>("/v1/projects").await }
    });

    let show_dialog = RwSignal::new(false);
    let new_code = RwSignal::new(String::new());
    let new_name = RwSignal::new(String::new());
    let create_err: RwSignal<Option<String>> = RwSignal::new(None);

    let on_create = move |_| {
        let code = new_code.get();
        let name = new_name.get();
        if code.is_empty() || name.is_empty() {
            return;
        }
        leptos::task::spawn_local(async move {
            match post_json::<CreateProjectReq, Project>(
                "/v1/projects",
                &CreateProjectReq { code, name },
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

    view! {
        <div class="space-y-6">
            <PageHeader title="Projects".to_string()>
                <Button variant=ButtonVariant::Default size=ButtonSize::Sm on:click=move |_| show_dialog.set(true)>
                    "New project"
                </Button>
            </PageHeader>

            <Dialog open=show_dialog>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>"New project"</DialogTitle>
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
                            <Input value=new_code placeholder="my-project".to_string() />
                        </div>
                        <div class="space-y-1">
                            <Label>"Name"</Label>
                            <Input value=new_name placeholder="My Project".to_string() />
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
                {move || projects.get().map(|result| {
                    let nav = navigate.clone();
                    match result {
                        Err(e) => view! {
                            <Alert variant=AlertVariant::Destructive>
                                <AlertTitle>"Failed to load projects"</AlertTitle>
                                <AlertDescription>{e.message}</AlertDescription>
                            </Alert>
                        }.into_any(),
                        Ok(page) if page.items.is_empty() => view! {
                            <Empty
                                title="No projects yet".to_string()
                                description="Create a project to start managing secrets and config.".to_string()
                            >
                                // lock icon
                                <svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="text-muted-foreground/40">
                                    <rect width="18" height="11" x="3" y="11" rx="2" ry="2"/>
                                    <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                                </svg>
                                <Button variant=ButtonVariant::Default size=ButtonSize::Sm on:click=move |_| show_dialog.set(true)>
                                    "Create your first project"
                                </Button>
                            </Empty>
                        }.into_any(),
                        Ok(page) => view! {
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
                                        each=move || page.items.clone()
                                        key=|p| p.id.clone()
                                        children=move |p| {
                                            let id = p.id.clone();
                                            let nav2 = nav.clone();
                                            let ts = p.created_at.clone();
                                            let rel = relative_time(&ts);
                                            view! {
                                                <TableRow>
                                                    <TableCell>
                                                        <button
                                                            class="text-primary hover:underline text-sm font-mono"
                                                            on:click=move |_| {
                                                                nav2(&format!("/projects/{}", id), Default::default())
                                                            }
                                                        >
                                                            {p.code.clone()}
                                                        </button>
                                                    </TableCell>
                                                    <TableCell>{p.name.clone()}</TableCell>
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
                })}
            </Suspense>
        </div>
    }
}
