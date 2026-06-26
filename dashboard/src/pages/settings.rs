use crate::api::{del, get_json, post_json, CreatedToken, HealthStatus, Token};
use crate::util::{copy_to_clipboard, relative_time};
use leptos::prelude::*;
use serde::{Deserialize, Serialize};
use soma_ui::{
    Alert, AlertDescription, AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
    AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertTitle,
    AlertVariant, Button, ButtonSize, ButtonVariant, Dialog, DialogContent, DialogFooter,
    DialogHeader, DialogTitle, Input, Label, PageHeader, Spinner, Stat, Table, TableBody,
    TableCell, TableHead, TableHeader, TableRow,
};

#[derive(Serialize, Deserialize)]
struct CreateTokenReq {
    name: String,
}

#[component]
pub fn SettingsPage() -> impl IntoView {
    view! {
        <div class="space-y-10">
            <TokensSection />
            <HealthSection />
        </div>
    }
}

#[component]
fn TokensSection() -> impl IntoView {
    // B6: correct route is /v1/auth/tokens (not /v1/tokens).
    let tokens = LocalResource::new(|| async { get_json::<Vec<Token>>("/v1/auth/tokens").await });

    let show_dialog = RwSignal::new(false);
    let new_name = RwSignal::new(String::new());
    let created_token_value: RwSignal<Option<String>> = RwSignal::new(None);
    let create_err: RwSignal<Option<String>> = RwSignal::new(None);
    let tok_copy_label = RwSignal::new("Copy");

    let on_create = move |_| {
        let name = new_name.get();
        if name.is_empty() {
            return;
        }
        leptos::task::spawn_local(async move {
            match post_json::<CreateTokenReq, CreatedToken>(
                "/v1/auth/tokens",
                &CreateTokenReq { name },
            )
            .await
            {
                Ok(tok) => {
                    created_token_value.set(Some(tok.token));
                    new_name.set(String::new());
                    tok_copy_label.set("Copy");
                    tokens.refetch();
                }
                Err(e) => create_err.set(Some(e.message)),
            }
        });
    };

    view! {
        <div class="space-y-6">
            <PageHeader title="Settings".to_string()>
                <Button
                    variant=ButtonVariant::Default
                    size=ButtonSize::Sm
                    on:click=move |_| {
                        show_dialog.set(true);
                        created_token_value.set(None);
                        create_err.set(None);
                        tok_copy_label.set("Copy");
                    }
                >
                    "Create token"
                </Button>
            </PageHeader>

            <Dialog open=show_dialog>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>"Create access token"</DialogTitle>
                    </DialogHeader>
                    <div class="space-y-4 my-4">
                        {move || create_err.get().map(|e| view! {
                            <Alert variant=AlertVariant::Destructive>
                                <AlertTitle>"Error"</AlertTitle>
                                <AlertDescription>{e}</AlertDescription>
                            </Alert>
                        })}
                        {move || created_token_value.get().map(|tok| {
                            let tok_for_copy = tok.clone();
                            let tok_signal = RwSignal::new(tok);
                            view! {
                                <Alert variant=AlertVariant::Warning>
                                    <AlertTitle>"Copy this token — it won't be shown again"</AlertTitle>
                                    <AlertDescription>
                                        <div class="mt-2 flex items-center gap-2">
                                            <div class="flex-1">
                                                <Input value=tok_signal class="font-mono text-xs".to_string() />
                                            </div>
                                            <Button
                                                variant=ButtonVariant::Ghost
                                                size=ButtonSize::Icon
                                                on:click=move |_| copy_to_clipboard(tok_for_copy.clone(), tok_copy_label)
                                            >
                                                {move || if tok_copy_label.get() == "Copied!" {
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
                                    </AlertDescription>
                                </Alert>
                            }
                        })}
                        {move || created_token_value.get().is_none().then(|| view! {
                            <div class="space-y-1">
                                <Label>"Token name"</Label>
                                <Input value=new_name placeholder="ci-deploy".to_string() />
                            </div>
                        })}
                    </div>
                    <DialogFooter>
                        {move || if created_token_value.get().is_some() {
                            view! {
                                <Button variant=ButtonVariant::Default on:click=move |_| show_dialog.set(false)>
                                    "Done"
                                </Button>
                            }.into_any()
                        } else {
                            view! {
                                <div class="flex gap-2">
                                    <Button variant=ButtonVariant::Outline on:click=move |_| show_dialog.set(false)>
                                        "Cancel"
                                    </Button>
                                    <Button variant=ButtonVariant::Default on:click=on_create>
                                        "Create"
                                    </Button>
                                </div>
                            }.into_any()
                        }}
                    </DialogFooter>
                </DialogContent>
            </Dialog>

            <Suspense fallback=|| view! { <div class="flex justify-center py-8"><Spinner /></div> }>
                {move || tokens.get().map(|result| {
                    match result {
                        Err(e) => view! {
                            <Alert variant=AlertVariant::Destructive>
                                <AlertTitle>"Failed to load tokens"</AlertTitle>
                                <AlertDescription>{e.message}</AlertDescription>
                            </Alert>
                        }.into_any(),
                        Ok(list) => view! {
                            <Table>
                                <TableHeader>
                                    <TableRow>
                                        <TableHead>"Name"</TableHead>
                                        <TableHead>"Created"</TableHead>
                                        <TableHead>"Last used"</TableHead>
                                        <TableHead>"Actions"</TableHead>
                                    </TableRow>
                                </TableHeader>
                                <TableBody>
                                    <For
                                        each=move || list.clone()
                                        key=|t| t.id.clone()
                                        children=move |tok| {
                                            let tok_id = StoredValue::new(tok.id.clone());
                                            let confirm = RwSignal::new(false);
                                            let created_ts = tok.created_at.clone();
                                            let created_rel = relative_time(&created_ts);
                                            let last_used_display = tok.last_used_at.clone().map(|ts| {
                                                let rel = relative_time(&ts);
                                                (rel, ts)
                                            });
                                            view! {
                                                <TableRow>
                                                    <TableCell class="font-medium".to_string()>{tok.name.clone()}</TableCell>
                                                    <TableCell class="text-xs text-muted-foreground".to_string()>
                                                        <span title=created_ts>{created_rel}</span>
                                                    </TableCell>
                                                    <TableCell class="text-xs text-muted-foreground".to_string()>
                                                        {match last_used_display {
                                                            Some((rel, ts)) => view! { <span title=ts>{rel}</span> }.into_any(),
                                                            None => view! { <span>"Never"</span> }.into_any(),
                                                        }}
                                                    </TableCell>
                                                    <TableCell>
                                                        <Button
                                                            variant=ButtonVariant::Ghost
                                                            size=ButtonSize::Sm
                                                            on:click=move |_| confirm.set(true)
                                                        >
                                                            "Revoke"
                                                        </Button>
                                                        <AlertDialog open=confirm>
                                                            <AlertDialogContent>
                                                                <AlertDialogHeader>
                                                                    <AlertDialogTitle>"Revoke token?"</AlertDialogTitle>
                                                                    <AlertDialogDescription>
                                                                        "This token will immediately stop working."
                                                                    </AlertDialogDescription>
                                                                </AlertDialogHeader>
                                                                <AlertDialogFooter>
                                                                    <AlertDialogCancel>"Cancel"</AlertDialogCancel>
                                                                    <AlertDialogAction on_click=Callback::new(move |_| {
                                                                        let id = tok_id.get_value();
                                                                        leptos::task::spawn_local(async move {
                                                                            let _ = del(&format!("/v1/auth/tokens/{}", id)).await;
                                                                            tokens.refetch();
                                                                        });
                                                                    })>
                                                                        "Revoke"
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
                        }.into_any(),
                    }
                })}
            </Suspense>
        </div>
    }
}

#[component]
fn HealthSection() -> impl IntoView {
    // B7: health route is /health (not /v1/health).
    let health = LocalResource::new(|| async { get_json::<HealthStatus>("/health").await });

    view! {
        <div class="space-y-4">
            <h2 class="text-lg font-semibold text-foreground">"Seal health"</h2>
            <Suspense fallback=|| view! { <Spinner /> }>
                {move || health.get().map(|result| {
                    match result {
                        Err(e) => view! {
                            <Alert variant=AlertVariant::Destructive>
                                <AlertTitle>"Health check failed"</AlertTitle>
                                <AlertDescription>{e.message}</AlertDescription>
                            </Alert>
                        }.into_any(),
                        Ok(h) => {
                            let is_software = h.seal_backend == "software";
                            view! {
                                <div class="space-y-4">
                                    {is_software.then(|| view! {
                                        <Alert variant=AlertVariant::Warning>
                                            <AlertTitle>"Software KMS detected"</AlertTitle>
                                            <AlertDescription>
                                                "Software KMS is not production auto-unseal. Configure AWS/GCP/Azure KMS for production deployments."
                                            </AlertDescription>
                                        </Alert>
                                    })}
                                    <div class="grid grid-cols-2 gap-4">
                                        <Stat label="Status".to_string() value=h.status.clone() />
                                        <Stat label="Seal backend".to_string() value=h.seal_backend.clone() />
                                    </div>
                                </div>
                            }.into_any()
                        }
                    }
                })}
            </Suspense>
        </div>
    }
}
