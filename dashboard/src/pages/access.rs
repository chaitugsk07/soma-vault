use crate::api::{del, get_json, get_me, post_json, CreatedToken, Token};
use crate::util::{copy_to_clipboard, relative_time};
use leptos::prelude::*;
use serde::{Deserialize, Serialize};
use soma_ui::{
    Alert, AlertDescription, AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
    AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertTitle,
    AlertVariant, Badge, BadgeVariant, Button, ButtonSize, ButtonVariant, Dialog, DialogContent,
    DialogFooter, DialogHeader, DialogTitle, Empty, Input, Label, PageHeader, Select,
    SelectContent, SelectItem, Spinner, Table, TableBody, TableCell, TableHead, TableHeader,
    TableRow,
};

#[derive(Serialize, Deserialize)]
struct CreateTokenReq {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    role: Option<String>,
}

fn role_badge(role: &str) -> impl IntoView {
    let label = role.to_string();
    let variant = match role {
        "admin" => BadgeVariant::Destructive,
        "developer" => BadgeVariant::Default,
        _ => BadgeVariant::Secondary,
    };
    view! { <Badge variant=variant>{label}</Badge> }
}

#[component]
pub fn AccessPage() -> impl IntoView {
    let me = LocalResource::new(|| async { get_me().await });
    let tokens =
        LocalResource::new(|| async { get_json::<Vec<Token>>("/v1/auth/tokens").await });

    let show_dialog = RwSignal::new(false);
    let new_name = RwSignal::new(String::new());
    let new_role = RwSignal::new("developer".to_string());
    let created_token_value: RwSignal<Option<String>> = RwSignal::new(None);
    let create_err: RwSignal<Option<String>> = RwSignal::new(None);
    let tok_copy_label = RwSignal::new("Copy");

    let on_create = move |_| {
        let name = new_name.get();
        if name.is_empty() {
            return;
        }
        let role = new_role.get();
        leptos::task::spawn_local(async move {
            match post_json::<CreateTokenReq, CreatedToken>(
                "/v1/auth/tokens",
                &CreateTokenReq {
                    name,
                    role: Some(role),
                },
            )
            .await
            {
                Ok(tok) => {
                    created_token_value.set(Some(tok.token));
                    new_name.set(String::new());
                    new_role.set("developer".to_string());
                    tok_copy_label.set("Copy");
                    tokens.refetch();
                }
                Err(e) => create_err.set(Some(e.message)),
            }
        });
    };

    view! {
        <div class="space-y-6">
            <PageHeader title="Access".to_string()>
                <div class="flex items-center gap-3">
                    // Current user's role pill
                    <Suspense fallback=|| view! { <></> }>
                        {move || me.get().map(|r| r.ok().and_then(|m| m.role).map(|role| {
                            view! {
                                <span class="text-sm text-muted-foreground">
                                    "Your role: "
                                    {role_badge(&role)}
                                </span>
                            }
                        }))}
                    </Suspense>
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
                </div>
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
                            <div class="space-y-4">
                                <div class="space-y-1">
                                    <Label>"Token name"</Label>
                                    <Input value=new_name placeholder="ci-deploy".to_string() />
                                </div>
                                <div class="space-y-1">
                                    <Label>"Role"</Label>
                                    <Select value=new_role placeholder="Select role".to_string()>
                                        <SelectContent>
                                            <SelectItem value="admin">"admin"</SelectItem>
                                            <SelectItem value="developer">"developer"</SelectItem>
                                            <SelectItem value="reader">"reader"</SelectItem>
                                        </SelectContent>
                                    </Select>
                                </div>
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
                        Ok(list) if list.is_empty() => view! {
                            <Empty
                                title="No tokens yet".to_string()
                                description="Create a token to authenticate API access.".to_string()
                            >
                                <svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="text-muted-foreground/40">
                                    <circle cx="8" cy="8" r="6"/>
                                    <path d="m22 22-4.3-4.3"/>
                                    <path d="M11.9 11.9a3.9 3.9 0 1 0-5.5-5.5"/>
                                </svg>
                            </Empty>
                        }.into_any(),
                        Ok(list) => view! {
                            <Table>
                                <TableHeader>
                                    <TableRow>
                                        <TableHead>"Name"</TableHead>
                                        <TableHead>"Role"</TableHead>
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
                                            let role = tok.role.clone().unwrap_or_else(|| "developer".to_string());
                                            view! {
                                                <TableRow>
                                                    <TableCell class="font-medium".to_string()>{tok.name.clone()}</TableCell>
                                                    <TableCell>
                                                        {role_badge(&role)}
                                                    </TableCell>
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
