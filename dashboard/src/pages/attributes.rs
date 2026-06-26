use crate::api::{del, get_json, patch_json, post_json, AttrDef};
use leptos::prelude::*;
use serde::{Deserialize, Serialize};
use soma_ui::{
    Alert, AlertDescription, AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
    AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertTitle,
    AlertVariant, Button, ButtonSize, ButtonVariant, Dialog, DialogContent, DialogFooter,
    DialogHeader, DialogTitle, Input, Label, PageHeader, Select, SelectContent, SelectItem, Switch,
    Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
};

/// B5: server fields are is_required / is_pii / sort_order.
#[derive(Serialize, Deserialize)]
struct CreateAttrReq {
    code: String,
    name: String,
    data_type: String,
    entity_type: String,
    is_required: bool,
    is_pii: bool,
}

#[derive(Serialize, Deserialize)]
struct PatchAttrReq {
    name: String,
    is_required: bool,
    is_pii: bool,
}

#[component]
pub fn AttributesPage() -> impl IntoView {
    let entity_type = RwSignal::new("secret".to_string());

    let attrs = LocalResource::new(move || {
        let et = entity_type.get();
        async move { get_json::<Vec<AttrDef>>(&format!("/v1/meta/attr-defs?entity_type={}", et)).await }
    });

    let show_dialog = RwSignal::new(false);
    let edit_id: RwSignal<Option<String>> = RwSignal::new(None);
    let new_code = RwSignal::new(String::new());
    let new_name = RwSignal::new(String::new());
    let new_data_type = RwSignal::new("text".to_string());
    let new_required = RwSignal::new(false);
    let new_pii = RwSignal::new(false);
    let dialog_err: RwSignal<Option<String>> = RwSignal::new(None);
    let confirm_delete_id: RwSignal<Option<String>> = RwSignal::new(None);
    let confirm_delete_open = RwSignal::new(false);

    let reset_form = move || {
        edit_id.set(None);
        new_code.set(String::new());
        new_name.set(String::new());
        new_data_type.set("text".to_string());
        new_required.set(false);
        new_pii.set(false);
        dialog_err.set(None);
    };

    let on_save = move |_| {
        let et = entity_type.get();
        let code = new_code.get();
        let name = new_name.get();
        let data_type = new_data_type.get();
        let required = new_required.get();
        let pii = new_pii.get();

        if name.is_empty() {
            return;
        }

        if let Some(id) = edit_id.get_untracked() {
            leptos::task::spawn_local(async move {
                match patch_json::<PatchAttrReq, AttrDef>(
                    &format!("/v1/meta/attr-defs/{}", id),
                    &PatchAttrReq {
                        name,
                        is_required: required,
                        is_pii: pii,
                    },
                )
                .await
                {
                    Ok(_) => {
                        show_dialog.set(false);
                        reset_form();
                        attrs.refetch();
                    }
                    Err(e) => dialog_err.set(Some(e.message)),
                }
            });
        } else {
            if code.is_empty() {
                return;
            }
            leptos::task::spawn_local(async move {
                match post_json::<CreateAttrReq, AttrDef>(
                    "/v1/meta/attr-defs",
                    &CreateAttrReq {
                        code,
                        name,
                        data_type,
                        entity_type: et,
                        is_required: required,
                        is_pii: pii,
                    },
                )
                .await
                {
                    Ok(_) => {
                        show_dialog.set(false);
                        reset_form();
                        attrs.refetch();
                    }
                    Err(e) => dialog_err.set(Some(e.message)),
                }
            });
        }
    };


    view! {
        <div class="space-y-6">
            <PageHeader
                title="Attribute Registry".to_string()
                subtitle=Some("Add typed fields to entities — no migrations required".to_string())
            >
                <Button
                    variant=ButtonVariant::Default
                    size=ButtonSize::Sm
                    on:click=move |_| { reset_form(); show_dialog.set(true); }
                >
                    "Add attribute"
                </Button>
            </PageHeader>

            <div class="space-y-2">
                <Label>"Entity type"</Label>
                <div class="w-48">
                    <Select value=entity_type placeholder="Select entity".to_string()>
                        <SelectContent>
                            <SelectItem value="secret">"secret"</SelectItem>
                            <SelectItem value="config_key">"config_key"</SelectItem>
                        </SelectContent>
                    </Select>
                </div>
            </div>

            <Dialog open=show_dialog>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>
                            {move || if edit_id.get().is_some() { "Edit attribute" } else { "Add attribute" }}
                        </DialogTitle>
                    </DialogHeader>
                    <div class="space-y-4 my-4">
                        {move || dialog_err.get().map(|e| view! {
                            <Alert variant=AlertVariant::Destructive>
                                <AlertTitle>"Error"</AlertTitle>
                                <AlertDescription>{e}</AlertDescription>
                            </Alert>
                        })}
                        {move || edit_id.get().is_none().then(|| view! {
                            <div class="space-y-1">
                                <Label>"Code (slug)"</Label>
                                <Input value=new_code placeholder="my_field".to_string() />
                            </div>
                        })}
                        <div class="space-y-1">
                            <Label>"Name"</Label>
                            <Input value=new_name placeholder="My field".to_string() />
                        </div>
                        <div class="space-y-1">
                            <Label>"Data type"</Label>
                            <Select value=new_data_type placeholder="Select type".to_string()>
                                <SelectContent>
                                    <SelectItem value="text">"text"</SelectItem>
                                    <SelectItem value="int">"int"</SelectItem>
                                    <SelectItem value="float">"float"</SelectItem>
                                    <SelectItem value="bool">"bool"</SelectItem>
                                    <SelectItem value="json">"json"</SelectItem>
                                </SelectContent>
                            </Select>
                        </div>
                        <div class="flex items-center gap-3">
                            <Label>"Required"</Label>
                            <Switch checked=new_required />
                        </div>
                        <div class="flex items-center gap-3">
                            <Label>"PII"</Label>
                            <Switch checked=new_pii />
                        </div>
                    </div>
                    <DialogFooter>
                        <Button
                            variant=ButtonVariant::Outline
                            on:click=move |_| { show_dialog.set(false); reset_form(); }
                        >
                            "Cancel"
                        </Button>
                        <Button variant=ButtonVariant::Default on:click=on_save>
                            "Save"
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>

            <AlertDialog open=confirm_delete_open>
                <AlertDialogContent>
                    <AlertDialogHeader>
                        <AlertDialogTitle>"Delete attribute?"</AlertDialogTitle>
                        <AlertDialogDescription>
                            "This attribute definition will be removed."
                        </AlertDialogDescription>
                    </AlertDialogHeader>
                    <AlertDialogFooter>
                        <AlertDialogCancel>"Cancel"</AlertDialogCancel>
                        <AlertDialogAction on_click=Callback::new(move |_| {
                            if let Some(id) = confirm_delete_id.get_untracked() {
                                leptos::task::spawn_local(async move {
                                    let _ = del(&format!("/v1/meta/attr-defs/{}", id)).await;
                                    attrs.refetch();
                                });
                            }
                        })>
                            "Delete"
                        </AlertDialogAction>
                    </AlertDialogFooter>
                </AlertDialogContent>
            </AlertDialog>

            // Bug fix: render actions inside the same table row as the data so edit/delete
            // are always bound to the correct attribute by ID, not by insertion index.
            {move || attrs.get().map(|result| {
                match result {
                    Err(e) => view! {
                        <Alert variant=AlertVariant::Destructive>
                            <AlertTitle>"Failed to load attributes"</AlertTitle>
                            <AlertDescription>{e.message}</AlertDescription>
                        </Alert>
                    }.into_any(),
                    Ok(list) => {
                        let list_sv = StoredValue::new(list);
                        view! {
                            <Table>
                                <TableHeader>
                                    <TableRow>
                                        <TableHead>"Code"</TableHead>
                                        <TableHead>"Name"</TableHead>
                                        <TableHead>"Data type"</TableHead>
                                        <TableHead>"Required"</TableHead>
                                        <TableHead>"PII"</TableHead>
                                        <TableHead>"Sort"</TableHead>
                                        <TableHead>"Actions"</TableHead>
                                    </TableRow>
                                </TableHeader>
                                <TableBody>
                                    <For
                                        each=move || list_sv.get_value()
                                        key=|a| a.id.clone()
                                        children=move |attr| {
                                            // Capture all data needed for click handlers by value,
                                            // keyed by attr.id — never by position.
                                            let id_edit = StoredValue::new(attr.id.clone());
                                            let id_del = StoredValue::new(attr.id.clone());
                                            let attr_name = attr.name.clone();
                                            let attr_data_type = attr.data_type.clone();
                                            let attr_required = attr.is_required;
                                            let attr_pii = attr.is_pii;
                                            view! {
                                                <TableRow>
                                                    <TableCell class="font-mono text-xs".to_string()>
                                                        {attr.code.clone()}
                                                    </TableCell>
                                                    <TableCell>{attr.name.clone()}</TableCell>
                                                    <TableCell>{attr.data_type.clone()}</TableCell>
                                                    <TableCell>
                                                        {if attr.is_required { "Yes" } else { "No" }}
                                                    </TableCell>
                                                    <TableCell>
                                                        {if attr.is_pii { "Yes" } else { "No" }}
                                                    </TableCell>
                                                    <TableCell>{attr.sort_order.to_string()}</TableCell>
                                                    <TableCell>
                                                        <div class="flex items-center gap-1">
                                                            <Button
                                                                variant=ButtonVariant::Ghost
                                                                size=ButtonSize::Sm
                                                                on:click=move |_| {
                                                                    edit_id.set(Some(id_edit.get_value()));
                                                                    new_name.set(attr_name.clone());
                                                                    new_data_type.set(attr_data_type.clone());
                                                                    new_required.set(attr_required);
                                                                    new_pii.set(attr_pii);
                                                                    show_dialog.set(true);
                                                                }
                                                            >
                                                                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                                                    <path d="M17 3a2.85 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z"/>
                                                                </svg>
                                                            </Button>
                                                            <Button
                                                                variant=ButtonVariant::Ghost
                                                                size=ButtonSize::Sm
                                                                on:click=move |_| {
                                                                    confirm_delete_id.set(Some(id_del.get_value()));
                                                                    confirm_delete_open.set(true);
                                                                }
                                                            >
                                                                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="text-destructive">
                                                                    <path d="M3 6h18"/>
                                                                    <path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/>
                                                                    <path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/>
                                                                </svg>
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
                }
            })}
        </div>
    }
}
