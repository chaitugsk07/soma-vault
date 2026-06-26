use crate::api::ApiError;
use leptos::prelude::*;
use leptos_router::hooks::use_navigate;
use serde::{Deserialize, Serialize};
use soma_ui::{
    Alert, AlertDescription, AlertTitle, AlertVariant, Button, ButtonVariant, Card, CardContent,
    Input, Label,
};
use wasm_bindgen::JsValue;
use web_sys::MouseEvent;

#[derive(Serialize, Deserialize)]
struct LoginReq {
    token: String,
}

/// Post to the session endpoint without the global 401→/login redirect so that a bad
/// token shows an inline error instead of silently reloading the page.
async fn post_login(token: String) -> Result<(), ApiError> {
    let body = serde_json::to_string(&LoginReq { token }).unwrap();
    let resp = gloo_net::http::Request::post("/v1/auth/session")
        .header("Content-Type", "application/json")
        .body(JsValue::from_str(&body))
        .map_err(|e| ApiError { status: 0, message: e.to_string() })?
        .send()
        .await
        .map_err(|e| ApiError { status: 0, message: e.to_string() })?;
    if resp.ok() {
        Ok(())
    } else {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        let msg = if status == 401 {
            "Invalid token — please check and try again.".to_string()
        } else {
            serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(|s| s.to_string()))
                .unwrap_or(body)
        };
        Err(ApiError { status, message: msg })
    }
}

#[component]
pub fn LoginPage() -> impl IntoView {
    let token = RwSignal::new(String::new());
    let error: RwSignal<Option<ApiError>> = RwSignal::new(None);
    let loading = RwSignal::new(false);
    let navigate = use_navigate();

    let on_submit = StoredValue::new(move |_: MouseEvent| {
        let tok = token.get();
        if tok.is_empty() {
            return;
        }
        let nav = navigate.clone();
        loading.set(true);
        error.set(None);
        leptos::task::spawn_local(async move {
            match post_login(tok).await {
                Ok(_) => nav("/projects", Default::default()),
                Err(e) => {
                    error.set(Some(e));
                    loading.set(false);
                }
            }
        });
    });

    view! {
        <div class="min-h-screen flex flex-col items-center justify-center bg-background p-4 gap-8">
            // Product wordmark
            <div class="flex flex-col items-center gap-2 select-none">
                // Vault / lock icon
                <div class="w-12 h-12 rounded-xl bg-primary/10 flex items-center justify-center">
                    <svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="text-primary">
                        <rect width="18" height="11" x="3" y="11" rx="2" ry="2"/>
                        <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                        <circle cx="12" cy="16" r="1"/>
                    </svg>
                </div>
                <span class="font-heading font-bold text-2xl text-foreground tracking-tight">
                    "soma-vault"
                </span>
                <p class="text-sm text-muted-foreground">"Secrets and config, out of your repo."</p>
            </div>

            // Sign-in card
            <Card class="w-full max-w-sm shadow-elev-md".to_string()>
                <CardContent>
                    <div class="space-y-4 pt-6">
                        {move || error.get().map(|e| view! {
                            <Alert variant=AlertVariant::Destructive>
                                <AlertTitle>"Authentication failed"</AlertTitle>
                                <AlertDescription>{e.message}</AlertDescription>
                            </Alert>
                        })}
                        <div class="space-y-1">
                            <Label>"Access token"</Label>
                            <Input
                                value=token
                                input_type="password".to_string()
                                placeholder="sv_tok_…".to_string()
                            />
                        </div>
                        {move || view! {
                            <Button
                                variant=ButtonVariant::Default
                                disabled=loading.get()
                                on:click=move |e| on_submit.get_value()(e)
                            >
                                {if loading.get() { "Signing in…" } else { "Sign in" }}
                            </Button>
                        }}
                    </div>
                </CardContent>
            </Card>
        </div>
    }
}
