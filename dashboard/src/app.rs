use crate::pages::{
    AccessPage, AttributesPage, AuditPage, ConfigDetailPage, ConfigPage, LoginPage,
    ProjectDetailPage, ProjectsPage, SecretDetailPage, SecretsPage, SettingsPage,
};
use leptos::prelude::*;
use leptos_router::{
    components::{FlatRoutes, Redirect, Route, Router},
    hooks::use_location,
    path,
};
use soma_ui::{Button, ButtonSize, ButtonVariant, Sidebar, SidebarItem, ThemeToggle, STYLES};

fn sidebar_items() -> Vec<SidebarItem> {
    vec![
        SidebarItem {
            label: "Projects".to_string(),
            href: "/projects".to_string(),
            icon: Some(soma_ui::icons::icondata::LuFolderOpen),
        },
        SidebarItem {
            label: "Access".to_string(),
            href: "/access".to_string(),
            icon: Some(soma_ui::icons::icondata::LuKey),
        },
        SidebarItem {
            label: "Audit".to_string(),
            href: "/audit".to_string(),
            icon: Some(soma_ui::icons::icondata::LuShield),
        },
        SidebarItem {
            label: "Settings".to_string(),
            href: "/settings".to_string(),
            icon: Some(soma_ui::icons::icondata::LuSettings),
        },
        SidebarItem {
            label: "Attributes".to_string(),
            href: "/settings/attributes".to_string(),
            icon: Some(soma_ui::icons::icondata::LuList),
        },
    ]
}

#[component]
fn AppShell(children: Children) -> impl IntoView {
    let location = use_location();
    let active_path = Signal::derive(move || location.pathname.get());

    let brand = view! {
        <span class="font-heading font-bold text-lg text-foreground tracking-tight">
            "soma-vault"
        </span>
    }
    .into_any();

    view! {
        <div class="flex h-screen bg-background overflow-hidden">
            <Sidebar
                items=sidebar_items()
                active_path=active_path
                brand=brand
            />
            <div class="flex flex-col flex-1 overflow-hidden">
                // Top bar
                <header class="flex items-center justify-between px-4 h-14 border-b border-border bg-card shrink-0">
                    <span class="font-heading font-semibold text-foreground">"soma-vault"</span>
                    <div class="flex items-center gap-2">
                        <ThemeToggle />
                        // Bug 3 fix: inline user menu so overlay (z-40) and panel (z-50) share
                        // the same stacking context with no overflow-hidden ancestor isolating them.
                        {
                            let menu_open = RwSignal::new(false);
                            view! {
                                <div class="relative inline-block">
                                    // Click-catcher overlay rendered BEFORE the panel; lower z-index.
                                    <Show when=move || menu_open.get()>
                                        <div
                                            class="fixed inset-0 z-40"
                                            on:click=move |_| menu_open.set(false)
                                        />
                                        // Panel at z-50: sibling to overlay, later in DOM → paints on top.
                                        <div class="absolute right-0 z-50 mt-2 min-w-[10rem] rounded-md border border-border bg-card p-1 shadow-elev-md">
                                            <button
                                                class="flex w-full cursor-pointer items-center rounded-sm px-2 py-1.5 text-sm text-foreground hover:bg-accent hover:text-accent-foreground"
                                                on:click=move |_| {
                                                    menu_open.set(false);
                                                    leptos::task::spawn_local(async {
                                                        let _ = gloo_net::http::Request::delete("/v1/auth/session")
                                                            .send()
                                                            .await;
                                                        let window = web_sys::window().unwrap();
                                                        let _ = window.location().set_href("/login");
                                                    });
                                                }
                                            >
                                                "Sign out"
                                            </button>
                                        </div>
                                    </Show>
                                    <Button
                                        variant=ButtonVariant::Ghost
                                        size=ButtonSize::Icon
                                        on:click=move |_| menu_open.update(|v| *v = !*v)
                                    >
                                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                            <circle cx="12" cy="8" r="4"/>
                                            <path d="M20 21a8 8 0 1 0-16 0"/>
                                        </svg>
                                    </Button>
                                </div>
                            }
                        }
                    </div>
                </header>
                // Page content
                <main class="flex-1 overflow-auto p-6">
                    {children()}
                </main>
            </div>
        </div>
    }
}

#[component]
pub fn App() -> impl IntoView {
    view! {
        <style>{STYLES}</style>
        <Router>
            <AppRoutes />
        </Router>
    }
}

#[component]
fn AppRoutes() -> impl IntoView {
    let location = use_location();
    let is_login = move || location.pathname.get() == "/login";

    view! {
        {move || if is_login() {
            view! {
                <FlatRoutes fallback=|| view! { <LoginPage /> }>
                    <Route path=path!("/login") view=LoginPage />
                </FlatRoutes>
            }.into_any()
        } else {
            view! {
                <AppShell>
                    <FlatRoutes fallback=|| view! { <div class="text-muted-foreground">"Page not found"</div> }>
                        <Route path=path!("/") view=|| view! { <Redirect path="/projects" /> } />
                        <Route path=path!("/projects") view=ProjectsPage />
                        <Route path=path!("/projects/:pid") view=ProjectDetailPage />
                        <Route path=path!("/projects/:pid/envs/:eid/secrets") view=SecretsPage />
                        <Route path=path!("/projects/:pid/envs/:eid/secrets/*path") view=SecretDetailPage />
                        <Route path=path!("/projects/:pid/envs/:eid/config") view=ConfigPage />
                        <Route path=path!("/projects/:pid/envs/:eid/config/:key") view=ConfigDetailPage />
                        <Route path=path!("/access") view=AccessPage />
                        <Route path=path!("/audit") view=AuditPage />
                        <Route path=path!("/settings") view=SettingsPage />
                        <Route path=path!("/settings/attributes") view=AttributesPage />
                    </FlatRoutes>
                </AppShell>
            }.into_any()
        }}
    }
}
