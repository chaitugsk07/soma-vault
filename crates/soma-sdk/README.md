# soma-sdk

In-process Rust client for [soma-vault](https://github.com/chaitugsk07/soma-vault).
Read secrets and config inside your application — no shelling out to the CLI.

## Quickstart

```toml
# Cargo.toml
[dependencies]
soma-sdk = "0.1"
serde = { version = "1", features = ["derive"] }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

## Plug-and-play: zero-config injection

Set `SOMA_URL`, `SOMA_TOKEN`, `SOMA_PROJECT`, `SOMA_ENVIRONMENT` in your
deployment environment, then add one line at the top of `main`:

```rust
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load all secrets+config and inject into the process environment.
    // Vault values overwrite any pre-existing env var with the same name.
    soma_sdk::init().await?;

    // Existing code reads from env — no .env file needed.
    let db_url = std::env::var("DATABASE_URL")?;
    Ok(())
}
```

## Typed config struct

```rust
use serde::Deserialize;

#[derive(Deserialize)]
struct Config {
    database_password: String,  // vault path "database/password"
    server_port: u16,           // vault path "server/port", "8080" coerced to u16
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Zero-config: builds the client from SOMA_* env vars, loads, deserializes.
    let cfg: Config = soma_sdk::from_env().await?;
    println!("Listening on port {}", cfg.server_port);
    Ok(())
}
```

## Key mapping

Vault path → env var name (identical to `soma run` / `soma export`):
uppercase every letter, replace every non-`[A-Z0-9]` character with `_`.
Struct field names are the lowercase form.

| Vault path          | Env var (`init`)   | Struct field (`load`) |
|---------------------|--------------------|-----------------------|
| `database/password` | `DATABASE_PASSWORD`| `database_password`   |
| `server/port`       | `SERVER_PORT`      | `server_port`         |
| `db-host`           | `DB_HOST`          | `db_host`             |

String values that look like JSON scalars (`"8080"`, `"true"`) are coerced to
the target field type automatically.

## Manual client

```rust
use soma_sdk::SomaClient;

#[tokio::main]
async fn main() -> Result<(), soma_sdk::Error> {
    let client = SomaClient::builder()
        .url("http://localhost:8080")   // or SOMA_URL
        .token("sv_...")                // or SOMA_TOKEN
        .project("your-project-uuid")  // or SOMA_PROJECT
        .environment("your-env-uuid")  // or SOMA_ENVIRONMENT
        .build()?;

    // Single reads
    let db_pass: String = client.secret("database/password").await?;
    let port: String    = client.config("server/port").await?;

    // Bulk load
    let all = client.load_all().await?;

    // In-memory cache (sub-microsecond sync reads)
    let cache = client.cache().await?;
    println!("{}", cache.get("database/password").unwrap_or(""));

    // Inject into process environment (vault wins)
    client.inject(true).await?;

    // Typed deserialization
    #[derive(serde::Deserialize)]
    struct Cfg { database_password: String, server_port: u16 }
    let cfg: Cfg = client.load().await?;

    Ok(())
}
```

## Environment variables

| Variable           | Default                   | Description          |
|--------------------|---------------------------|----------------------|
| `SOMA_URL`         | `http://127.0.0.1:8080`   | soma-vault server URL|
| `SOMA_TOKEN`       | *(required)*              | Bearer token         |
| `SOMA_PROJECT`     | *(required)*              | Project UUID         |
| `SOMA_ENVIRONMENT` | *(required)*              | Environment UUID     |

Builder methods override env vars.

## How it works

soma-vault encrypts secrets server-side with envelope encryption (per-secret DEK
wrapped by a KMS-held KEK). When you call `client.secret(path)`, the server decrypts
the DEK, recovers the plaintext, and returns it over your authenticated HTTPS channel.
The SDK never touches cryptographic material — it receives and forwards plaintext only.

## Integration test

```sh
SOMA_SDK_TEST_URL=http://127.0.0.1:18100 \
SOMA_SDK_TEST_TOKEN=<root-token> \
cargo test -p soma-sdk -- --test-threads=1
```
