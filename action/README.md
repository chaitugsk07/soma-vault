# soma-vault GitHub Action

Injects [soma-vault](https://github.com/soma-platform/soma-vault) secrets and config into subsequent workflow steps by writing them to `$GITHUB_ENV`.

## Usage

```yaml
- uses: soma-platform/soma-vault/action@v1
  with:
    server: ${{ vars.SOMA_SERVER }}
    token: ${{ secrets.SOMA_TOKEN }}
    project: my-project
    environment: production
```

After this step, every injected secret is available as an environment variable in subsequent steps — just like GitHub secrets, but managed in soma-vault.

## Inputs

| Input         | Required | Description |
|---------------|----------|-------------|
| `server`      | yes      | soma-vault server URL (e.g. `https://vault.example.com`) |
| `token`       | yes      | Bearer token for the vault. Store as a GitHub secret. |
| `project`     | yes      | Project ID or code |
| `environment` | yes      | Environment ID or code |
| `version`     | no       | Pinned soma CLI version (e.g. `0.1.0`). If omitted, builds from source. Once official releases are published, set this to avoid the build step. |

## Security

- Secret values are masked in CI logs via `::add-mask::` before being written to `$GITHUB_ENV`.
- Values are never written to a `.env` file on disk.
- Use `${{ secrets.SOMA_TOKEN }}` for the `token` input — never hard-code it.

## Full example

```yaml
name: Deploy

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Inject secrets from soma-vault
        uses: soma-platform/soma-vault/action@v1
        with:
          server: ${{ vars.SOMA_SERVER }}
          token: ${{ secrets.SOMA_TOKEN }}
          project: my-project
          environment: production

      # Subsequent steps see injected vars as environment variables.
      - name: Deploy
        run: ./scripts/deploy.sh
        # DATABASE_URL, API_KEY, etc. are now available as env vars.
```

## How it works

1. Installs the `soma` CLI (downloads a prebuilt binary if `version` is set; otherwise `cargo install` from source).
2. Calls `soma export --format dotenv` to fetch all secrets and config for the given project+environment.
3. Parses the dotenv output and writes each `KEY=VALUE` pair to `$GITHUB_ENV`, masked from logs.
