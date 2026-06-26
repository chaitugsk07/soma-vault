# @soma-vault/sdk

TypeScript/Node.js client for [soma-vault](https://github.com/soma-platform/soma-vault). Zero runtime dependencies — uses Node 18+ native `fetch`.

## Install

```bash
npm install @soma-vault/sdk
```

## Quickstart

```ts
import { SomaClient } from '@soma-vault/sdk';

const client = new SomaClient({
  url: process.env.SOMA_URL,         // default: http://localhost:8080
  token: process.env.SOMA_TOKEN!,
  project: process.env.SOMA_PROJECT!,
  environment: process.env.SOMA_ENV!,
});

// Read a single secret
const dbPass = await client.secret('database/password');

// Read a config value
const port = await client.config('server/port');

// Read config and expand any $ref pointers in the value
const dbUrl = await client.config('db/url', { resolveRefs: true });

// Bulk-load everything in one HTTP call
const all = await client.loadAll();
// { 'database/password': 'hunter2', 'server/port': '8080', ... }

// Inject all values into process.env
await client.inject();
console.log(process.env['database/password']);
```

## Constructor

`new SomaClient(config?)` — each field resolves: explicit arg → env var → default.

| Field         | Env var                      | Default                  |
|---------------|------------------------------|--------------------------|
| `url`         | `SOMA_URL`                   | `http://localhost:8080`  |
| `token`       | `SOMA_TOKEN`                 | *(required)*             |
| `project`     | `SOMA_PROJECT`               | *(required)*             |
| `environment` | `SOMA_ENV` / `SOMA_ENVIRONMENT` | *(required)*          |

Throws `SomaError` with code `'config'` if any required field is missing.

## Error handling

All errors are instances of `SomaError`:

```ts
import { SomaClient, SomaError } from '@soma-vault/sdk';

try {
  await client.secret('db/password');
} catch (e) {
  if (e instanceof SomaError) {
    console.error(e.code);    // 'not_found' | 'unauthorized' | 'server' | 'network' | 'config'
    console.error(e.status);  // HTTP status, e.g. 404
    console.error(e.path);    // the path that was not found
  }
}
```

## License

Apache-2.0
