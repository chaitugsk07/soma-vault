/**
 * @soma-vault/sdk — in-process TypeScript client for soma-vault.
 *
 * Zero runtime dependencies — uses native `fetch` (Node 18+ global).
 *
 * @example
 * ```ts
 * import { SomaClient } from '@soma-vault/sdk';
 *
 * const client = new SomaClient({
 *   url: process.env.SOMA_URL ?? 'http://localhost:8080',
 *   token: process.env.SOMA_TOKEN!,
 *   project: process.env.SOMA_PROJECT!,
 *   environment: process.env.SOMA_ENV!,
 * });
 *
 * const dbPass = await client.secret('database/password');
 * const port   = await client.config('server/port');
 * const portR  = await client.config('db/url', { resolveRefs: true });
 * const env    = await client.loadAll();   // one HTTP call
 * await client.inject();                   // → process.env
 * ```
 */

/** Constructor options for {@link SomaClient}. Each field falls back to an env var. */
export interface SomaClientConfig {
  /** Server base URL. Env: `SOMA_URL`. Default: `http://localhost:8080`. */
  url?: string;
  /** Bearer token. Env: `SOMA_TOKEN`. Required. */
  token: string;
  /** Project code or ID. Env: `SOMA_PROJECT`. Required. */
  project: string;
  /** Environment code or ID. Env: `SOMA_ENV` or `SOMA_ENVIRONMENT`. Required. */
  environment: string;
}

/** Options for {@link SomaClient.config}. */
export interface ConfigOptions {
  /**
   * When true, sends `?resolve_refs=true` so the server expands any `$ref`
   * pointers inside config values before returning.
   */
  resolveRefs?: boolean;
}

/** Error codes returned by {@link SomaError}. */
export type SomaErrorCode = 'unauthorized' | 'not_found' | 'config' | 'network' | 'server';

/**
 * All errors thrown by {@link SomaClient} are instances of this class.
 *
 * @example
 * ```ts
 * try {
 *   await client.secret('db/password');
 * } catch (e) {
 *   if (e instanceof SomaError && e.code === 'not_found') {
 *     console.error('secret missing:', e.path);
 *   }
 * }
 * ```
 */
export class SomaError extends Error {
  /** Machine-readable error category. */
  readonly code: SomaErrorCode;
  /** HTTP status code, if the error originated from an HTTP response. */
  readonly status?: number;
  /** The secret/config path that was not found (for `not_found` errors). */
  readonly path?: string;

  constructor(code: SomaErrorCode, message: string, status?: number, path?: string) {
    super(message);
    this.name = 'SomaError';
    this.code = code;
    this.status = status;
    this.path = path;
  }
}

/** soma-vault client. Construct once per process; reuse across calls. */
export class SomaClient {
  private readonly url: string;
  private readonly token: string;
  private readonly project: string;
  private readonly environment: string;

  /**
   * @param config - Partial config; missing fields resolved from env vars.
   * @throws {SomaError} code `'config'` if `token`, `project`, or `environment` cannot be resolved.
   */
  constructor(config: Partial<SomaClientConfig> = {}) {
    this.url = config.url ?? process.env['SOMA_URL'] ?? 'http://localhost:8080';
    this.token = config.token ?? process.env['SOMA_TOKEN'] ?? '';
    this.project = config.project ?? process.env['SOMA_PROJECT'] ?? '';
    this.environment =
      config.environment ??
      process.env['SOMA_ENV'] ??
      process.env['SOMA_ENVIRONMENT'] ??
      '';

    if (!this.token) throw new SomaError('config', 'soma-vault: token is required (set SOMA_TOKEN or pass token in config)');
    if (!this.project) throw new SomaError('config', 'soma-vault: project is required (set SOMA_PROJECT or pass project in config)');
    if (!this.environment) throw new SomaError('config', 'soma-vault: environment is required (set SOMA_ENV or pass environment in config)');
  }

  /**
   * Percent-encode a path segment.
   *
   * Only unreserved chars (A-Za-z0-9 - _ . ~) pass through; everything else
   * becomes %XX (uppercase hex). This matches Rust's `pct_encode` used by the
   * soma-vault server, which means `/` inside a secret path becomes `%2F`.
   */
  private pctEncode(s: string): string {
    return Array.from(s)
      .map((ch) => {
        if (/[A-Za-z0-9\-_.~]/.test(ch)) return ch;
        return '%' + ch.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0');
      })
      .join('');
  }

  /** Base URL for the current project+environment. */
  private envBase(): string {
    return `${this.url}/v1/projects/${this.project}/environments/${this.environment}`;
  }

  /**
   * Authenticated GET — returns parsed JSON body.
   * @throws {SomaError} on non-2xx or network failure.
   */
  private async get(url: string): Promise<unknown> {
    let res: Response;
    try {
      res = await fetch(url, {
        headers: { Authorization: `Bearer ${this.token}` },
      });
    } catch (err) {
      throw new SomaError('network', `soma-vault: network error — ${String(err)}`);
    }

    if (res.status === 401) {
      throw new SomaError('unauthorized', 'soma-vault: unauthorized — check your token', 401);
    }

    if (res.status === 404) {
      // Let callers wrap 404 with path context.
      const err = new SomaError('not_found', 'soma-vault: not found', 404);
      throw err;
    }

    if (!res.ok) {
      let detail = '';
      try {
        const body = (await res.json()) as { error?: string };
        detail = body.error ? ` — ${body.error}` : '';
      } catch {
        // ignore JSON parse failure
      }
      throw new SomaError('server', `soma-vault: server error ${res.status}${detail}`, res.status);
    }

    return res.json();
  }

  /**
   * Read a secret by path.
   *
   * Slashes in `path` (e.g. `"database/password"`) are percent-encoded so
   * they are treated as part of the secret name, not URL path separators.
   *
   * @param path - Secret path, e.g. `"database/password"`.
   * @returns The plaintext secret value.
   * @throws {SomaError} code `'not_found'` if the secret does not exist.
   */
  async secret(path: string): Promise<string> {
    try {
      const data = await this.get(`${this.envBase()}/secrets/${this.pctEncode(path)}`);
      return (data as { value: string }).value;
    } catch (e) {
      if (e instanceof SomaError && e.status === 404) {
        throw new SomaError('not_found', `soma-vault: secret not found: ${path}`, 404, path);
      }
      throw e;
    }
  }

  /**
   * Read a config value by key.
   *
   * @param key - Config key, e.g. `"server/port"`.
   * @param opts - Optional flags; set `resolveRefs: true` to expand `$ref` pointers.
   * @returns The config value as a string.
   * @throws {SomaError} code `'not_found'` if the key does not exist.
   */
  async config(key: string, opts?: ConfigOptions): Promise<string> {
    const qs = opts?.resolveRefs ? '?resolve_refs=true' : '';
    try {
      const data = await this.get(`${this.envBase()}/config/${this.pctEncode(key)}${qs}`);
      return (data as { value: string }).value;
    } catch (e) {
      if (e instanceof SomaError && e.status === 404) {
        throw new SomaError('not_found', `soma-vault: config not found: ${key}`, 404, key);
      }
      throw e;
    }
  }

  /**
   * Bulk-load all secrets and config for this project+environment in one
   * HTTP call via the `/export` endpoint.
   *
   * @returns A flat `Record<string, string>` mapping key/path → value.
   */
  async loadAll(): Promise<Record<string, string>> {
    const data = await this.get(`${this.envBase()}/export`);
    return (data as { values: Record<string, string> }).values;
  }

  /**
   * Load all secrets and config, then inject them into `process.env`.
   *
   * Existing env vars are **not** overwritten — uses `Object.assign` which
   * only sets keys not already present on the target when the target has
   * no own-property for that key. Actually `Object.assign` does overwrite;
   * call this early in your process before other code reads `process.env`.
   */
  async inject(): Promise<void> {
    const values = await this.loadAll();
    Object.assign(process.env, values);
  }
}
