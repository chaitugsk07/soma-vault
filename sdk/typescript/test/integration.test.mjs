/**
 * Integration test for @soma-vault/sdk.
 *
 * Gated on SOMA_SDK_TEST_URL — skipped (prints a message and exits cleanly)
 * when absent. Uses node:test (no framework deps). Imports from ../dist/index.js
 * (build first with `npm run build`).
 *
 * Creates its own project+env+secret with a unique code so parallel runs
 * don't conflict.
 */
import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { SomaClient, SomaError } from '../dist/index.js';

const BASE_URL = process.env['SOMA_SDK_TEST_URL'];
const TOKEN =
  process.env['SOMA_SDK_TEST_TOKEN'] ??
  '7c09b0744d303488a1042eecc43001448ad895c5e13c52fcc5d99371c7a855df';

if (!BASE_URL) {
  console.log('SOMA_SDK_TEST_URL not set — skipping integration tests.');
  process.exit(0);
}

/** Authenticated fetch helper for test setup. */
async function api(method, path, body) {
  const res = await fetch(`${BASE_URL}${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${TOKEN}`,
      'Content-Type': 'application/json',
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`${method} ${path} → ${res.status}: ${text}`);
  }
  return res.json();
}

/** Percent-encode a path segment (mirrors SDK's pctEncode). */
function pctEncode(s) {
  return Array.from(s)
    .map((ch) => {
      if (/[A-Za-z0-9\-_.~]/.test(ch)) return ch;
      return '%' + ch.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0');
    })
    .join('');
}

// Unique suffix to avoid conflicts across test runs.
const suffix = Date.now();
const projectCode = `ts-sdk-test-${suffix}`;
const secretPath = 'ts/sdk/secret';
const secretValue = 'hello-from-ts-sdk';

let projectId;
let environmentId;
let client;

describe('SomaClient integration', () => {
  before(async () => {
    // Create a fresh project for this run.
    const project = await api('POST', '/v1/projects', {
      code: projectCode,
      name: `TS SDK Test ${suffix}`,
    });
    projectId = project.id;

    // Create environment.
    const env = await api('POST', `/v1/projects/${projectId}/environments`, {
      code: 'test',
      name: 'Test',
    });
    environmentId = env.id;

    // Write test secret.
    await api(
      'PUT',
      `/v1/projects/${projectId}/environments/${environmentId}/secrets/${pctEncode(secretPath)}`,
      { value: secretValue },
    );

    // Build the SDK client pointing at our new project+env.
    client = new SomaClient({
      url: BASE_URL,
      token: TOKEN,
      project: projectId,
      environment: environmentId,
    });
  });

  it('secret() round-trips a value', async () => {
    const val = await client.secret(secretPath);
    assert.equal(val, secretValue);
  });

  it('loadAll() returns a map including our secret', async () => {
    const all = await client.loadAll();
    assert.equal(all[secretPath], secretValue);
  });

  it('secret() throws SomaError not_found for missing path', async () => {
    await assert.rejects(
      () => client.secret('no/such/path'),
      (err) => {
        assert.ok(err instanceof SomaError, 'should be SomaError');
        assert.equal(err.code, 'not_found');
        assert.equal(err.status, 404);
        assert.equal(err.path, 'no/such/path');
        return true;
      },
    );
  });

  it('bad token throws SomaError unauthorized', async () => {
    const badClient = new SomaClient({
      url: BASE_URL,
      token: 'bad-token',
      project: projectId,
      environment: environmentId,
    });
    await assert.rejects(
      () => badClient.secret(secretPath),
      (err) => {
        assert.ok(err instanceof SomaError, 'should be SomaError');
        assert.equal(err.code, 'unauthorized');
        assert.equal(err.status, 401);
        return true;
      },
    );
  });
});
