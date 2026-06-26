# Security policy

## Reporting a vulnerability

Please do not open a public GitHub issue for security vulnerabilities. soma-vault handles secrets — a public proof-of-concept could expose users before a fix is available.

Email **gskchaitanya.gadde@gmail.com** with:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept (redact any real credentials or keys)
- The version of soma-vault where you observed the issue

You will receive a response within 72 hours acknowledging receipt. We aim to release a fix or provide a workaround within 14 days for confirmed vulnerabilities, depending on severity and complexity.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |

Older versions will be supported if a critical fix can be backported without breaking changes; otherwise users will be asked to upgrade.

## Scope

Reports are in scope for:

- Vulnerabilities in the envelope encryption implementation (`soma-crypto`)
- Authentication and authorization bypasses in the API
- Secrets leaking into logs, error messages, or HTTP responses
- Key material surviving longer in memory than the active request
- Migration runner behaviour that could corrupt or expose stored secrets

Out of scope: bugs in the Leptos dashboard that have no security impact, theoretical weaknesses in underlying cryptographic primitives (AES-GCM, AES-KW) rather than their use in this codebase.

## Cryptography note

In Phase 1, soma-vault uses a software KMS: the master key encryption key (KEK) is provided at startup via the `SOMA_MASTER_KEK_HEX` environment variable. Each secret is stored as an AES-GCM ciphertext alongside an AES-KW-wrapped per-secret DEK. A Postgres dump **without** the KEK value is useless — the ciphertexts cannot be decrypted. However, anyone who has both the database dump and the `SOMA_MASTER_KEK_HEX` value can decrypt all secrets. Treat that environment variable as carefully as you would treat the secrets themselves: use a secrets manager or sealed Kubernetes secret to inject it, and rotate it if you suspect it has been exposed.

Cloud-KMS auto-unseal — where the KEK is wrapped by AWS KMS / GCP KMS / Azure Key Vault and the pod authenticates via workload identity rather than a shared secret — is on the roadmap. That model removes the need for any persistent key material in an environment variable.
