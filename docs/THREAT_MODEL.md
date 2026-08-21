# Threat model

## Protected assets

Accounts and tokens, authorization records, network metadata, findings, reports,
audit history and availability of both the assessor and assessed laboratory.

## Trust boundaries and threats

- Browser to API: token theft, XSS, CSRF and unsafe CORS.
- API to database: unauthorized cross-project access and injection.
- Scan worker to target: scope bypass, DNS rebinding and resource exhaustion.
- File import: decompression bombs, malformed captures, payload retention and paths.
- Reports and logs: secret leakage, formula injection and audit tampering.

## Mitigations

Short-lived JWT access tokens, rotated refresh token types, Argon2 password hashes,
role and project checks, SQLAlchemy parameters, strict target normalization, DNS
result revalidation, host/port/concurrency/time ceilings, limited uploads, metadata-
only parsing, CSV neutralization, append-only audit API, secure headers, structured
logs and non-root containers. Production deployments should add TLS, a secret
manager, database backups, malware scanning for uploads and centralized monitoring.

## Residual risk

TCP connects can affect fragile devices; banners and version matching can be wrong;
an administrator can still intentionally broaden an allowlist; and compromised host
credentials inherit that host's visibility. Human authorization and validation remain
mandatory.

