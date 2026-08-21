# NetSecure Assess architecture

## System shape

```text
React + TypeScript SPA
  |  REST/JWT + scan progress polling
FastAPI application
  |-- authentication and RBAC
  |-- projects, assets, findings and audit APIs
  |-- bounded async TCP-connect scanner
  |-- traffic metadata importer and constrained rules
  |-- assessment, risk and reporting services
SQLAlchemy repository
  |-- SQLite for local development
  `-- PostgreSQL-compatible production schema
```

The API is intentionally a modular monolith: routes validate transport data, services
own security and scoring rules, and ORM models provide persistence. This keeps the
educational codebase approachable while leaving clear seams for a dedicated worker,
object storage, or external vulnerability provider.

## Directory structure

```text
backend/app/       FastAPI application, domain models, schemas and services
backend/tests/     unit, API, permission and safety tests
frontend/src/      React pages, reusable components and API client
docs/              architecture, schema, threat model and ethical-use policy
nginx/             optional reverse proxy configuration
docker-compose.yml local multi-container deployment
```

## Database design

`User` owns projects and activity. `Project` is the authorization boundary and has
members, authorization records, assets, scans, findings, alerts and assessments.
Assets contain discovered services. Findings may reference vulnerabilities and
remediation tasks. Traffic imports contain metadata-only records. Detection rules
produce alerts. Templates contain assessment controls; responses belong to an
assessment. Reports store generated snapshots, while audit logs are append-only.

Every mutable business record has timestamps. User-facing domain records support a
soft-deletion marker where removal is appropriate. Project and owner indexes support
the common dashboard queries.

## API endpoint plan

- `/api/auth`: register, login, refresh and profile
- `/api/projects`: CRUD, membership and project snapshots
- `/api/assets`: inventory and asset detail
- `/api/scans`: target validation, create, progress, cancel and comparison
- `/api/findings`: filtered lists and workflow updates
- `/api/traffic`: safe metadata imports and aggregates
- `/api/alerts`: defensive detections and analyst workflow
- `/api/rules`: constrained JSON detection rules
- `/api/assessments`: templates, responses, transparent scoring
- `/api/reports`: executive/technical JSON and CSV exports
- `/api/admin`: users and safety settings
- `/api/audit-logs`: immutable security-event list

FastAPI publishes complete OpenAPI documentation at `/docs` and `/openapi.json`.

## Safety controls

Targets are normalized with Python's `ipaddress` module. The default policy only
accepts localhost, RFC1918 IPv4 networks, and administrator allowlists. CIDRs are
bounded to 64 hosts, selected ports to 256, concurrent sockets to 16, banners to a
small byte count, and every scan to a hard deadline. Redirects do not expand scope.
Scans are TCP connect checks only: there is no raw-packet stealth, evasion,
credential attack, exploitation, persistence, denial-of-service or payload capture.
Every scan requires a stored declaration, purpose, approved scope and policy
acceptance. Cancellation is immediate at task boundaries and all lifecycle events
are audited. Live capture is disabled by default.

## Phased implementation

1. Foundation: authentication, RBAC, database, dashboard shell and projects.
2. Inventory: bounded target validation, demo/authorized scans, services/findings.
3. Monitoring: metadata import, defensive rules, alerts and visual analytics.
4. Governance: assessments, transparent risk, remediation and reports.
5. Assurance: tests, hardened containers, deployment docs and demo seed data.

