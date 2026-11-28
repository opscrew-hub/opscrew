# Specification: Self-Hosted Gitea Provisioning & App Integration (Feature 043 Follow-Up)

**Feature:** `043-gitea-self-hosted` | **Issue:** `#70` | **Depends on:** Feature `043-forgejo-gitea` (merged on `042-git-platforms`)

## Overview

Enable OpsCrew to provision and operate a hardened, self-hosted Gitea instance on a user's server (cloud VPS or own server) under OpsCrew's mandatory `plan -> policy checks -> SHA-256 plan-hash approval -> apply` safety gate, include Gitea in OpsCrew's snapshots and restore drills, and provide a first-class, secret-safe app integration contract (API base URL, scoped API token, and webhook signing secret) so an app that displays repositories, pull requests, and activity can plug Gitea in the same way as GitHub.

## User Stories

### US1 — Declare Self-Hosted Gitea in `opscrew/plan.yaml`
- Additive optional top-level `gitea` block in `DeployPlanSchema` (`packages/plan-schema`):
  - `enabled` (boolean, default `false`)
  - `version` (pinned semantic version, e.g. `"28.4.0"`)
  - `hostname` (FQDN served behind the server's reverse proxy, e.g. `git.example.com`)
  - `database`: `"sqlite"` (default) or `"postgres"` (dedicated Postgres container)
  - `adminUser` (default `"gitea-admin"`), `adminEmail`
  - `disableRegistration` (boolean, default `true`)
  - `ssh`: `{ enabled: false, port: 2222 }` (SSH disabled by default; port `22`/`80`/`443` refused)
  - `appIntegration`: `{ enabled: true, tokenScopes: ["read:repository", "read:issue", "read:organization", "read:user"], webhook?: { path?, allowedHosts? } }`
  - `memoryMb`: `{ gitea: 512, postgres: 256 }`
- Refused on non-server targets (serverless, hosting, Portainer, localhost) and preview environments.
- Validates hostname uniqueness against the app domain, `www.` alias, Portainer, and Beszel hostnames, plus Cloudflare Universal SSL edge coverage when proxied.

### US2 — Render Hardened Gitea Compose & Reverse Proxy Site (Caddy / nginx / OpenLiteSpeed)
- Pinned rootless image `gitea/gitea:28.4.0-rootless@sha256:15ab7fadb44981a2b781f40c712cad07066197f395100ea1c6326e14e5bb073a` in `IMAGES.gitea`.
- `compose.yaml` (`opscrew-gitea` project):
  - `GITEA__security__INSTALL_LOCK=true`, `GITEA__service__DISABLE_REGISTRATION=true` (by default), `GITEA__server__ROOT_URL=https://<hostname>/`, `GITEA__webhook__SKIP_TLS_VERIFY=false`, restricted `GITEA__webhook__ALLOWED_HOST_LIST` (never `*`).
  - Zero plaintext secrets in `compose.yaml` (all secrets loaded via `0600` `gitea.env` and optional `postgres.env`).
  - HTTP port `3000` is never published to `0.0.0.0`; Gitea joins `opscrew-edge` under alias `opscrew-gitea` and is served exclusively behind the reverse proxy.
  - Supports both SQLite (single container) and dedicated PostgreSQL 17 (`gitea-db` on isolated `gitea-internal` network).
  - Container hardening: rootless UID 1000, `no-new-privileges:true`, `cap_drop: ["ALL"]`, `mem_limit` / `memswap_limit`, `json-file` log rotation, `/api/healthz` healthcheck.
- Reverse proxy site rendering for **Caddy**, **nginx**, and **OpenLiteSpeed** (`/srv/edge/sites/opscrew-gitea.<ext>`), enforcing HTTPS, HSTS, baseline security headers, WebSockets, and large Git push payloads.

### US3 — SecOps Policy Checks & Hash-Approved Provisioning / Teardown
- Deterministic SecOps evaluator `evaluateGiteaPolicies(plan, rendered)` blocks provisioning on any critical/high failure:
  - `gitea-install-lock` (critical)
  - `gitea-registration-disabled` (high)
  - `gitea-image-pinned` (high)
  - `gitea-no-public-http-port` (critical)
  - `gitea-no-plaintext-secrets` (critical)
  - `gitea-webhook-host-restricted` (high)
  - `gitea-ssh-port-safe` (high)
  - `gitea-proxy-hardened` (high)
- Every server mutation goes through a SHA-256 hash-bound `HostPlan` (`planGitea`) applied via `@opscrew/connector-ssh-host` (`applyHostPlan`):
  - Shared-server ownership is enforced via a `0600` `$DIR/.owner` marker on the host (checked in both `check` and `apply`) plus ADR 0035 `shares` guards in `@opscrew/agents`.
  - Secrets (`adminPassword`, `botPassword`, `secretKey`, `internalToken`, `jwtSecret`, `lfsJwtSecret`, `postgresPassword`, `appApiToken`, `webhookSecret`) are stored locally with mode `0600` in `gitea_secrets.json` (included in `opscrew secrets backup`/`restore`), registered with the redactor, and delivered strictly over stdin (`ApplySecrets`) — never in plan JSON, logs, audit entries, or stdout.
  - Disabling keeps data volumes by default (`--keep-data` / `keepData: true`); deleting Gitea data volumes requires an explicit `allowDestroy` approval with typed confirmation of the resource name (`gitea.hostname` / `opscrew-gitea`), and `verify` checks that the Docker volumes are gone.

### US4 — App Integration (Scoped API Token & Webhooks)
- Idempotent host bootstrap creates the admin user (`gitea.adminUser`) and a dedicated non-admin bot user (`opscrew-bot`) via stdin-only password delivery (never `docker compose exec --env-file`), generates a least-privilege scoped API token (`opscrew-app`, with clean re-enable fallback over kept volumes), writes `0600` `.bootstrapped` only after every step succeeds, and captures the token into local `0600` `gitea_secrets.json`.
- Deterministic app connection helper (`giteaAppIntegration`) exposes secret-free integration metadata:
  - Environment variables: `GITEA_URL`, `GITEA_API_URL`, `GITEA_API_TOKEN`, `GITEA_WEBHOOK_SECRET` (OpsCrew saves the secret values locally in `gitea_secrets.json` and prints exact wiring instructions via `opscrew values set` / `.env` and manual webhook registration rather than auto-injecting into the running app container)
  - REST v1 endpoints for repositories, pull requests, issues, commits, and activity feeds
  - Webhook payload, events, and `X-Gitea-Signature` HMAC-SHA256 verification details (raw lowercase hex, no `sha256=` prefix).
- Exposed through CLI (`opscrew addon enable|disable|status gitea`) and MCP (`opscrew_addon_enable|disable|status` with `addon: "gitea"`, keeping MCP `TOOL_COUNT = 43` and under budget).

### US5 — Snapshots, Restore Drills & User Documentation
- `snapshotParts(plan, server)` includes Gitea (`gitea.tar` for data/config volumes, plus stop-only `gitea-db.dump` when `database: "postgres"`).
- `snapshot.sh` stops Gitea cleanly for consistent volume and Postgres dumps/restores, and restore drills (`opscrew restore --drill`) boot throwaway pinned Gitea (and Postgres on an `--internal` network) containers with zero external network access and probe `/api/healthz`.
- `docs/guide/gitea.md` (and `docs/guide/gitea-self-hosted.md` linked from `docs/guide/gitea.md` and `docs/guide/index.md`) documents self-hosted Gitea provisioning, hardening, snapshots/restore drills, and step-by-step app integration (API token scopes, REST v1 endpoints vs GitHub, webhook setup, and `X-Gitea-Signature` HMAC verification).

## Non-Goals / Constraints
- No live server provisioning in automated unit tests; all tests use injected `FakeHost`, fake `RemoteExec`, and deterministic fixtures.
- No secret-shaped literals anywhere in source, docs, or tests (use `fakeSecret()` from `@opscrew/core/testing`).
- No new external npm dependencies.
- Keep `packages/mcp-server` within `TOOL_COUNT = 43` and `TOOL_LIST_BUDGET = 40_000`.
