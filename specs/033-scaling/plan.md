# Implementation Plan: Scaling Across Servers (Feature 033 — Phase 1)

**Branch**: `033-scaling` | **Spec**: [spec.md](spec.md) | **ADR**: [ADR 0039](../../docs/adr/0039-scaling-across-servers.md)

## Architecture Summary

Feature `033` Phase 1 builds directly on Feature `018` (split placement + WireGuard private mesh) and Feature `049` (per-app `app-proxy` isolation):

1. **Plan Schema (`@opscrew/plan-schema`):**
   - `ProjectFactsSchema.statelessIssues` — deterministic local-session / local-upload findings from `@opscrew/detect`.
   - `DeployPlanSchema.app.servers?: ServerNameSchema[]` — unique extra servers from `servers[]` running web copies beside `app`.
   - `ProcessesSchema.workers[].servers?: ServerNameSchema[]` — unique extra servers from `servers[]` running worker copies (refused when `single: true`).
   - `DeployPlanSchema.scaling?: { loadBalancer?: { kind: "edge"; policy: "round_robin" | "least_conn" | "ip_hash" } }`.
   - Helpers: `webServers(plan)`, `workerServers(plan, worker)`, `appCopyServers(plan)`, `hasRemoteAppCopies(plan)`.
   - `checkPlacement` rules:
     - Extra servers running web/worker copies count as occupied (do not trigger "runs no enabled service") and cannot be the monitoring server.
     - `app.servers` non-empty requires `network`, refuses `storage.sqlite` and `storage.files`, refuses previews and non-VPS targets.
2. **Stateless Detection (`@opscrew/detect` — contributor Slice A):**
   - `packages/detect/src/stateless.ts` implementing R3's deterministic detectors for Laravel/PHP, Express/Node.js, Django/Python, and Rails/Ruby.
   - Wired into `detectProject` → `ProjectFacts.statelessIssues`.
3. **Runtime, Proxy Load Balancing & Rolling Deploy (`@opscrew/iac-templates`):**
   - **Private copy upstream port:** `APP_COPY_PROXY_PORT = 18080` bound exclusively on `<peer_wg_ip>:18080` inside `renderServerCompose(plan, server)` (never `0.0.0.0`).
   - **Service reachability:** `publishedAddress(plan, service)` publishes `APP_SERVER`-hosted backing services (DB, PgBouncer, Valkey/Redis, brokers, etc.) on `APP_SERVER`'s private WireGuard IP whenever `hasRemoteAppCopies(plan)` is true, and copy servers' `app.env` receives private WireGuard hostnames/IPs for every backing service.
   - **Copy-server Compose (`renderServerCompose`):** renders `app` (on `internal` only) + `app-proxy` (bridging `internal`, bound to `${wgIp}:${APP_COPY_PROXY_PORT}:80`) + any workers placed on `server`, and never renders `release` or `cron`.
   - **Front-proxy load balancing (`edge/index.ts`, `edge/nginx.ts`, `edge/openlitespeed.ts`):**
     - Byte-for-byte unchanged when `app.servers` is empty.
     - When `app.servers` is non-empty, balances across local `<app>-kamal-proxy:80` and every copy's `<wg_ip>:18080` with health checks and circuit breaking (`Caddy`, `nginx`, `OpenLiteSpeed`).
   - **Serial 1-by-1 Rolling Deploy & Rollback (`workflow/jobs.ts`, `workflow/switch.ts`, `workflow/rollback.ts`):**
     - Pull image on all web/worker servers first; run snapshot + `releaseCommand` once on `app`; roll `app` then each `app.servers[]` copy serially (switching its local `app-proxy` and verifying health before continuing, rolling back already-updated copies on failure); roll worker-only servers after web succeeds.
4. **Orchestration, Design, Provision, Operations & Docs (`@opscrew/agents`, `packages/cli`, `packages/mcp-server`, `docs/guide/scaling.md`):**
   - **Design & Advise (contributor Slice B after Wave 1 schema lands):** stateless readiness gate (`statelessIssues` + SQLite/local-files), PgBouncer auto-recommendation for PostgreSQL when `webServers(plan).length > 1`, pricing of copy servers across mixed providers + own servers, cross-provider/region DB latency warning, and `advise` scale-out guidance.
   - **Provision, Status, Drift, Verify, Rollback, Rotate, Destroy (Lead):**
     - `provision` uploads `app.env` (with private WG service addresses), `worker-db.env` (if PgBouncer), and `compose.yaml` to copy servers; configures WireGuard peers & firewall (allowing `APP_SERVER` → copy server TCP `18080` over `wg-opscrew*` only, which WireGuard's existing `iifname wg-opscrew*` rule already permits!); sets copy-server SSH secrets for GitHub Actions.
     - `status`, `drift`, `verify`, `rollback`, `rotate`, `destroy` report and operate across all web/worker copy servers cleanly.
   - **User guide:** `docs/guide/scaling.md` linked from `docs/guide/index.md`.

## Work Split (Proportional: Lead Larger Core Share + Contributor Slices)

- **Lead (Core Architecture, Schema, Runtime/LB/Deploy, Provision/Ops):**
  - Spec, Plan, Tasks, ADR 0039 (`T3300`)
  - Wave 1: `@opscrew/plan-schema` scaling schema, invariants, helpers, JSON schemas (`T3301–T3303`)
  - Wave 2: `@opscrew/iac-templates` copy-server runtime, WireGuard service publishing, Caddy/nginx/OpenLiteSpeed multi-upstream LB, serial rolling deploy & rollback, Docker integration test (`T3305–T3309`)
  - Wave 3: `@opscrew/agents` provision/status/drift/verify/rollback/rotate/destroy wiring + CLI/MCP + `docs/guide/scaling.md` (`T3311–T3314`)
- **Contributor (`Windwalker4u` — clean parallel zero-conflict slices on `033-scaling`):**
  - **Slice A (`T3304`):** `@opscrew/detect` stateless readiness detection (`packages/detect/src/stateless.ts` + tests) — starts immediately after Wave 1 pushes!
  - **Slice B (`T3310`):** `@opscrew/agents` `design` & `advise` scaling checks (stateless gate, PgBouncer recommendation, copy-server memory sizing & cross-provider/region DB latency warning + unit tests) — starts right after Slice A merges into `033-scaling`!

