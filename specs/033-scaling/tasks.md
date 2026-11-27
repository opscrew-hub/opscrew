# Tasks: Feature 033 — Scaling Across Servers (Phase 1: Manual Copies & Load Balancing)

**Feature:** `033-scaling` | **Spec:** [spec.md](spec.md) | **Plan:** [plan.md](plan.md) | **ADR:** [ADR 0039](../../docs/adr/0039-scaling-across-servers.md)

## Wave 0 — Spec, Plan & ADR (Lead)

- [x] **T3300 (lead):** Author `specs/033-scaling/spec.md`, `plan.md`, `tasks.md`, and `docs/adr/0039-scaling-across-servers.md`.

## Wave 1 — Plan Schema & Facts Contract (`@opscrew/plan-schema`, Lead)

- [x] **T3301 (lead):** Add `ProjectFactsSchema.statelessIssues` (`local-sessions`, `local-uploads`) in `packages/plan-schema/src/facts.ts` and regenerate `schemas/architecture.schema.json`.
- [x] **T3302 (lead):** Add `app.servers`, `processes.workers[].servers`, and `scaling.loadBalancer` (`kind: "edge"`, `policy: "round_robin" | "least_conn" | "ip_hash"`) to `packages/plan-schema/src/plan.ts` & `components.ts`; export `webServers`, `workerServers`, `appCopyServers`, `hasRemoteAppCopies`; regenerate `schemas/plan.schema.json`.
- [x] **T3303 (lead):** Extend `checkPlacement` in `packages/plan-schema/src/placement.ts` for copy-server validation (server existence, monitoring-server exclusion, occupied check, WireGuard network required, hard-block `storage.sqlite` & `storage.files`, block `worker.single` copies, block non-VPS & preview targets) with comprehensive unit tests.

## Wave 1b — Stateless Readiness Detection (`@opscrew/detect`, Contributor Slice A)

- [x] **T3304 (contributor — Slice A):** Implement deterministic `detectStatelessIssues` in `packages/detect/src/stateless.ts` (Laravel/PHP, Express/Node.js, Django/Python, Rails/Ruby per `research.md` R3), wire into `detectProject` → `ProjectFacts.statelessIssues`, and add fixture-backed unit tests covering both unsafe local defaults and safe Redis/DB/cookie/S3 configurations.

## Wave 2 — Runtime, Load Balancing & Serial Rolling Deploy (`@opscrew/iac-templates`, Lead)

- [x] **T3305 (lead):** Update `publishedAddress` (`runtime/network.ts`) and copy-server `renderServerCompose` (`runtime/index.ts`, `runtime/components.ts`) so backing services on `app` publish on `app`'s WireGuard IP when `hasRemoteAppCopies(plan)` is true, and copy servers run `app` (on `internal`) + `app-proxy` (bound only to `<wg_ip>:18090`) + placed workers (never `release` or `cron`).
- [x] **T3306 (lead):** Add multi-upstream load balancing to Caddy (`edge/index.ts`, `runtime/services.ts`), nginx (`edge/nginx.ts`), and OpenLiteSpeed (`edge/openlitespeed.ts`) over local `<app>-kamal-proxy:80` + copy servers' `<wg_ip>:18090` with active/passive health checks and `lb_policy`, keeping single-copy output byte-for-byte identical.
- [x] **T3307 (lead):** Implement serial 1-by-1 rolling deploy across web copies + worker copy servers in `workflow/jobs.ts` & `workflow/switch.ts` (pull on all servers first, pre-release snapshot + migrations once on `app`, roll `app` then each `app.servers[]` copy serially with health verification, roll back failed + already-updated copies on failure, then roll worker copies).
- [x] **T3308 (lead):** Extend `workflow/rollback.ts` and `workflow/rotate.ts` to roll back and rotate secrets across all web/worker copy servers cleanly.
- [x] **T3309 (lead):** Add real Docker integration test (`packages/iac-templates/src/edge/scaling.docker.test.ts`, `OPSCREW_DOCKER_TESTS=1`) verifying load balancing across 2 `app-proxy` backends and automatic failover when one copy stops.

## Wave 3 — Design, Provision, Operations & Guide (`@opscrew/agents`, `packages/cli`, `packages/mcp-server`, `docs/guide/`)

- [x] **T3310 (contributor — Slice B):** Implement `design` & `advise` scaling readiness in `packages/agents/src/design/` and `packages/agents/src/advise/` (stateless readiness gate surfacing `statelessIssues` + SQLite/local-files, PgBouncer recommendation/enablement for PostgreSQL when `webServers > 1`, copy-server memory sizing across mixed providers + own servers, and cross-provider/region DB latency warning) with unit tests.
- [x] **T3311 (lead):** Wire `provision` (`packages/agents/src/provision/`) for copy servers: upload `app.env` (with private WG service addresses), `worker-db.env`, and `compose.yaml` to each copy server, configure deploy secrets/host keys, and update `generated_values` & host plans cleanly.
- [x] **T3312 (lead):** Wire `status`, `drift`, `verify`, `rollback`, `rotate`, and `destroy` (`packages/agents/src/`) to inspect, verify, roll back, rotate, and tear down web/worker copy servers cleanly (including verifying copy-server `app-proxy` health and reporting per-server copy status).
- [x] **T3313 (lead):** Add `docs/guide/scaling.md` and link it from `docs/guide/index.md`; verify CLI & MCP tools expose multi-copy status/plans cleanly.
- [x] **T3314 (lead):** Opus 5.5 full-feature review over `033-scaling`, full-repo gate (`gate exit 0`), and real Docker verification.
