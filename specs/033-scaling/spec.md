# Feature Specification: Scaling Across Servers (Feature 033 — Phase 1: Manual Copies & Load Balancing)

**Feature Branch**: `033-scaling`  
**Created**: 2026-11-27  
**Status**: In Progress (Phase 1 — Manual copies across servers; Phase 2 automatic scaling & crash-loop auto-rollback wait on the MINOR constitution amendment for standing approvals)  
**Research**: [research.md](research.md) | **ADR**: [ADR 0039](../../docs/adr/0039-scaling-across-servers.md)

## Overview

Apps on Hetzner, Contabo, DigitalOcean, OVHcloud, Kamatera, or the user's own servers currently run a single copy of the web service (and workers on `app`). Feature `033` Phase 1 lets users run multiple copies of stateless web and worker processes across several servers — at one provider or across any mix of supported cloud providers and the user's own servers — connected over Feature `018`'s encrypted WireGuard private network, behind the front server's load-balancing reverse proxy, with zero-downtime serial rolling deploys and full rollback across all copies.

Every infrastructure and host change in Phase 1 goes through OpsCrew's existing plan-hash-bound approval model (no standing approvals or constitution changes in Phase 1).

## User Stories

### US1 — Stateless Readiness Gate Before Scaling Out (P1)
As a developer scaling an app to ≥2 servers, I want OpsCrew to detect local per-server state (SQLite, local file uploads, file/memory sessions) before adding copies, and explain plainly what to switch (PostgreSQL/MySQL, S3-compatible object storage, Valkey/DB/cookie sessions), so my users never hit random logouts or missing uploads.

**Acceptance criteria:**
- `plan.yaml` schema refuses web copies (`app.servers` non-empty) when `storage.sqlite` or `storage.files` is set.
- `@opscrew/detect` deterministically detects local session stores and local disk uploads across Laravel/PHP, Express/Node.js, Django/Python, and Rails/Ruby (recording `ProjectFacts.statelessIssues` without ever recording secret values).
- `opscrew design` blocks/warns with the concrete framework remediation when `statelessIssues` are present.
- `opscrew design` recommends (and enables when PostgreSQL is present) PgBouncer (`050`) when running ≥2 web/worker servers so N copies do not exhaust PostgreSQL's `max_connections`.

### US2 — Manual Web & Worker Copies Across Any Mix of Servers (P1)
As a developer, I want to declare extra servers in `opscrew/plan.yaml` (`servers[]`) at any mix of OpsCrew-supported cloud providers and my own servers, list them under `app.servers` (web copies) and/or `processes.workers[].servers` (worker copies), and let `design` + `provision` create, wire (WireGuard + firewall + deploy keys), and price them under normal plan-hash-bound approvals.

**Acceptance criteria:**
- `app.servers` lists additional server names from `servers[]` that run a copy of the web service alongside `app` (default `app` always runs copy 1; total web copies = `1 + app.servers.length`).
- `processes.workers[].servers` lists additional server names from `servers[]` that run copies of that worker; refused when `worker.single === true` (schedulers run once only).
- Cron jobs (`processes.cron`) always run on `app` only — never duplicated across copy servers.
- Databases, caches, and brokers stay on one server each (`018` split placement); when remote web/worker copies exist, any backing service running on `app` is published on `app`'s private WireGuard address so copy servers reach it over encrypted WireGuard.
- Cross-provider/cross-region distance between copy servers and the database server is flagged during `design` with a plain-English latency warning.
- Copy servers run `app` on their private `internal` Docker network and their own per-app `app-proxy` (`049`) published **only** on that server's private WireGuard IP (`<wg_ip>:18080`), never on public ports 80/443.

### US3 — Load Balancing Across Copies Over WireGuard (P1)
As a developer, I want the front server's reverse proxy (Caddy, nginx, or OpenLiteSpeed) to spread HTTP/WebSocket traffic across the local `app-proxy` and every copy server's WireGuard `app-proxy`, with active/passive health checks so an unhealthy copy stops receiving traffic automatically.

**Acceptance criteria:**
- Single-copy plans (`app.servers` empty/absent) render byte-for-byte identical proxy configs to before `033`.
- Multi-copy plans balance across `<app>-kamal-proxy:80` and each copy server's `<wg_ip>:18080`:
  - **Caddy:** `reverse_proxy <app>-kamal-proxy:80 <wg_ip_2>:18080 ...` with `lb_policy` (`round_robin` default, or `least_conn` / `ip_hash`), `health_uri`, `health_interval 5s`, `health_timeout 2s`, `fail_duration 30s`, `max_fails 2`.
  - **nginx:** per-app `upstream <app>-kamal-proxy` listing local `<app>-kamal-proxy:80 resolve` plus each `<wg_ip>:18080` with `max_fails=2 fail_timeout=30s` and optional `least_conn;` / `ip_hash;`.
  - **OpenLiteSpeed:** per-copy `extprocessor` entries behind a `loadbalancer` processor targeting all copies.
- Real Docker integration test verifies requests are balanced across ≥2 `app-proxy` backends and continue succeeding when one copy goes down.

### US4 — Zero-Downtime Serial Rolling Deploy & Rollback Across N Copies (P1)
As a developer, I want every deploy and rollback to roll across my web copies one server at a time (after pulling the image on all servers and running migrations once on `app`), aborting and rolling back already-updated copies if any copy fails its health check.

**Acceptance criteria:**
- Deploy workflow pulls `$APP_IMAGE` on all web/worker servers first (fail fast before changing traffic).
- Pre-release DB snapshot and `releaseCommand` (migrations) run **once** on `app` only.
- Web copies roll **serially one server at a time**: `app` switches first, then each server in `app.servers` switches its local `app-proxy` and passes health check before the next starts.
- On failure on copy `k`, copy `k` restores its previous route and previously-updated copies `1..k-1` roll back to the previous digest so all copies stay on one known-good release.
- Worker copies on extra servers roll after web succeeds; cron stays on `app` only.
- `opscrew rollback`, `opscrew status`, `opscrew drift`, `opscrew verify`, `opscrew rotate`, and `opscrew destroy` cover all copy servers cleanly.

## Out of Scope for Phase 1 (Deferred to Phase 2)
- Automatic scaling recipes & crash-loop auto-rollback (require MINOR constitution amendment for standing approvals, plus live provider snapshot boot benchmarks).
- Managed cloud load balancers (Hetzner LB11, DigitalOcean LB, OVHcloud Octavia, Cloudflare LB) — Phase 1 ships the universal `$0` front-server WireGuard load balancer that works identically across all providers and own servers; `scaling.loadBalancer.kind` is designed to add managed LBs additively later.
- Canary / percentage rollouts (`kamal-proxy rollout set --percent`).
- Self-hosted PostgreSQL streaming replicas / manual `pg_promote()`.

