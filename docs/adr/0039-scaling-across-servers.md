# ADR 0039: Scaling Across Servers (Phase 1 — Manual Copies Over WireGuard)

- **Status:** Proposed (Phase 1 implementation in progress on `033-scaling`)
- **Date:** 2026-11-27
- **Feature:** `033-scaling` ([spec](../../specs/033-scaling/spec.md), [research](../../specs/033-scaling/research.md))

## Context

OpsCrew's split placement (ADR 0022, Feature `018`) places databases, caches, and brokers on extra servers linked by a per-app encrypted WireGuard mesh, and Feature `049` isolates each app behind its own `app-proxy` container. However, an app's web service and workers still run on only a single server (`app`), leaving users on Hetzner, Contabo, DigitalOcean, OVHcloud, Kamatera, or their own servers unable to scale web or worker capacity horizontally across multiple servers.

## Decisions

### D1. Phased delivery preserving Constitution I & IV
- **Phase 1 (this ADR)** ships manual horizontal copies of stateless web and worker services across any mix of supported cloud providers and the user's own servers. Every change is planned and approved by SHA-256 hash — zero changes to the constitution or approval model.
- **Phase 2 (future)** will add automatic scaling recipes and crash-loop auto-rollback only after a MINOR constitution amendment introduces standing approvals for bounded scaling recipes and live provider snapshot benchmarks settle cooldowns.

### D2. Plan representation extends Feature `018` placement
- Extra copy servers are normal entries in `plan.servers[]` (so they automatically get Terraform modules across any provider mix, WireGuard mesh membership, deploy keys, and host hardening).
- `app.servers?: ServerNameSchema[]` names the extra servers that run web copies alongside `app` (`webServers(plan) = ["app", ...app.servers]`).
- `processes.workers[].servers?: ServerNameSchema[]` names the extra servers that run worker copies (refused when `worker.single === true`).
- `processes.cron` always runs on `app` only so scheduled jobs never fire N times.
- `scaling.loadBalancer` defaults to `{ kind: "edge", policy: "round_robin" }` when `app.servers` is non-empty, leaving room for future additive `kind` values (provider managed LBs, Cloudflare LB) without breaking existing plans.

### D3. Universal `$0` front-server load balancing over WireGuard
- Each copy server runs `app` on its private `internal` Docker network and its own `app-proxy` (`049`) bound **exclusively** to that server's private WireGuard IP on port `18080` (`<wg_ip>:18080`), never on public ports 80/443.
- The front server's reverse proxy (Caddy, nginx, or OpenLiteSpeed) balances across the local `<app>-kamal-proxy:80` and every copy server's `<wg_ip>:18080` with active/passive health checks.
- Single-copy plans render byte-for-byte identical proxy configs to pre-`033`.
- When remote web/worker copies exist, backing services running on `app` are published on `app`'s private WireGuard IP so copy servers reach them over encrypted WireGuard without opening any public ports.

### D4. Hard stateless gates & connection pooling
- `plan.yaml` validation refuses `app.servers` when `storage.sqlite` or `storage.files` is set.
- `@opscrew/detect` deterministically detects local session stores and local disk uploads across Laravel/PHP, Express/Node.js, Django/Python, and Rails/Ruby (`ProjectFacts.statelessIssues`), which `design` surfaces before scaling out.
- `design` recommends/enables PgBouncer (`050`) for PostgreSQL when `webServers(plan).length > 1` so N copies do not exhaust `max_connections`, and warns when copy servers sit in another provider/region from the database.

### D5. Zero-downtime serial 1-by-1 rolling deploys
- Deploy workflows pull `$APP_IMAGE` on all web/worker servers first, run pre-release DB snapshot + `releaseCommand` **once** on `app`, then roll web copies one server at a time (`app` first, then each `app.servers[]` copy), verifying health before advancing and rolling back failed + already-updated copies on failure. Worker copies roll after web succeeds.

