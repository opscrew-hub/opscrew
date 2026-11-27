# Scaling across servers: web and worker copies

By default, your app runs one web process (and any workers) on one server. That stays simple and
inexpensive while one server holds your traffic. When your app needs more web capacity, more
background worker throughput, or redundancy across machines, OpsCrew can run copies of your web
process and workers across several servers — at one cloud provider, across a mix of providers, or
alongside servers you already own.

The servers join an encrypted [WireGuard private network](private-network.md). The front server's
[reverse proxy](reverse-proxy.md) load-balances requests across every web copy at **no extra load
balancer cost**, and every deploy rolls across copies one server at a time without downtime.

This works on servers OpsCrew creates on [Hetzner Cloud](hetzner.md), [DigitalOcean](digitalocean.md),
[Contabo](contabo.md) or [OVHcloud](ovhcloud.md) (mixed freely), and on
[servers you already have](own-server.md) reached at a public address. It does not apply to a
[Portainer](portainer-target.md), [your computer](localhost.md), [previews](previews.md), a
[hosting account](hosting-accounts.md), [Cloudflare's hosting](cloudflare-hosting.md) or
[GitHub Pages](github-pages.md): design refuses it there and says why.

## Before you add a second web server: stateless readiness

When two or more servers handle web requests, a visitor's next request can land on a different
server than their first. Anything stored only on one server's disk — a SQLite file, uploaded files,
or file/in-memory sessions — breaks across copies.

OpsCrew checks this before you scale out:

- **Hard blocks in `opscrew/plan.yaml`:** `npx opscrew design` refuses `app.servers` when your plan
  uses local [SQLite](databases.md#sqlite) (`storage.sqlite`) or a local kept folder
  (`storage.files`). Move your database to PostgreSQL or another networked database, and move
  uploaded files to [S3-compatible object storage](object-storage.md) first.
- **Framework session and upload checks:** `npx opscrew analyze` deterministically inspects common
  frameworks (Laravel/PHP, Express/Node.js, Django/Python and Rails/Ruby) for local session drivers
  (such as `SESSION_DRIVER=file` or Express's default in-memory `MemoryStore`) and local disk
  uploads (such as `multer.diskStorage`, Django's default `FileSystemStorage` or Rails Active
  Storage `:local`). When you add `app.servers`, `npx opscrew design` prints a warning for each
  finding with the file and the concrete fix (for example switching sessions to Valkey/Redis, a
  database or signed cookies, and uploads to object storage).

## Add web and worker copies

Declare the extra servers under `servers` in `opscrew/plan.yaml`, list the ones that should run
copies of the web process under `app.servers`, and (optionally) list extra servers on any worker
under `processes.workers[].servers`:

```yaml
app:
  name: shop
  port: 3000
  healthPath: /api/health
  servers: [web2]

processes:
  workers:
    - name: jobs
      command: node worker.js
      count: 1
      memoryMb: 512
      enabled: true
      servers: [web2, w2]

servers:
  - name: web2
  - name: w2
    target: { provider: digitalocean, location: fra1 }

scaling:
  loadBalancer:
    kind: edge
    policy: least_conn
```

- **The front server (`app`) always runs copy 1.** Listing `app.servers: [web2]` gives you 2 web
  copies (`app` and `web2`); listing `[web2, web3]` gives you 3.
- **Leave `location` and `serverType` out** on a cloud server and `npx opscrew design` fills them
  in: the app server's provider and location (the lowest-latency hop), and the smallest server size
  whose memory holds every copy placed on it (`app.memoryMb` plus `app-proxy`'s 32 MB for a web
  copy, `worker.memoryMb * worker.count` for each enabled worker copy, any co-located services or
  monitoring, and the system's 384 MB reserve).
- **Mix cloud providers and your own servers freely.** Set `target: { provider: digitalocean,
  location: fra1 }` (or `hetzner`, `contabo`, `ovhcloud`) for another cloud provider, or
  `target: { provider: own, mode: vps-compose, arch: amd64 }` for a server you already own. Design
  asks for an own server's address and SSH login once and keeps them only on your computer.
- **Single-instance workers and cron jobs stay on `app`.** Workers marked `single: true` (such as
  schedulers) cannot set `servers`, and cron jobs (`processes.cron`) always run on `app` only so
  scheduled tasks never fire twice.
- **A dedicated monitoring server stays for monitoring.** You cannot place web or worker copies on
  a server dedicated to the [self-hosted monitoring stack](monitoring.md).

Then run:

```bash
npx opscrew design      # sizes and prices each server, enables PgBouncer, checks readiness
npx opscrew provision   # creates and wires each server after you approve the plan hash
```

Every infrastructure and host change still goes through OpsCrew's normal plan-hash-bound approval.

## Zero-extra-cost load balancing over WireGuard

You do not need to pay for a cloud load balancer to run multiple web copies. The front server's
[reverse proxy](reverse-proxy.md) — **Caddy**, **nginx** or **OpenLiteSpeed** — balances HTTP and
WebSocket requests across its local `app-proxy` and each copy server's `app-proxy` over the
encrypted WireGuard network:

- **Private only:** copy servers run the app on a private Docker network and expose their
  `app-proxy` only on their private WireGuard address — never on public ports 80 or 443.
- **Automatic failover:** active and passive health checks mark an unhealthy copy down and route
  all traffic to the remaining healthy copies until it recovers.
- **Load-balancing policy (`scaling.loadBalancer.policy`):**
  - `round_robin` (default): distributes requests evenly in turn.
  - `least_conn`: sends each request to the copy handling the fewest active connections (helpful
    when some endpoints take longer than others).
  - `ip_hash`: pins a client IP to the same copy when possible.
- **Single-copy plans stay untouched:** without `app.servers`, OpsCrew generates the exact same
  single-server proxy configuration as before.

## PostgreSQL connection pooling with PgBouncer

Every additional web or worker server opens its own pool of database connections. With several
copies running, apps can quickly hit PostgreSQL's `max_connections` limit.

When your plan has two or more web servers (`app.servers` non-empty) and an enabled self-hosted
PostgreSQL 15+ database, `npx opscrew design` automatically enables
[PgBouncer](databases.md) (`options: { logins: separate, pooler: pgbouncer }`) and counts
PgBouncer's memory on the database server. If your database runs PostgreSQL 14 or an older deployed
database without `logins: separate`, design leaves the database untouched and prints a warning
explaining how to turn connection pooling on.

## Cross-provider and cross-region database latency

Databases, caches and message brokers remain on one server each
([split placement](split-placement.md)). When remote web or worker copies exist, any backing
service running on `app` publishes on `app`'s private WireGuard address so copy servers reach it
over the encrypted tunnel.

Every query from a remote copy to a database or cache crosses the network between those two
servers:

- **Same provider and region (recommended):** WireGuard adds roughly 1 ms per query.
- **Different cloud regions or different providers (or a cloud server beside your own server):**
  every query crosses the internet over WireGuard and adds round-trip latency on every round trip.
  `npx opscrew design` flags this with a clear warning (including an estimated round-trip time when
  both cloud locations are known).

Keep web and worker copy servers in the same provider and region as your database whenever low
request latency matters.

## Serial rolling deploys, rollbacks and operations

When you push a release to a multi-copy app, the deploy workflow keeps the site online and keeps
every copy on the same version:

1. **Pull everywhere first:** every web and worker server pulls the new container image before any
   traffic changes, so a bad image or registry hiccup fails fast with zero impact.
2. **Snapshot and migrations once:** the pre-release [snapshot](snapshots.md) and your
   `releaseCommand` (database migrations) run once on `app` only.
3. **One web server at a time:** `app` switches to the new version and passes its health check
   first, then each server in `app.servers` switches serially one by one.
4. **Automatic rollback on failure:** if any web copy fails its health check, OpsCrew restores that
   copy's previous route and rolls back every already-updated copy to the previous digest so you
   never run mixed versions.
5. **Workers roll after web succeeds:** worker copies on extra servers update after all web copies
   are healthy; cron jobs remain on `app` only.

Day-to-day commands cover all copy servers automatically:

- `npx opscrew status` shows the web copies, load-balancer policy, worker copies, private network
  links and per-server status ([logs and status](logs-and-status.md)).
- `npx opscrew rollback` rolls back all web and worker copies together ([rollback](rollback.md)).
- `npx opscrew drift`, `npx opscrew verify`, `npx opscrew rotate` and `npx opscrew destroy` include
  every copy server cleanly.

## When advise recommends scaling out

On a single-server app, [`npx opscrew advise`](advise.md) watches for sustained high CPU load,
sustained web process memory pressure, or hitting the largest single-server tier at your provider:

- If no local-state blockers are present, advise proposes adding a second web server under
  `servers` and `app.servers`.
- If `storage.sqlite`, `storage.files`, or framework `statelessIssues` from `opscrew/architecture.json`
  are present, advise lists each concrete blocker and its fix before suggesting horizontal copies.
