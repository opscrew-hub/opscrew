# Research: Self-Hosted Gitea Provisioning & App Integration (Feature 043 Follow-Up)

**Feature:** `043-gitea-self-hosted` | **Issue:** `#70` | **Date:** 2026-11-28 | **Sources:** Official Gitea documentation (`docs.gitea.com`), `go-gitea/gitea` GitHub releases, and Docker Hub OCI Registry v2 API only.

---

## R1. Official Rootless Docker Image & Pinning

- **Upstream release checked live (2026-11-28):** `go-gitea/gitea` latest stable release is **`v28.4.0`** (published `2026-11-15T19:39:47Z`, `https://github.com/go-gitea/gitea/releases/tag/v28.4.0`).
- **Rootless image choice:** Gitea ships an official rootless Docker image (`gitea/gitea:<version>-rootless`) that runs non-root as UID/GID `1000` (`git`), avoids host OpenSSH coupling, and uses FHS-compliant paths:
  - Data directory: `/var/lib/gitea` (repositories, SQLite database, LFS objects, attachments, avatars, packages, indexers)
  - Config directory: `/etc/gitea` (`app.ini`)
  - HTTP port (inside container): `3000`
  - Built-in SSH server port (inside container, when enabled): `2222`
- **Multi-arch OCI index digest (verified live from Docker Hub `registry-1.docker.io` on 2026-11-28):**
  - Tag: `gitea/gitea:28.4.0-rootless`
  - Digest: `sha256:15ab7fadb44981a2b781f40c712cad07066197f395100ea1c6326e14e5bb073a`
  - Architectures: `linux/amd64`, `linux/arm64`, `linux/riscv64`
  - Full pin for `packages/iac-templates/src/pins.ts`:
    `gitea/gitea:28.4.0-rootless@sha256:15ab7fadb44981a2b781f40c712cad07066197f395100ea1c6326e14e5bb073a`
- **Named volumes vs host bind mounts:** Official Gitea rootless Docker docs note that Docker named volumes (`gitea_data:/var/lib/gitea`, `gitea_config:/etc/gitea`) automatically initialize ownership for UID/GID `1000`, avoiding host `chown` issues and working uniformly on both cloud servers (deploy user) and own servers (root).
- **Health endpoint:** `GET http://127.0.0.1:3000/api/healthz` returns HTTP `200` with JSON status when Gitea and its database are ready.

---

## R2. Database Options (SQLite vs PostgreSQL)

Gitea maps environment variables of the form `GITEA__<SECTION>__<KEY>` directly into `app.ini` at container startup (official Configuration Cheat Sheet & Installation with Docker docs).

### Option 1: SQLite (Default for small servers)
- Single container, zero additional database RAM overhead.
- Settings:
  - `GITEA__database__DB_TYPE=sqlite3`
  - `GITEA__database__PATH=/var/lib/gitea/data/gitea.db`
- All state resides in the `gitea_data` volume (`/var/lib/gitea`).

### Option 2: Dedicated PostgreSQL 17 (`database: "postgres"`)
- Recommended for higher concurrency, larger repository counts, or teams.
- Runs a dedicated `IMAGES.postgres.ref` (`postgres:17-alpine@sha256:...`) container (`gitea-db`) isolated on Gitea's internal Docker network (`gitea-internal`, never exposed on `opscrew-edge` or host ports).
- Settings:
  - Gitea container:
    - `GITEA__database__DB_TYPE=postgres`
    - `GITEA__database__HOST=gitea-db:5432`
    - `GITEA__database__NAME=gitea`
    - `GITEA__database__USER=gitea`
    - `GITEA__database__PASSWD` — supplied ONLY in `gitea.env` (mode `0600`), never in `compose.yaml`.
  - Postgres container:
    - `POSTGRES_DB=gitea`, `POSTGRES_USER=gitea`, `POSTGRES_PASSWORD` — supplied ONLY in `postgres.env` (mode `0600`).
    - Healthcheck: `pg_isready -U gitea -d gitea`.

---

## R3. Hardened Unattended Setup & Reverse Proxy Integration

### Unattended Install & Hardened Defaults
- `GITEA__security__INSTALL_LOCK=true`: skips the interactive web installer so a freshly started instance can never be hijacked via `/install`.
- `GITEA__service__DISABLE_REGISTRATION=true`: disables public self-registration by default (only administrators create accounts).
- Generated secrets (all delivered via `0600` `gitea.env`, never in `compose.yaml`, `plan.yaml`, logs, or audit):
  - `GITEA__security__SECRET_KEY` (32 random bytes hex)
  - `GITEA__security__INTERNAL_TOKEN` (64 random bytes base64url)
  - `GITEA__oauth2__JWT_SECRET` (32 random bytes base64url)
  - `GITEA__lfs__JWT_SECRET` (32 random bytes base64url)
- Public URL & domain:
  - `GITEA__server__ROOT_URL=https://<hostname>/`
  - `GITEA__server__DOMAIN=<hostname>`
  - `GITEA__server__PROTOCOL=http`
  - `GITEA__server__HTTP_ADDR=0.0.0.0`
  - `GITEA__server__HTTP_PORT=3000`
- Reverse proxy trust (official Reverse Proxies docs):
  - `GITEA__security__REVERSE_PROXY_LIMIT=1`
  - `GITEA__security__REVERSE_PROXY_TRUSTED_PROXIES=127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16`
- Git-over-SSH:
  - Disabled by default (`GITEA__server__DISABLE_SSH=true`, `GITEA__server__START_SSH_SERVER=false`) so Git operates over HTTPS with scoped personal access tokens and the host firewall requires zero ports beyond 22/80/443.
  - Opt-in (`ssh: { enabled: true, port: 2222 }`): sets `START_SSH_SERVER=true`, `DISABLE_SSH=false`, `SSH_LISTEN_PORT=2222`, `SSH_PORT=<port>`, and publishes `<port>:2222` (port `22`, `80`, `443` forbidden to prevent collisions).
- Actions & OCI Package Registry enabled by default (`GITEA__actions__ENABLED=true`, `GITEA__packages__ENABLED=true`, `GITEA__server__LFS_START_SERVER=true`) so the provisioned instance works seamlessly with OpsCrew's existing Feature `043` Gitea Actions & registry workflow.

### Reverse Proxy Routing Behind `opscrew-edge` (Caddy / nginx / OpenLiteSpeed)
- Port `3000` is **never published on `0.0.0.0`** (nor on host loopback, avoiding port `3000` collisions with self-hosted Grafana).
- Instead, the `gitea` service joins OpsCrew's external `opscrew-edge` network under network alias `opscrew-gitea`, and OpsCrew renders a dedicated edge site file `/srv/edge/sites/opscrew-gitea.<ext>`:
  - **Caddy** (`opscrew-gitea.caddy`): `caddySite` with `upstream: "opscrew-gitea:3000"`, automatic TLS (or Cloudflare Origin TLS), HSTS, security headers.
  - **nginx** (`opscrew-gitea.conf`): `nginxSite` with dynamic Docker DNS resolution (`set $opscrew_upstream http://opscrew-gitea:3000; proxy_pass $opscrew_upstream;`), TLS, HSTS, WebSockets, `proxy_buffering off`, large Git push body limit (`512m`).
  - **OpenLiteSpeed** (`opscrew-gitea.vhost`, `opscrew-gitea.map`, `opscrew-gitea.vhconf`): dedicated proxy extprocessor targeting `http://opscrew-gitea:3000`, TLS, HSTS, security headers.

---

## R4. Admin Bootstrap, Scoped API Tokens & Webhooks (App Integration)

### Programmatic Admin & Scoped Token Creation (Gitea CLI)
Official Gitea CLI commands executed inside the healthy `gitea` container (with secrets delivered via environment/stdin, never on remote shell command lines):
1. Admin user creation (idempotent — skipped if username already exists):
   ```sh
   gitea admin user create \
     --username "$GITEA_ADMIN_USER" \
     --password "$GITEA_ADMIN_PASSWORD" \
     --email "$GITEA_ADMIN_EMAIL" \
     --admin \
     --must-change-password=false
   ```
2. Scoped API token creation:
   ```sh
   gitea admin user generate-access-token \
     --username "$GITEA_ADMIN_USER" \
     --token-name "opscrew-app" \
     --scopes "read:repository,read:issue,read:organization,read:user" \
     --raw
   ```
- **Least-privilege scopes:** Gitea supports fine-grained scopes (`read:*` / `write:*` across `repository`, `issue`, `organization`, `user`, `package`, `notification`, `misc`, `admin`). Default app-integration scopes are read-only (`read:repository`, `read:issue`, `read:organization`, `read:user`) — enough for an app that displays repositories, pull requests, issues, commits, and activity without write/admin access. Users may opt into broader scopes (e.g. `write:repository`, `write:issue`) in `plan.yaml`.

### REST API v1 Endpoints for App Integration
Base URL: `https://<hostname>/api/v1` | Auth header: `Authorization: token <GITEA_TOKEN>`
- Repositories: `GET /api/v1/user/repos`, `GET /api/v1/orgs/{org}/repos`, `GET /api/v1/repos/{owner}/{repo}`
- Pull requests: `GET /api/v1/repos/{owner}/{repo}/pulls`
- Issues & comments: `GET /api/v1/repos/{owner}/{repo}/issues`, `GET /api/v1/repos/{owner}/{repo}/issues/{index}/comments`
- Commits & activity: `GET /api/v1/repos/{owner}/{repo}/commits`, `GET /api/v1/users/{username}/heatmap`, `GET /api/v1/repos/{owner}/{repo}/activities/feeds`
- Webhooks management: `GET|POST /api/v1/repos/{owner}/{repo}/hooks`, `PATCH|DELETE /api/v1/repos/{owner}/{repo}/hooks/{id}`, `POST /api/v1/repos/{owner}/{repo}/hooks/{id}/tests`

### Webhooks & HMAC-SHA256 Verification
- **Delivery:** HTTP `POST` with `Content-Type: application/json`, event name in `X-Gitea-Event` (e.g. `push`, `pull_request`, `issues`, `issue_comment`, `release`), delivery UUID in `X-Gitea-Delivery`.
- **Signature header (`X-Gitea-Signature`):** Lowercase hex-encoded HMAC-SHA256 digest of the **raw** request body using the shared webhook secret.
  - **Key difference from GitHub:** GitHub sends `X-Hub-Signature-256: sha256=<hex>`, whereas Gitea sends `X-Gitea-Signature: <hex>` (no `sha256=` prefix). Apps must compare digests with constant-time `crypto.timingSafeEqual`.
- **Outgoing webhook SSRF hardening (`[webhook]` section):**
  - `GITEA__webhook__ALLOWED_HOST_LIST` defaults to `external` (non-private public unicast IPs). When the app lives on the same domain or extra allowed hosts are configured, OpsCrew explicitly lists them (`external,<app-domain>,...`) and **never** allows wildcard `*`.
  - `GITEA__webhook__SKIP_TLS_VERIFY=false` always enforced.

---

## R5. Snapshots, Restore & Restore Drills

- **SQLite mode:** Consistent backup requires stopping the `gitea` container cleanly (flushing SQLite WAL and git packfiles), tarring `gitea_data` (`/var/lib/gitea`) and `gitea_config` (`/etc/gitea`) into `gitea.tar`, and restarting `gitea` — matching OpsCrew's existing stop-only service snapshot mechanism in `snapshot.sh`.
- **PostgreSQL mode:** Takes both an online `pg_dump -Fc` of `gitea-db` (`gitea-db.dump`) and a stop-only archive of `gitea_data` + `gitea_config` (`gitea.tar`) so database metadata and bare Git repositories stay consistent.
- **Restore drills (`opscrew restore --drill`):** Restores Gitea snapshot artifacts (`gitea.tar` and optional `gitea-db.dump`) into a throwaway Compose project with `--network none` / internal-only networking, verifies the restored SQLite/PostgreSQL schema and Gitea config/data integrity, and removes the throwaway copy afterwards.
