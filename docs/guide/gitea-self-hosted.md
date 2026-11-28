# Self-Hosted Gitea: Provisioning & App Integration

OpsCrew can provision and operate a hardened, self-hosted [Gitea](https://about.gitea.com/) instance
on your server (a cloud VPS or your own server), route it over HTTPS behind OpsCrew's reverse proxy,
include it in snapshots and restore drills, and prepare a least-privilege API token and HMAC webhook
secret so your application can integrate with Gitea the same way it integrates with GitHub.

> Looking to deploy a repository hosted on an existing Gitea instance (`gitea.com` or your own)?
> See [Gitea (`gitea.com` and self-hosted)](gitea.md).

## Prerequisites: DNS & Routing

Before running `opscrew addon enable gitea --hostname git.example.com`, make sure `git.example.com`
reaches your server's reverse proxy:

- **Direct DNS (A/AAAA):** point `git.example.com` to your server's public IPv4 (and IPv6, if enabled)
  at your DNS provider. Your server's reverse proxy (Caddy, nginx, or OpenLiteSpeed) will obtain and
  renew the TLS certificate automatically.
- **Cloudflare Tunnel:** if your server is served through a Cloudflare Tunnel rather than a public
  HTTP/HTTPS port, add a public hostname route for `git.example.com` pointing to your edge proxy
  container/port and matching DNS CNAME record.
- **Shared servers (ADR 0035):** self-hosted Gitea is a server-wide singleton owned by a single app
  (tracked via a `0600` `.owner` marker on the host). OpsCrew refuses to enable or disable Gitea from
  a second app sharing another app's server.

## Provisioning self-hosted Gitea

Every change goes through OpsCrew's safety gate:
`plan -> SecOps policy checks -> SHA-256 plan-hash approval -> apply`.

### SQLite (default, single container)

```bash
npx opscrew addon enable gitea \
  --hostname git.example.com \
  --admin-email admin@example.com \
  --webhook-path /api/webhooks/gitea
```

### Dedicated PostgreSQL 17

For higher concurrency or teams, use a dedicated PostgreSQL 17 container isolated on Gitea's own
internal Docker network (`gitea-internal`):

```bash
npx opscrew addon enable gitea \
  --hostname git.example.com \
  --admin-email admin@example.com \
  --database postgres \
  --webhook-path /api/webhooks/gitea
```

> Switching `database` between `sqlite` and `postgres` in place is refused because it would boot an
> empty database without migrating data. Back up first (`opscrew snapshot take`), disable with
> `--delete-data`, and re-enable with the desired engine.

### Non-interactive / plan-first workflow

```bash
# 1. Preview the host plan, SecOps checks, and SHA-256 plan hash (changes nothing)
npx opscrew addon enable gitea \
  --hostname git.example.com \
  --admin-email admin@example.com \
  --plan-only

# 2. Approve and apply the exact plan hash
npx opscrew addon enable gitea \
  --hostname git.example.com \
  --admin-email admin@example.com \
  --approve <sha256-hash>
```

## Hardened defaults

OpsCrew enforces these security controls via `evaluateGiteaPolicies` before asking for approval:

- **Pinned rootless image:** runs `gitea/gitea:28.4.0-rootless@sha256:...` (UID/GID `1000`, non-root,
  `no-new-privileges:true`, `cap_drop: ["ALL"]`, memory limits, and log rotation).
- **Web installer locked (`GITEA__security__INSTALL_LOCK=true`):** eliminates interactive `/install`
  takeover on fresh boots.
- **Open registration & OpenID signup disabled:** `GITEA__service__DISABLE_REGISTRATION=true` and
  `GITEA__openid__ENABLE_OPENID_SIGNUP=false` by default so only administrators create accounts.
- **Secure session cookies (`GITEA__session__COOKIE_SECURE=true`):** session cookies are sent only
  over HTTPS.
- **Behind the reverse proxy only:** port `3000` is never published on `0.0.0.0`. Gitea joins
  `opscrew-edge` under alias `opscrew-gitea` and is served over HTTPS with HSTS and security headers
  by your server's configured proxy (**Caddy**, **nginx**, or **OpenLiteSpeed**).
- **Git over HTTPS by default:** built-in SSH is disabled by default so the firewall stays locked to
  ports 22, 80, and 443. Opt in with `--ssh --ssh-port 2222` (ports 22, 80, and 443 are refused).
  When `--ssh` is enabled, OpsCrew sets `GITEA__server__SSH_DOMAIN=<hostname>` and publishes your
  chosen port; you must also allow that TCP port in your server firewall (UFW and/or cloud provider
  firewall) if external Git-over-SSH clients need to reach it.
- **Webhook SSRF protection:** `GITEA__webhook__ALLOWED_HOST_LIST` allows `external` plus your app's
  domain (refusing `*`, `all`, `private`, and `loopback`), and `GITEA__webhook__SKIP_TLS_VERIFY=false`.
- **Zero plaintext secrets in Git, plans, or logs:** `adminPassword`, `botPassword`, `SECRET_KEY`,
  `INTERNAL_TOKEN`, JWT secrets, optional Postgres password, `appApiToken`, and `webhookSecret` are
  stored locally in `gitea_secrets.json` (mode `0600`), included in `opscrew secrets backup` /
  `opscrew secrets restore`, registered with OpsCrew's redactor, and delivered to the server strictly
  over stdin into `0600` env files.

## Connecting your app to Gitea (API token & webhooks)

During provisioning, OpsCrew's idempotent host bootstrap creates:

1. Your administrator account (`gitea.adminUser`, default `gitea-admin`).
2. A dedicated **non-admin** bot account (`opscrew-bot`) with a least-privilege Personal Access Token
   (`opscrew-app`, default scopes: `read:repository,read:issue,read:organization,read:user`).

OpsCrew saves the generated `appApiToken` and `webhookSecret` locally in your project's `0600`
`gitea_secrets.json` (backed up via `opscrew secrets backup`). **OpsCrew does not automatically
inject these variables into your running app container or create repository webhooks in Gitea.**

### 1. Wire environment variables into your app

Set these four environment variables on your app (for example using `opscrew values set` or your
app's `.env` workflow), reading the secret values from your local `gitea_secrets.json`:

| Variable | Value | Secret? |
| --- | --- | --- |
| `GITEA_URL` | `https://git.example.com` | No |
| `GITEA_API_URL` | `https://git.example.com/api/v1` | No |
| `GITEA_API_TOKEN` | Non-admin `opscrew-bot` Personal Access Token (`appApiToken`) | **Yes** |
| `GITEA_WEBHOOK_SECRET` | 64-char hex HMAC-SHA256 signing secret (`webhookSecret`) | **Yes** |

Authenticate API calls with the `Authorization: token <GITEA_API_TOKEN>` header:

| Capability | GitHub REST v3 | Gitea REST v1 (`$GITEA_API_URL`) |
| --- | --- | --- |
| List repositories | `GET /user/repos` | `GET /user/repos` |
| List pull requests | `GET /repos/{owner}/{repo}/pulls` | `GET /repos/{owner}/{repo}/pulls` |
| List issues | `GET /repos/{owner}/{repo}/issues` | `GET /repos/{owner}/{repo}/issues` |
| List commits | `GET /repos/{owner}/{repo}/commits` | `GET /repos/{owner}/{repo}/commits` |
| Activity feed | `GET /repos/{owner}/{repo}/events` | `GET /repos/{owner}/{repo}/activities/feeds` |
| User heatmap | GraphQL contributions | `GET /users/{username}/heatmap` |
| Manage webhooks | `POST /repos/{owner}/{repo}/hooks` | `POST /repos/{owner}/{repo}/hooks` |

### 2. Registering a repository webhook

Register the webhook in Gitea's repository/organization settings (or via the REST API using an admin
token or a token with `write:repository`), passing `webhookSecret` from `gitea_secrets.json`:

```bash
curl -sS -X POST "$GITEA_API_URL/repos/<owner>/<repo>/hooks" \
  -H "Authorization: token <ADMIN_OR_WRITE_REPO_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "gitea",
    "active": true,
    "events": ["push", "pull_request", "issues", "issue_comment", "release"],
    "config": {
      "url": "https://app.example.com/api/webhooks/gitea",
      "content_type": "json",
      "secret": "'"$GITEA_WEBHOOK_SECRET"'"
    }
  }'
```

### 3. Verifying `X-Gitea-Signature` (HMAC-SHA256)

Gitea signs the **raw** JSON request body using HMAC-SHA256 and sends the **lowercase hex** digest
in `X-Gitea-Signature` — note that unlike GitHub's `X-Hub-Signature-256: sha256=<hex>`, Gitea does
**not** include a `sha256=` prefix. Always compare signatures in constant time:

```ts
import { createHmac, timingSafeEqual } from "node:crypto";

export function verifyGiteaWebhook(
  rawBody: Buffer,
  signatureHeader: string | undefined,
  secret: string,
): boolean {
  if (!signatureHeader || !/^[0-9a-f]{64}$/i.test(signatureHeader)) return false;
  const expected = createHmac("sha256", secret).update(rawBody).digest("hex");
  const actualBuf = Buffer.from(signatureHeader.toLowerCase(), "hex");
  const expectedBuf = Buffer.from(expected, "hex");
  return actualBuf.length === expectedBuf.length && timingSafeEqual(actualBuf, expectedBuf);
}
```

## Snapshots and restore drills

When `plan.gitea.enabled` is `true`, Gitea is automatically included in OpsCrew snapshots and
restore drills:

- **SQLite mode:** `opscrew snapshot` stops Gitea cleanly to flush SQLite WAL and Git packfiles,
  archives `gitea_data` (`/var/lib/gitea`) and `gitea_config` (`/etc/gitea`) into `gitea.tar`, and
  restarts Gitea.
- **PostgreSQL mode:** stops Gitea cleanly before taking both `gitea-db.dump` (`pg_dump -Fc`) and
  `gitea.tar`, and stops Gitea before restoring either part so repositories and database rows match
  the same point in time.
- **Restore drills (`opscrew restore --drill`):** restores into throwaway volumes and boots a
  throwaway pinned Gitea container (plus a throwaway PostgreSQL container on an `--internal` network
  in Postgres mode) with zero external network access, probes `/api/healthz`, and removes the
  throwaway containers and network afterward. Production Gitea is never touched.

## Status, disabling, destroy, and known gaps

```bash
# Check status and connection details (never prints secrets)
npx opscrew addon status

# Stop Gitea and remove the reverse proxy route while keeping data volumes (default)
npx opscrew addon disable gitea

# Permanently remove Gitea AND all repositories/database volumes (requires typing git.example.com)
npx opscrew addon disable gitea --delete-data
```

- **Server teardown (`opscrew destroy`):** destroying the app's server permanently deletes any
  self-hosted Gitea repositories and database hosted on it. OpsCrew names Gitea in the destroy
  confirmation prompt; back up or mirror your repositories off-server first.
- **Known gap — secret rotation:** `opscrew rotate` does not yet automate rotating Gitea's internal
  keys (`SECRET_KEY`, `INTERNAL_TOKEN`, JWT secrets) or Postgres password. Keep `gitea_secrets.json`
  backed up via `opscrew secrets backup` so re-enables always reuse the existing `SECRET_KEY`.
