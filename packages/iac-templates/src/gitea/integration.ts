import type { DeployPlan, GiteaSettings, GiteaTokenScope } from "@opscrew/plan-schema";
import { shellQuote } from "../runtime/services";
import { GITEA_HTTP_PORT, GITEA_PROJECT } from "./compose";

/** Dedicated non-admin Gitea user that owns the least-privilege app integration token. */
export const GITEA_BOT_USER = "opscrew-bot";

/** Standard token name OpsCrew registers in Gitea for the app's integration. */
export const GITEA_APP_TOKEN_NAME = "opscrew-app";

/** Default webhook events subscribed by an app showing repositories, pull requests, and activity. */
export const GITEA_DEFAULT_WEBHOOK_EVENTS = [
  "push",
  "pull_request",
  "issues",
  "issue_comment",
  "release",
] as const;

/** Environment variable names wired into an app connecting to self-hosted Gitea (never values). */
export const GITEA_APP_ENV_VARS = {
  url: "GITEA_URL",
  apiUrl: "GITEA_API_URL",
  token: "GITEA_API_TOKEN",
  webhookSecret: "GITEA_WEBHOOK_SECRET",
} as const;

/** Secret-free contract describing how an application connects to the provisioned Gitea instance. */
export interface GiteaAppConnectionSpec {
  /** Public HTTPS base URL (`https://<hostname>`). */
  url: string;
  /** REST API v1 base URL (`https://<hostname>/api/v1`). */
  apiUrl: string;
  /** Authorization header format (`Authorization: token <GITEA_TOKEN>`). */
  authHeader: string;
  /** Fine-grained Personal Access Token scopes granted to `GITEA_TOKEN`. */
  tokenScopes: readonly GiteaTokenScope[];
  /** Environment variable names the app should read. */
  envVars: typeof GITEA_APP_ENV_VARS;
  /** Key REST v1 endpoints matching GitHub's repository/PR/activity integration model. */
  endpoints: {
    listRepos: string;
    listPullRequests: string;
    listIssues: string;
    listCommits: string;
    activityFeed: string;
    manageWebhooks: string;
  };
  /** Webhook delivery & HMAC-SHA256 verification contract. */
  webhook: {
    /** Full target URL on the app if `dns.domain` and `webhook.path` are known. */
    targetUrl?: string;
    /** HTTP header carrying the raw lowercase hex HMAC-SHA256 digest (no `sha256=` prefix). */
    signatureHeader: "X-Gitea-Signature";
    /** HTTP header carrying the event name (`push`, `pull_request`, ...). */
    eventHeader: "X-Gitea-Event";
    /** HTTP header carrying the unique delivery UUID. */
    deliveryHeader: "X-Gitea-Delivery";
    /** Signature format note contrasting with GitHub's `sha256=` prefix. */
    signatureFormat: "lowercase-hex-hmac-sha256";
    /** Recommended events to subscribe to. */
    events: readonly string[];
  };
}

/**
 * Returns the deterministic, secret-free connection spec for an application plugging into the
 * provisioned self-hosted Gitea instance (API base URL, scoped API token contract, and HMAC
 * webhook verification details).
 */
export function giteaAppIntegration(
  plan: DeployPlan,
  gitea: GiteaSettings,
): GiteaAppConnectionSpec {
  const url = `https://${gitea.hostname}`;
  const apiUrl = `${url}/api/v1`;
  const webhookPath = gitea.appIntegration.webhook?.path;
  const targetUrl =
    plan.dns.domain !== undefined && webhookPath !== undefined
      ? `https://${plan.dns.domain}${webhookPath}`
      : undefined;

  return {
    url,
    apiUrl,
    authHeader: "Authorization: token $GITEA_API_TOKEN",
    tokenScopes: [...gitea.appIntegration.tokenScopes],
    envVars: GITEA_APP_ENV_VARS,
    endpoints: {
      listRepos: `${apiUrl}/user/repos`,
      listPullRequests: `${apiUrl}/repos/{owner}/{repo}/pulls`,
      listIssues: `${apiUrl}/repos/{owner}/{repo}/issues`,
      listCommits: `${apiUrl}/repos/{owner}/{repo}/commits`,
      activityFeed: `${apiUrl}/repos/{owner}/{repo}/activities/feeds`,
      manageWebhooks: `${apiUrl}/repos/{owner}/{repo}/hooks`,
    },
    webhook: {
      ...(targetUrl === undefined ? {} : { targetUrl }),
      signatureHeader: "X-Gitea-Signature",
      eventHeader: "X-Gitea-Event",
      deliveryHeader: "X-Gitea-Delivery",
      signatureFormat: "lowercase-hex-hmac-sha256",
      events: [...GITEA_DEFAULT_WEBHOOK_EVENTS],
    },
  };
}

/**
 * Renders an idempotent POSIX shell script that runs inside the Gitea addon directory on the
 * server after `docker compose up -d --wait`:
 * 1. Waits for Gitea's `/api/healthz` endpoint.
 * 2. Creates the initial admin user if absent, passing the password strictly on stdin to
 *    `docker compose exec -T` (never via `--env-file` which `exec` does not support, and never in
 *    command-line arguments or logs), deleting the temporary `0600` bootstrap file via trap.
 * 3. When `appIntegration.enabled` is true, creates a dedicated non-admin bot user (`opscrew-bot`)
 *    if absent and generates a least-privilege Personal Access Token (`opscrew-app`, falling back
 *    to a timestamped name if re-enabling over a kept volume where `opscrew-app` already exists in
 *    Gitea's database), writing it atomically to `0600` `.app-token` without printing it.
 * 4. Writes `0600` `.bootstrapped` only after every step succeeds so failed bootstraps are retried.
 */
export function giteaBootstrapScript(gitea: GiteaSettings): string {
  const user = shellQuote(gitea.adminUser);
  const email = shellQuote(gitea.adminEmail);
  const botUser = shellQuote(GITEA_BOT_USER);
  const botEmail = shellQuote(`${GITEA_BOT_USER}@${gitea.hostname}`);
  const scopes = shellQuote(gitea.appIntegration.tokenScopes.join(","));
  const tokenName = shellQuote(GITEA_APP_TOKEN_NAME);
  const lines = [
    "set -eu",
    "umask 077",
    `PROJECT=${shellQuote(GITEA_PROJECT)}`,
    'BOOT_FILE=".bootstrap.env"',
    "trap 'rm -f \"$BOOT_FILE\" .app-token.tmp' EXIT INT TERM",
    'cat > "$BOOT_FILE"',
    'chmod 600 "$BOOT_FILE"',
    'ADMIN_PASS="$(sed -n \'s/^GITEA_ADMIN_PASSWORD=//p\' "$BOOT_FILE" | head -n 1)"',
    'BOT_PASS="$(sed -n \'s/^GITEA_BOT_PASSWORD=//p\' "$BOOT_FILE" | head -n 1)"',
    '[ -n "$ADMIN_PASS" ] || { echo "Missing GITEA_ADMIN_PASSWORD in bootstrap input" >&2; exit 1; }',
    'i=0; until docker compose -p "$PROJECT" exec -T gitea wget -q -O /dev/null http://127.0.0.1:' +
      `${GITEA_HTTP_PORT}/api/healthz; do i=$((i+1)); [ "$i" -lt 30 ] || { echo "Gitea did not become healthy" >&2; exit 1; }; sleep 2; done`,
    "if ! docker compose -p \"$PROJECT\" exec -T gitea gitea admin user list --admin | awk 'NR>1 {print $2}' | grep -Fxq " +
      `${user}; then`,
    `  printf '%s\\n' "$ADMIN_PASS" | docker compose -p "$PROJECT" exec -T gitea sh -c 'IFS= read -r P && exec gitea admin user create --username "$1" --password "$P" --email "$2" --admin --must-change-password=false' _ ${user} ${email} >/dev/null`,
    "fi",
  ];
  if (gitea.appIntegration.enabled) {
    lines.push(
      '[ -n "$BOT_PASS" ] || { echo "Missing GITEA_BOT_PASSWORD in bootstrap input" >&2; exit 1; }',
      `if ! docker compose -p "$PROJECT" exec -T gitea gitea admin user list | awk 'NR>1 {print $2}' | grep -Fxq ${botUser}; then`,
      `  printf '%s\\n' "$BOT_PASS" | docker compose -p "$PROJECT" exec -T gitea sh -c 'IFS= read -r P && exec gitea admin user create --username "$1" --password "$P" --email "$2" --must-change-password=false' _ ${botUser} ${botEmail} >/dev/null`,
      "fi",
      'if [ ! -s ".app-token" ]; then',
      `  if ! docker compose -p "$PROJECT" exec -T gitea gitea admin user generate-access-token --username ${botUser} --token-name ${tokenName} --scopes ${scopes} --raw > .app-token.tmp 2>/dev/null; then`,
      `    docker compose -p "$PROJECT" exec -T gitea gitea admin user generate-access-token --username ${botUser} --token-name ${shellQuote(`${GITEA_APP_TOKEN_NAME}-`)}"$(date -u +%Y%m%d%H%M%S)" --scopes ${scopes} --raw > .app-token.tmp`,
      "  fi",
      '  [ -s .app-token.tmp ] || { echo "Failed to generate Gitea app token" >&2; exit 1; }',
      "  chmod 600 .app-token.tmp && mv .app-token.tmp .app-token",
      "fi",
    );
  }
  lines.push("touch .bootstrapped && chmod 600 .bootstrapped");
  return `${lines.join("\n")}\n`;
}
