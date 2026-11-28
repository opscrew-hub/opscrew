import type { DeployPlan, GiteaSettings } from "@opscrew/plan-schema";
import { addonImage, composeFile } from "../addons/compose";
import { EDGE_PROJECT } from "../edge";
import { IMAGES } from "../pins";
import { memoryLimit } from "../runtime/components";
import { hardened } from "../runtime/services";
import { planFilePath } from "../workflow/shared";

/** Compose project name for self-hosted Gitea. */
export const GITEA_PROJECT = "opscrew-gitea";

/** Network alias of the Gitea container on the shared edge network (`opscrew-edge`). */
export const GITEA_EDGE_ALIAS = "opscrew-gitea";

/** Internal HTTP port inside the rootless Gitea container (never published on 0.0.0.0). */
export const GITEA_HTTP_PORT = 3000;

/** Internal built-in SSH port inside the rootless Gitea container. */
export const GITEA_SSH_CONTAINER_PORT = 2222;

/** Upstream `host:port` that the reverse proxy routes `gitea.hostname` to. */
export const GITEA_UPSTREAM = `${GITEA_EDGE_ALIAS}:${GITEA_HTTP_PORT}`;

/** Isolated internal Docker network connecting Gitea and its dedicated Postgres container. */
export const GITEA_INTERNAL_NETWORK = "gitea-internal";

/** Env file holding Gitea's secrets (`0600`, written over stdin, never committed). */
export const GITEA_ENV_FILE = "gitea.env";

/** Env file holding Gitea's dedicated Postgres secrets (`0600`, written over stdin, never committed). */
export const GITEA_POSTGRES_ENV_FILE = "postgres.env";

/** Named Docker volumes kept by the `opscrew-gitea` project. */
export const GITEA_VOLUMES = {
  data: "gitea_data",
  config: "gitea_config",
  db: "gitea_db",
} as const;

/** Private RFC1918 + loopback ranges trusted for reverse proxy headers from OpsCrew's edge. */
const TRUSTED_PROXY_CIDRS = "127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16";

/** Gitea webhook host keywords forbidden for SSRF protection (case-insensitive). */
const FORBIDDEN_WEBHOOK_HOSTS = new Set(["*", "all", "private", "loopback"]);

/**
 * Computes `GITEA__webhook__ALLOWED_HOST_LIST` safely (never `*`, `all`, `private`, or `loopback`):
 * starts with `external`, adds the app's own domain when set, and appends any explicit
 * `appIntegration.webhook.allowedHosts`.
 */
export function giteaWebhookAllowedHostList(plan: DeployPlan, gitea: GiteaSettings): string {
  const hosts = new Set<string>(["external"]);
  if (plan.dns.domain !== undefined && plan.dns.domain !== "") {
    hosts.add(plan.dns.domain);
  }
  for (const host of gitea.appIntegration.webhook?.allowedHosts ?? []) {
    const trimmed = host.trim();
    if (trimmed !== "" && !FORBIDDEN_WEBHOOK_HOSTS.has(trimmed.toLowerCase())) {
      hosts.add(trimmed);
    }
  }
  return [...hosts].join(",");
}

/**
 * Renders the hardened rootless Gitea `compose.yaml` (project `opscrew-gitea`):
 * - Uses the digest-pinned `gitea/gitea:<ver>-rootless` image (UID/GID 1000, non-root).
 * - Never embeds plaintext secrets (all secrets come from `gitea.env` / `postgres.env`, mode 0600).
 * - Enforces `INSTALL_LOCK=true`, `DISABLE_REGISTRATION` (default `true`), `SKIP_TLS_VERIFY=false`,
 *   and restricted `ALLOWED_HOST_LIST`.
 * - Never publishes port 3000 to the host; joins `opscrew-edge` as alias `opscrew-gitea` so Caddy,
 *   nginx, or OpenLiteSpeed terminates TLS and proxies to `opscrew-gitea:3000`.
 * - Supports `database: "sqlite"` (single container) or `database: "postgres"` (dedicated isolated
 *   `postgres:17-alpine` container on `gitea-internal`).
 */
export function renderGiteaCompose(plan: DeployPlan, gitea: GiteaSettings): string {
  const giteaImage = addonImage(IMAGES.gitea.ref, `${gitea.version}-rootless`);
  const usePostgres = gitea.database === "postgres";

  const environment: Record<string, string> = {
    GITEA__security__INSTALL_LOCK: "true",
    GITEA__security__REVERSE_PROXY_LIMIT: "1",
    GITEA__security__REVERSE_PROXY_TRUSTED_PROXIES: TRUSTED_PROXY_CIDRS,
    GITEA__session__COOKIE_SECURE: "true",
    GITEA__service__DISABLE_REGISTRATION: gitea.disableRegistration ? "true" : "false",
    GITEA__openid__ENABLE_OPENID_SIGNUP: gitea.disableRegistration ? "false" : "true",
    GITEA__server__ROOT_URL: `https://${gitea.hostname}/`,
    GITEA__server__DOMAIN: gitea.hostname,
    GITEA__server__PROTOCOL: "http",
    GITEA__server__HTTP_ADDR: "0.0.0.0",
    GITEA__server__HTTP_PORT: String(GITEA_HTTP_PORT),
    GITEA__server__DISABLE_SSH: gitea.ssh.enabled ? "false" : "true",
    GITEA__server__START_SSH_SERVER: gitea.ssh.enabled ? "true" : "false",
    ...(gitea.ssh.enabled
      ? {
          GITEA__server__SSH_DOMAIN: gitea.hostname,
          GITEA__server__SSH_LISTEN_PORT: String(GITEA_SSH_CONTAINER_PORT),
          GITEA__server__SSH_PORT: String(gitea.ssh.port),
        }
      : {}),
    GITEA__server__LFS_START_SERVER: "true",
    GITEA__actions__ENABLED: "true",
    GITEA__packages__ENABLED: "true",
    GITEA__webhook__ALLOWED_HOST_LIST: giteaWebhookAllowedHostList(plan, gitea),
    GITEA__webhook__SKIP_TLS_VERIFY: "false",
    ...(usePostgres
      ? {
          GITEA__database__DB_TYPE: "postgres",
          GITEA__database__HOST: "gitea-db:5432",
          GITEA__database__NAME: "gitea",
          GITEA__database__USER: "gitea",
        }
      : {
          GITEA__database__DB_TYPE: "sqlite3",
          GITEA__database__PATH: "/var/lib/gitea/data/gitea.db",
        }),
  };

  const giteaService: Record<string, unknown> = {
    image: giteaImage.image,
    restart: "unless-stopped",
    env_file: [GITEA_ENV_FILE],
    environment,
    ...(gitea.ssh.enabled ? { ports: [`${gitea.ssh.port}:${GITEA_SSH_CONTAINER_PORT}`] } : {}),
    volumes: [`${GITEA_VOLUMES.data}:/var/lib/gitea`, `${GITEA_VOLUMES.config}:/etc/gitea`],
    healthcheck: {
      test: ["CMD-SHELL", `wget -q -O /dev/null http://127.0.0.1:${GITEA_HTTP_PORT}/api/healthz`],
      interval: "15s",
      timeout: "5s",
      retries: 6,
      start_period: "30s",
    },
    ...(usePostgres ? { depends_on: { "gitea-db": { condition: "service_healthy" } } } : {}),
    networks: {
      [GITEA_INTERNAL_NETWORK]: {},
      [EDGE_PROJECT]: { aliases: [GITEA_EDGE_ALIAS] },
    },
    ...memoryLimit(gitea.memoryMb.gitea),
    ...hardened({ noCapabilities: true }),
  };

  const services: Record<string, unknown> = { gitea: giteaService };
  const volumes: Record<string, object> = {
    [GITEA_VOLUMES.data]: {},
    [GITEA_VOLUMES.config]: {},
  };

  if (usePostgres) {
    services["gitea-db"] = {
      image: IMAGES.postgres.ref,
      restart: "unless-stopped",
      env_file: [GITEA_POSTGRES_ENV_FILE],
      volumes: [`${GITEA_VOLUMES.db}:/var/lib/postgresql/data`],
      healthcheck: {
        test: ["CMD-SHELL", "pg_isready -U gitea -d gitea"],
        interval: "10s",
        timeout: "5s",
        retries: 6,
        start_period: "20s",
      },
      networks: [GITEA_INTERNAL_NETWORK],
      ...memoryLimit(gitea.memoryMb.postgres),
      ...hardened(),
    };
    volumes[GITEA_VOLUMES.db] = {};
  }

  const header = [
    `Generated by OpsCrew from ${planFilePath(plan)}; \`opscrew addon enable gitea\` regenerates it.`,
    `Self-hosted rootless Gitea served exclusively behind the reverse proxy at https://${gitea.hostname}/.`,
    "Port 3000 is never published directly; secrets live in 0600 env files beside this file, never here.",
    ...(giteaImage.pinned
      ? []
      : [
          `Gitea ${gitea.version} (gitea.version in the plan) is pinned by tag only, not by digest.`,
        ]),
  ];

  return composeFile(header, {
    name: GITEA_PROJECT,
    services,
    networks: {
      [GITEA_INTERNAL_NETWORK]: { internal: true },
      [EDGE_PROJECT]: { external: true },
    },
    volumes,
  });
}
