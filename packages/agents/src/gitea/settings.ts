import { normalizeHostName, OpsCrewError } from "@opscrew/core";
import { IMAGES } from "@opscrew/iac-templates";
import {
  type DeployPlan,
  DeployPlanSchema,
  GITEA_DEFAULT_SSH_PORT,
  GITEA_DEFAULT_TOKEN_SCOPES,
  GITEA_MEMORY_DEFAULTS,
  type GiteaDatabase,
  type GiteaSettings,
  type GiteaTokenScope,
  onOneServer,
} from "@opscrew/plan-schema";
import { pinnedVersion } from "../addons/settings";

/** Pinned rootless Gitea version shipped by this version of OpsCrew (e.g. `28.4.0`). */
export const GITEA_VERSION = pinnedVersion(IMAGES.gitea.ref).replace(/-rootless$/, "");

/** User options for `opscrew addon enable gitea`. */
export interface GiteaEnableRequest {
  /** Public HTTPS hostname (e.g. `git.example.com`, or single label `git` expanded with `dns.zone`). */
  hostname?: string;
  /** Initial administrator email address (required on first enable). */
  adminEmail?: string;
  /** Initial administrator username (defaults to `gitea-admin`). */
  adminUser?: string;
  /** Backing database engine: `sqlite` (default) or `postgres`. */
  database?: GiteaDatabase;
  /** Keep open self-registration disabled (default `true`). */
  disableRegistration?: boolean;
  /** Enable built-in Git-over-SSH server (default `false`). */
  sshEnabled?: boolean;
  /** External TCP port when SSH is enabled (default `2222`; never 22, 80, or 443). */
  sshPort?: number;
  /** Enable app integration (scoped API token & webhook config, default `true`). */
  appIntegrationEnabled?: boolean;
  /** Fine-grained API token scopes for the app token. */
  tokenScopes?: readonly GiteaTokenScope[];
  /** Path on the app that receives Gitea webhooks (e.g. `/api/webhooks/gitea`). */
  webhookPath?: string;
  /** Additional hostnames/CIDRs Gitea webhooks may call (never `*`). */
  webhookAllowedHosts?: readonly string[];
}

/** Validates that `plan` targets a server OpsCrew can run self-hosted Gitea on. */
export function requireGiteaTarget(plan: DeployPlan, command: string): void {
  if (plan.environment?.previews !== undefined) {
    throw new OpsCrewError(
      "PHASE_PRECONDITION",
      `Self-hosted Gitea cannot run in a preview environment, so \`${command}\` changes nothing.`,
      { hint: "Run `opscrew addon enable gitea` for a persistent environment such as prod." },
    );
  }
  if (onOneServer(plan.target.provider)) return;
  throw new OpsCrewError(
    "PHASE_PRECONDITION",
    `Self-hosted Gitea runs only on a cloud server or your own server, and this environment uses ${plan.target.provider}, so \`${command}\` changes nothing.`,
    { hint: "Choose a cloud VPS or own-server target to provision self-hosted Gitea." },
  );
}

/**
 * Resolves and validates {@link GiteaSettings} from the existing plan and user request.
 * Throws `INVALID_INPUT` with plain-English remediation if required fields are missing or invalid.
 */
export function giteaSettings(plan: DeployPlan, request: GiteaEnableRequest): GiteaSettings {
  const existing = plan.gitea;
  const rawHost = normalizeHostName(request.hostname ?? existing?.hostname ?? "");
  if (rawHost === "") {
    throw new OpsCrewError(
      "INVALID_INPUT",
      "Self-hosted Gitea needs a hostname so OpsCrew can serve it over HTTPS behind the reverse proxy. Nothing was changed.",
      {
        hint: "Pass `--hostname git.example.com` (or `--hostname git` when your domain is on Cloudflare).",
      },
    );
  }
  const zone = plan.dns.zone;
  const hostname = rawHost.includes(".") || zone === undefined ? rawHost : `${rawHost}.${zone}`;
  const adminEmail = (request.adminEmail ?? existing?.adminEmail ?? "").trim();
  if (adminEmail === "") {
    throw new OpsCrewError(
      "INVALID_INPUT",
      "Self-hosted Gitea needs an administrator email address for the initial admin account. Nothing was changed.",
      { hint: "Pass `--admin-email you@example.com`." },
    );
  }

  if (
    existing?.enabled === true &&
    request.database !== undefined &&
    request.database !== existing.database
  ) {
    throw new OpsCrewError(
      "INVALID_INPUT",
      `Self-hosted Gitea is already configured with \`${existing.database}\`; switching to \`${request.database}\` in place would boot an empty database without migrating repositories or metadata. Nothing was changed.`,
      {
        hint: "Back up your Gitea data first (`opscrew snapshot take`), disable Gitea with `--delete-data`, and re-enable it with the desired `--database`.",
      },
    );
  }

  const webhookPath = request.webhookPath ?? existing?.appIntegration.webhook?.path;
  const webhookAllowedHosts =
    request.webhookAllowedHosts !== undefined
      ? [...request.webhookAllowedHosts]
      : [...(existing?.appIntegration.webhook?.allowedHosts ?? [])];

  return {
    enabled: true,
    version: existing?.version ?? GITEA_VERSION,
    hostname,
    database: request.database ?? existing?.database ?? "sqlite",
    adminUser: request.adminUser ?? existing?.adminUser ?? "gitea-admin",
    adminEmail,
    disableRegistration: request.disableRegistration ?? existing?.disableRegistration ?? true,
    ssh: {
      enabled: request.sshEnabled ?? existing?.ssh.enabled ?? false,
      port: request.sshPort ?? existing?.ssh.port ?? GITEA_DEFAULT_SSH_PORT,
    },
    appIntegration: {
      enabled: request.appIntegrationEnabled ?? existing?.appIntegration.enabled ?? true,
      tokenScopes:
        request.tokenScopes !== undefined
          ? [...request.tokenScopes]
          : [...(existing?.appIntegration.tokenScopes ?? GITEA_DEFAULT_TOKEN_SCOPES)],
      ...(webhookPath !== undefined || webhookAllowedHosts.length > 0
        ? {
            webhook: {
              ...(webhookPath === undefined ? {} : { path: webhookPath }),
              allowedHosts: webhookAllowedHosts,
            },
          }
        : {}),
    },
    memoryMb: existing?.memoryMb ?? { ...GITEA_MEMORY_DEFAULTS },
  };
}

/**
 * Returns `plan` with `plan.gitea` replaced (or removed when `settings` is `undefined`), validated
 * against `DeployPlanSchema`. Throws `INVALID_INPUT` with plain-English message on violation.
 */
export function withGitea(plan: DeployPlan, settings: GiteaSettings | undefined): DeployPlan {
  const { gitea: _old, ...rest } = plan;
  const candidate = settings === undefined ? rest : { ...rest, gitea: settings };
  const parsed = DeployPlanSchema.safeParse(candidate);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    const path = issue?.path.join(".") ?? "gitea";
    throw new OpsCrewError(
      "INVALID_INPUT",
      `OpsCrew cannot use these self-hosted Gitea settings: ${path} ${issue?.message ?? "is not valid"}. Nothing was changed.`,
      { hint: "Fix the setting named above and run the command again." },
    );
  }
  return parsed.data;
}
