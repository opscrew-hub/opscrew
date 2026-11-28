/**
 * Self-hosted Gitea (`plan.gitea`, feature 043 follow-up, issue #70): optional hardened rootless
 * Gitea instance provisioned on the app's server behind the shared reverse proxy (`opscrew-edge`),
 * with SQLite or dedicated PostgreSQL storage and least-privilege app integration (API token &
 * HMAC-SHA256 webhooks).
 */
import { z } from "zod";
import { FqdnSchema, PortSchema, UrlPathSchema } from "./enums";

/** Default container memory limits for self-hosted Gitea, in MB. */
export const GITEA_MEMORY_DEFAULTS = {
  gitea: 512,
  postgres: 256,
} as const;

/** Default Gitea SSH port when Git-over-SSH is explicitly enabled (never host port 22). */
export const GITEA_DEFAULT_SSH_PORT = 2222;

/** Supported fine-grained Gitea Personal Access Token scopes. */
export const GITEA_TOKEN_SCOPES = [
  "read:repository",
  "write:repository",
  "read:issue",
  "write:issue",
  "read:organization",
  "write:organization",
  "read:user",
  "write:user",
  "read:package",
  "write:package",
  "read:notification",
  "write:notification",
  "read:misc",
] as const;

export type GiteaTokenScope = (typeof GITEA_TOKEN_SCOPES)[number];

export const GiteaTokenScopeSchema = z.enum(GITEA_TOKEN_SCOPES);

/** Default least-privilege scopes for an app displaying repositories, pull requests, issues, and activity. */
export const GITEA_DEFAULT_TOKEN_SCOPES: readonly GiteaTokenScope[] = [
  "read:repository",
  "read:issue",
  "read:organization",
  "read:user",
];

/** Backing database engine for self-hosted Gitea: single-container SQLite or dedicated PostgreSQL. */
export const GiteaDatabaseSchema = z.enum(["sqlite", "postgres"]);
export type GiteaDatabase = z.infer<typeof GiteaDatabaseSchema>;

const GiteaVersionSchema = z.string().regex(/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?$/, {
  message: "must be a pinned version such as `28.4.0`, not a floating tag such as `latest`",
});

const GiteaAdminUserSchema = z
  .string()
  .regex(/^[a-z][a-z0-9_-]{1,31}$/, {
    message:
      "must be 2-32 lower-case letters, digits, hyphens or underscores, starting with a letter",
  })
  .refine((name) => name !== "root", {
    message: 'must not be "root"; choose a dedicated administrator username such as "gitea-admin"',
  });

/** Gitea webhook `ALLOWED_HOST_LIST` wildcards/keywords forbidden for SSRF safety (case-insensitive). */
const FORBIDDEN_WEBHOOK_HOSTS = new Set(["*", "all", "private", "loopback"]);

/** Outgoing webhook delivery configuration for app integration. */
export const GiteaWebhookSchema = z.strictObject({
  /** Path on the app that receives Gitea webhooks, for example `/api/webhooks/gitea`. */
  path: UrlPathSchema.optional(),
  /**
   * Extra hostnames or CIDRs Gitea webhooks may deliver to, in addition to `external` and the
   * app's own domain. Wildcard `*` and Gitea's built-in `all`, `private`, and `loopback` keywords
   * are refused for SSRF safety.
   */
  allowedHosts: z
    .array(
      z
        .string()
        .min(1)
        .refine((host) => !FORBIDDEN_WEBHOOK_HOSTS.has(host.trim().toLowerCase()), {
          message:
            'must not be "*", "all", "private", or "loopback": name specific hostnames or CIDRs instead of allowing webhooks to reach arbitrary internal hosts',
        }),
    )
    .default(() => []),
});
export type GiteaWebhookSettings = z.output<typeof GiteaWebhookSchema>;

/** App integration settings: scoped API token and webhook delivery. */
export const GiteaAppIntegrationSchema = z.strictObject({
  enabled: z.boolean().default(true),
  /** Fine-grained Gitea token scopes; defaults to read-only repos, issues, organizations, and user. */
  tokenScopes: z
    .array(GiteaTokenScopeSchema)
    .min(1)
    .default(() => [...GITEA_DEFAULT_TOKEN_SCOPES]),
  webhook: GiteaWebhookSchema.optional(),
});
export type GiteaAppIntegration = z.output<typeof GiteaAppIntegrationSchema>;

/** Git-over-SSH settings for self-hosted Gitea (disabled by default). */
export const GiteaSshSchema = z.strictObject({
  enabled: z.boolean().default(false),
  /** External TCP port when SSH is enabled (never 22, 80, or 443; defaults to 2222). */
  port: PortSchema.refine((port) => port !== 22 && port !== 80 && port !== 443, {
    message: "must not be 22, 80 or 443 (reserved for host SSH and web traffic); use e.g. 2222",
  }).default(GITEA_DEFAULT_SSH_PORT),
});
export type GiteaSshSettings = z.output<typeof GiteaSshSchema>;

/**
 * Self-hosted Gitea settings (`plan.gitea`). Never holds secrets: admin password, `SECRET_KEY`,
 * `INTERNAL_TOKEN`, JWT secrets, Postgres password, app API token, and webhook signing secret live
 * in OpsCrew's private local secrets (`gitea_secrets.json`) and reach the server only via `0600`
 * env files over stdin.
 */
export const GiteaSchema = z.strictObject({
  enabled: z.boolean().default(false),
  /** Pinned rootless Gitea image version (e.g. `28.4.0`). */
  version: GiteaVersionSchema,
  /** Public HTTPS hostname served through the server's reverse proxy (e.g. `git.example.com`). */
  hostname: FqdnSchema,
  /** `sqlite` (default, single container) or `postgres` (dedicated PostgreSQL 17 container). */
  database: GiteaDatabaseSchema.default("sqlite"),
  /** Initial administrator username (default `gitea-admin`). */
  adminUser: GiteaAdminUserSchema.default("gitea-admin"),
  /** Initial administrator email address. */
  adminEmail: z.email(),
  /**
   * Disable open self-registration (`GITEA__service__DISABLE_REGISTRATION=true`).
   * Hardened default is `true`.
   */
  disableRegistration: z.boolean().default(true),
  /** Optional Git-over-SSH server (off by default). */
  ssh: GiteaSshSchema.prefault({}),
  /** App integration: scoped API token and webhook delivery. */
  appIntegration: GiteaAppIntegrationSchema.prefault({}),
  /** Container memory limits in MB. */
  memoryMb: z
    .strictObject({
      gitea: z.int().positive().default(GITEA_MEMORY_DEFAULTS.gitea),
      postgres: z.int().positive().default(GITEA_MEMORY_DEFAULTS.postgres),
    })
    .prefault({}),
});
export type GiteaSettings = z.output<typeof GiteaSchema>;

/** The plan's self-hosted Gitea settings when enabled, else `undefined`. */
export function giteaOf(plan: {
  readonly gitea?: GiteaSettings | undefined;
}): GiteaSettings | undefined {
  return plan.gitea?.enabled === true ? plan.gitea : undefined;
}
