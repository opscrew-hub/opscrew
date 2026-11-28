import { randomBytes } from "node:crypto";
import { mkdir, rm } from "node:fs/promises";
import { dirname } from "node:path";
import {
  OpsCrewError,
  type ProjectPaths,
  type Redactor,
  readTextIfExists,
  writeFileAtomic,
} from "@opscrew/core";
import { z } from "zod";

const GiteaSecretsSchema = z.strictObject({
  /** Initial administrator password (letters, digits, `-`, `_`). */
  adminPassword: z.string().regex(/^[A-Za-z0-9_-]{24,128}$/),
  /** Dedicated non-admin bot user (`opscrew-bot`) password (letters, digits, `-`, `_`). */
  botPassword: z
    .string()
    .regex(/^[A-Za-z0-9_-]{24,128}$/)
    .optional(),
  /** `GITEA__security__SECRET_KEY`: 64 lower-case hex digits (32 random bytes). */
  secretKey: z.string().regex(/^[0-9a-f]{64}$/),
  /** `GITEA__security__INTERNAL_TOKEN`: random base64url secret (64 bytes). */
  internalToken: z.string().regex(/^[A-Za-z0-9_-]{48,256}$/),
  /** `GITEA__oauth2__JWT_SECRET`: random base64url secret (32 bytes). */
  jwtSecret: z.string().regex(/^[A-Za-z0-9_-]{32,128}$/),
  /** `GITEA__lfs__JWT_SECRET`: random base64url secret (32 bytes). */
  lfsJwtSecret: z.string().regex(/^[A-Za-z0-9_-]{32,128}$/),
  /** Shared HMAC-SHA256 webhook signing secret (`GITEA_WEBHOOK_SECRET`): 64 hex digits. */
  webhookSecret: z.string().regex(/^[0-9a-f]{64}$/),
  /** Dedicated non-admin bot API token (`GITEA_API_TOKEN`) captured after bootstrap. */
  appApiToken: z.string().min(16).max(256).optional(),
  /** Dedicated PostgreSQL password when `database: "postgres"`: 64 hex digits. */
  postgresPassword: z
    .string()
    .regex(/^[0-9a-f]{64}$/)
    .optional(),
});

/** Self-hosted Gitea secrets stored on this computer (`gitea_secrets.json`, mode 0600). */
export type GiteaSecrets = z.infer<typeof GiteaSecretsSchema>;

function damaged(file: string): OpsCrewError {
  return new OpsCrewError(
    "ARTIFACT_INVALID",
    `The self-hosted Gitea secrets file OpsCrew keeps for this project (${file}) is damaged, so OpsCrew stopped instead of replacing it. Nothing was changed.`,
    {
      hint: "Restore the file from backup (`opscrew secrets restore`), or remove it and re-enable Gitea with fresh secrets.",
    },
  );
}

/** Registers every Gitea secret with the redactor so none can ever appear in output or logs. */
export function registerGiteaSecrets(
  redactor: Pick<Redactor, "addLiteral">,
  secrets: GiteaSecrets,
): GiteaSecrets {
  redactor.addLiteral(secrets.adminPassword, "gitea-admin-password");
  if (secrets.botPassword !== undefined) {
    redactor.addLiteral(secrets.botPassword, "gitea-bot-password");
  }
  redactor.addLiteral(secrets.secretKey, "gitea-secret-key");
  redactor.addLiteral(secrets.internalToken, "gitea-internal-token");
  redactor.addLiteral(secrets.jwtSecret, "gitea-jwt-secret");
  redactor.addLiteral(secrets.lfsJwtSecret, "gitea-lfs-jwt-secret");
  redactor.addLiteral(secrets.webhookSecret, "gitea-webhook-secret");
  if (secrets.appApiToken !== undefined) {
    redactor.addLiteral(secrets.appApiToken, "gitea-api-token");
  }
  if (secrets.postgresPassword !== undefined) {
    redactor.addLiteral(secrets.postgresPassword, "gitea-postgres-password");
  }
  return secrets;
}

/** Reads local Gitea secrets or returns `undefined`; fails closed if the file is damaged. */
export async function readGiteaSecrets(deps: {
  paths: Pick<ProjectPaths, "files">;
  redactor: Pick<Redactor, "addLiteral">;
}): Promise<GiteaSecrets | undefined> {
  const file = deps.paths.files.giteaSecrets;
  const text = await readTextIfExists(file);
  if (text === undefined) return undefined;
  let parsed: z.ZodSafeParseResult<GiteaSecrets>;
  try {
    parsed = GiteaSecretsSchema.safeParse(JSON.parse(text));
  } catch {
    throw damaged(file);
  }
  if (!parsed.success) throw damaged(file);
  return registerGiteaSecrets(deps.redactor, parsed.data);
}

/** Writes Gitea secrets atomically with mode `0600` in a `0700` directory. */
export async function writeGiteaSecrets(
  paths: Pick<ProjectPaths, "files">,
  secrets: GiteaSecrets,
): Promise<void> {
  const file = paths.files.giteaSecrets;
  await mkdir(dirname(file), { recursive: true, mode: 0o700 });
  await writeFileAtomic(file, `${JSON.stringify(secrets, null, 2)}\n`, { mode: 0o600 });
}

/**
 * Ensures Gitea secrets exist on this computer, creating fresh cryptographic secrets when absent
 * (or adding `postgresPassword` if switching from SQLite to PostgreSQL). Always registers every
 * secret with `deps.redactor`.
 */
export async function ensureGiteaSecrets(
  deps: {
    paths: Pick<ProjectPaths, "files">;
    redactor: Pick<Redactor, "addLiteral">;
  },
  usePostgres: boolean,
): Promise<GiteaSecrets> {
  const existing = await readGiteaSecrets(deps);
  if (existing !== undefined) {
    const needsBot = existing.botPassword === undefined;
    const needsPg = usePostgres && existing.postgresPassword === undefined;
    if (needsBot || needsPg) {
      const updated: GiteaSecrets = {
        ...existing,
        ...(needsBot ? { botPassword: randomBytes(24).toString("base64url") } : {}),
        ...(needsPg ? { postgresPassword: randomBytes(32).toString("hex") } : {}),
      };
      registerGiteaSecrets(deps.redactor, updated);
      await writeGiteaSecrets(deps.paths, updated);
      return updated;
    }
    return existing;
  }
  const fresh: GiteaSecrets = {
    adminPassword: randomBytes(24).toString("base64url"),
    botPassword: randomBytes(24).toString("base64url"),
    secretKey: randomBytes(32).toString("hex"),
    internalToken: randomBytes(64).toString("base64url"),
    jwtSecret: randomBytes(32).toString("base64url"),
    lfsJwtSecret: randomBytes(32).toString("base64url"),
    webhookSecret: randomBytes(32).toString("hex"),
    ...(usePostgres ? { postgresPassword: randomBytes(32).toString("hex") } : {}),
  };
  registerGiteaSecrets(deps.redactor, fresh);
  await writeGiteaSecrets(deps.paths, fresh);
  return fresh;
}

/** Removes local Gitea secrets (only when data is deleted). */
export async function removeGiteaSecrets(paths: Pick<ProjectPaths, "files">): Promise<void> {
  await rm(paths.files.giteaSecrets, { force: true });
}

/** Formats Gitea's secret env files for stdin delivery via `ApplySecrets`. Never log these strings. */
export function formatGiteaEnvFiles(
  secrets: GiteaSecrets,
  usePostgres: boolean,
): {
  giteaEnv: string;
  giteaPostgresEnv?: string;
  giteaBootstrapEnv: string;
} {
  const giteaLines = [
    `GITEA__security__SECRET_KEY=${secrets.secretKey}`,
    `GITEA__security__INTERNAL_TOKEN=${secrets.internalToken}`,
    `GITEA__oauth2__JWT_SECRET=${secrets.jwtSecret}`,
    `GITEA__lfs__JWT_SECRET=${secrets.lfsJwtSecret}`,
    ...(usePostgres && secrets.postgresPassword !== undefined
      ? [`GITEA__database__PASSWD=${secrets.postgresPassword}`]
      : []),
  ];
  const postgresLines =
    usePostgres && secrets.postgresPassword !== undefined
      ? [
          "POSTGRES_DB=gitea",
          "POSTGRES_USER=gitea",
          `POSTGRES_PASSWORD=${secrets.postgresPassword}`,
        ]
      : undefined;
  const bootstrapLines = [
    `GITEA_ADMIN_PASSWORD=${secrets.adminPassword}`,
    ...(secrets.botPassword !== undefined ? [`GITEA_BOT_PASSWORD=${secrets.botPassword}`] : []),
  ];
  return {
    giteaEnv: `${giteaLines.join("\n")}\n`,
    ...(postgresLines === undefined ? {} : { giteaPostgresEnv: `${postgresLines.join("\n")}\n` }),
    giteaBootstrapEnv: `${bootstrapLines.join("\n")}\n`,
  };
}
