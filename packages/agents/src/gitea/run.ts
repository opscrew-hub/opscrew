import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import {
  applyHostPlan,
  GITEA_HOST_PROJECT,
  giteaHostDir,
  type HostPlan,
  hostPlanHash,
  planGitea,
} from "@opscrew/connector-ssh-host";
import type { PolicyResult, RemoteExec } from "@opscrew/contracts";
import { canonicalJson, exists, OpsCrewError, writeFileAtomic } from "@opscrew/core";
import {
  edgeProxy,
  GITEA_BOT_USER,
  type GiteaAppConnectionSpec,
  giteaAppIntegration,
  giteaBootstrapScript,
  renderGiteaCompose,
  renderGiteaProxySite,
} from "@opscrew/iac-templates";
import { type DeployPlan, type GiteaSettings, giteaOf, writeArtifact } from "@opscrew/plan-schema";
import { blockingPolicyFailures, evaluateGiteaPolicies } from "@opscrew/secops";
import { ADDON_PHASE } from "../addons/settings";
import { deployUserShell } from "../addons/status";
import type { PhaseDeps } from "../context";
import { commandFlags } from "../environments/choice";
import { refusedBeforeChange } from "../previews/host";
import { type OtherAppsServices, requireNoOtherApps } from "../shares/guard";
import {
  ensureGiteaSecrets,
  formatGiteaEnvFiles,
  registerGiteaSecrets,
  removeGiteaSecrets,
  writeGiteaSecrets,
} from "./secrets";
import { type GiteaEnableRequest, giteaSettings, requireGiteaTarget, withGitea } from "./settings";

/** Injectable collaborators for self-hosted Gitea commands (fakes in tests). */
export interface GiteaServices {
  /** Remote shell on the app's server (default: SSH via `appServerShell`). */
  remote?: RemoteExec;
  /** Shared-server other-apps inspection collaborator (tests). */
  otherApps?: OtherAppsServices;
}

export interface GiteaEnableOptions extends GiteaEnableRequest {
  planOnly?: boolean;
  /** `--skip-other-apps-check`: go on when OpsCrew can't check a cloud server for other apps. */
  skipOtherAppsCheck?: boolean;
  services?: GiteaServices;
}

export interface GiteaDisableOptions {
  /** Keep Gitea's Docker data volumes (default `true`). `false` requires destroy confirmation. */
  keepData?: boolean;
  planOnly?: boolean;
  /** `--skip-other-apps-check`: go on when OpsCrew can't check a cloud server for other apps. */
  skipOtherAppsCheck?: boolean;
  services?: GiteaServices;
}

/** Secret-free status summary for self-hosted Gitea (`opscrew addon status`). */
export interface GiteaStatus {
  enabled: boolean;
  version?: string;
  hostname?: string;
  url?: string;
  apiUrl?: string;
  database?: "sqlite" | "postgres";
  adminUser?: string;
  disableRegistration?: boolean;
  sshEnabled?: boolean;
  sshPort?: number;
  secretsFileExists: boolean;
  connection?: GiteaAppConnectionSpec;
}

/** Result of enabling or disabling self-hosted Gitea (never contains secrets). */
export interface GiteaResult {
  hostPlanHash: string;
  hostApplied: boolean;
  policies: PolicyResult[];
  files: string[];
  status: GiteaStatus;
  connection?: GiteaAppConnectionSpec;
  approveCommand: string;
}

/** Saves a host plan JSON under `.opscrew/plans/host-<hash>.json` so CLI/MCP can reference it. */
async function saveHostPlan(deps: PhaseDeps, plan: HostPlan, hash: string): Promise<void> {
  await mkdir(deps.paths.files.plansDir, { recursive: true });
  await writeFileAtomic(
    join(deps.paths.files.plansDir, `host-${hash}.json`),
    `${canonicalJson(plan)}\n`,
  );
}

/** Resolves the server shell (`options.services.remote` in tests, real SSH in production). */
async function serverShell(
  deps: PhaseDeps,
  plan: DeployPlan,
  services?: GiteaServices,
): Promise<RemoteExec> {
  if (services?.remote !== undefined) return services.remote;
  return deployUserShell(deps, plan, {});
}

/** Read-only, secret-free status of self-hosted Gitea from the plan and local state. */
export async function giteaStatusOf(
  deps: Pick<PhaseDeps, "paths">,
  plan: DeployPlan,
): Promise<GiteaStatus> {
  const gitea = giteaOf(plan);
  const secretsFileExists = await exists(deps.paths.files.giteaSecrets);
  if (gitea === undefined) {
    return { enabled: false, secretsFileExists };
  }
  const connection = giteaAppIntegration(plan, gitea);
  return {
    enabled: true,
    version: gitea.version,
    hostname: gitea.hostname,
    url: connection.url,
    apiUrl: connection.apiUrl,
    database: gitea.database,
    adminUser: gitea.adminUser,
    disableRegistration: gitea.disableRegistration,
    sshEnabled: gitea.ssh.enabled,
    sshPort: gitea.ssh.port,
    secretsFileExists,
    connection,
  };
}

/** Plain-English status summary for CLI & MCP (never contains secrets). */
export function describeGiteaStatus(status: GiteaStatus): string {
  if (!status.enabled) {
    return status.secretsFileExists
      ? "Self-hosted Gitea: off (local secrets file kept; run `opscrew addon enable gitea` to re-enable)."
      : "Self-hosted Gitea: off.";
  }
  const lines = [
    `Self-hosted Gitea: on (v${status.version}, ${status.database}, ${status.url})`,
    `  Registration: ${status.disableRegistration ? "disabled (hardened)" : "ENABLED (open sign-ups)"}`,
    `  Git SSH: ${status.sshEnabled ? `enabled on port ${status.sshPort}` : "disabled (HTTPS only)"}`,
    `  API base URL: ${status.apiUrl} (Authorization: token $GITEA_API_TOKEN, bot user ${GITEA_BOT_USER})`,
  ];
  if (status.connection !== undefined) {
    lines.push(
      `  App token scopes: ${status.connection.tokenScopes.join(", ")}`,
      `  Webhook header: ${status.connection.webhook.signatureHeader} (HMAC-SHA256 hex, env GITEA_WEBHOOK_SECRET)`,
    );
    if (status.connection.webhook.targetUrl !== undefined) {
      lines.push(`  Webhook target URL: ${status.connection.webhook.targetUrl}`);
    }
  }
  return lines.join("\n");
}

/** ADR 0035 shared-server guard: refuses running/removing singleton Gitea on a shared server. */
async function requireExclusiveGiteaServer(
  deps: PhaseDeps,
  plan: DeployPlan,
  flag: string,
  command: string,
  actionText: string,
  options: { skipOtherAppsCheck?: boolean; services?: GiteaServices },
): Promise<void> {
  const first = plan.target.provider === "own" ? plan.target.shares?.app : undefined;
  if (first !== undefined) {
    throw refusedBeforeChange(
      "PHASE_PRECONDITION",
      `This app shares the server OpsCrew created for "${first}", and self-hosted Gitea is a server-wide instance owned by "${first}".`,
      `Manage self-hosted Gitea from "${first}"'s repository, or move this app to its own server with \`opscrew retarget${flag}\`.`,
    );
  }
  await requireNoOtherApps(deps, plan, actionText, command, {
    ...(options.skipOtherAppsCheck === undefined ? {} : { skip: options.skipOtherAppsCheck }),
    ...(options.services?.otherApps === undefined ? {} : { services: options.services.otherApps }),
  });
}

function buildEnableCommand(flag: string, gitea: GiteaSettings): string {
  return [
    `opscrew addon enable gitea${flag}`,
    `--hostname ${gitea.hostname}`,
    `--admin-email ${gitea.adminEmail}`,
    ...(gitea.database === "postgres" ? ["--database postgres"] : []),
    ...(gitea.appIntegration.webhook?.path !== undefined
      ? [`--webhook-path ${gitea.appIntegration.webhook.path}`]
      : []),
  ].join(" ");
}

/**
 * Enables or updates self-hosted Gitea under OpsCrew's safety gate:
 * validate settings -> render hardened Compose & edge proxy site -> run SecOps policies (block on
 * critical/high) -> generate/register 0600 secrets -> build hash-bound HostPlan -> request
 * human `host-apply` approval -> apply with secrets via stdin -> write `opscrew/plan.yaml`.
 */
export async function giteaEnable(
  deps: PhaseDeps,
  plan: DeployPlan,
  options: GiteaEnableOptions = {},
): Promise<GiteaResult> {
  const flag = await commandFlags(deps.paths.root, deps.paths.environment, deps.paths.app);
  const command = `opscrew addon enable gitea${flag}`;
  requireGiteaTarget(plan, command);
  await requireExclusiveGiteaServer(
    deps,
    plan,
    flag,
    command,
    "running self-hosted Gitea on the server",
    options,
  );

  const settings = giteaSettings(plan, options);
  const after = withGitea(plan, settings);
  const proxy = edgeProxy(after);
  const composeYaml = renderGiteaCompose(after, settings);
  const proxyFiles = renderGiteaProxySite(after, settings, { acmeEmail: settings.adminEmail });
  const bootstrapScript = giteaBootstrapScript(settings);
  const connection = giteaAppIntegration(after, settings);

  // Run SecOps policy gate before generating secrets or asking for approval.
  const policies = evaluateGiteaPolicies(after, { composeYaml, proxyFiles });
  const blockers = blockingPolicyFailures(policies);
  if (blockers.length > 0) {
    throw new OpsCrewError(
      "PHASE_PRECONDITION",
      `Self-hosted Gitea failed ${blockers.length} security policy ${blockers.length === 1 ? "check" : "checks"}: ${blockers.map((b) => `${b.policyId} (${b.message})`).join("; ")}. Nothing was changed.`,
      {
        hint: "Keep registration disabled, avoid exposing port 3000, use a pinned rootless image, and keep webhook hosts restricted.",
      },
    );
  }

  const runAs: "root" | "login" = after.target.provider === "own" ? "root" : "login";
  const hostPlan = planGitea({
    app: after.app.name,
    runAs,
    enable: {
      composeYaml,
      proxy,
      proxyFiles,
      bootstrapScript,
      usePostgres: settings.database === "postgres",
      appIntegrationEnabled: settings.appIntegration.enabled,
      hostname: settings.hostname,
      version: settings.version,
    },
  });
  const hash = hostPlanHash(hostPlan);
  await saveHostPlan(deps, hostPlan, hash);
  const approveCommand = buildEnableCommand(flag, settings);

  if (options.planOnly === true) {
    return {
      hostPlanHash: hash,
      hostApplied: false,
      policies,
      files: [],
      status: await giteaStatusOf(deps, plan),
      connection,
      approveCommand,
    };
  }

  const approval = await deps.approvals.request({
    kind: "host-apply",
    planHash: hash,
    policy: policies,
    title: `Deploy self-hosted Gitea ${settings.version} at https://${settings.hostname}/`,
    details: [
      `Target: ${after.target.provider} (${proxy} reverse proxy)`,
      `Database: ${settings.database}`,
      `Public registration: ${settings.disableRegistration ? "disabled" : "enabled"}`,
      `Git SSH: ${settings.ssh.enabled ? `port ${settings.ssh.port}` : "disabled (HTTPS only)"}`,
      `App token scopes: ${settings.appIntegration.tokenScopes.join(", ")}`,
      `Host plan SHA-256: ${hash}`,
    ].join("\n"),
  });
  if (!approval.approved) {
    throw new OpsCrewError(
      "APPROVAL_REFUSED",
      "Self-hosted Gitea host plan was not approved. Nothing was changed.",
      { hint: `Run \`${approveCommand} --approve ${hash}\` to approve this exact plan.` },
    );
  }

  const secrets = await ensureGiteaSecrets(deps, settings.database === "postgres");
  const envSecrets = formatGiteaEnvFiles(secrets, settings.database === "postgres");
  const remote = await serverShell(deps, after, options.services);

  const result = await applyHostPlan(remote, hostPlan, {
    approvedHash: hash,
    command,
    secrets: envSecrets,
    verifyLogin: async () => true,
  });

  // Capture the newly bootstrapped non-admin bot token from the server into 0600 local
  // gitea_secrets.json (included in `opscrew secrets backup`) and register it with the redactor.
  if (settings.appIntegration.enabled) {
    const tokenFile = `${giteaHostDir(runAs)}/.app-token`;
    const readRes = await remote
      .run(`if [ -s '${tokenFile}' ]; then cat '${tokenFile}'; fi`, { timeoutMs: 30_000 })
      .catch(() => ({ exitCode: 1, stdout: "", stderr: "" }));
    const captured = readRes.exitCode === 0 ? readRes.stdout.trim() : "";
    if (captured.length >= 16 && !/\s/.test(captured)) {
      const updated = registerGiteaSecrets(deps.redactor, { ...secrets, appApiToken: captured });
      await writeGiteaSecrets(deps.paths, updated);
    }
    deps.reporter.info(
      [
        `Gitea app integration secrets are saved locally (mode 0600) in ${deps.paths.files.giteaSecrets}.`,
        `OpsCrew does not automatically inject Gitea variables into your running app or create webhooks in Gitea.`,
        `To connect your app, wire ${connection.envVars.url} (${connection.url}), ${connection.envVars.apiUrl} (${connection.apiUrl}), ${connection.envVars.token}, and ${connection.envVars.webhookSecret} via \`opscrew values set${flag}\` (or your app's .env), and configure the webhook in Gitea using the HMAC secret stored in ${deps.paths.files.giteaSecrets}.`,
      ].join("\n"),
    );
  }

  await writeArtifact("plan", deps.paths.files.plan, after);
  await deps.audit.append({
    kind: "remote-exec",
    actor: "opscrew",
    action: "enable self-hosted Gitea",
    phase: ADDON_PHASE,
    target: `${ADDON_PHASE}:gitea`,
    decision: "approved",
    detail: `planHash=${hash} hostname=${settings.hostname} database=${settings.database} version=${settings.version}`,
  });

  return {
    hostPlanHash: hash,
    hostApplied: result.applied.length > 0,
    policies,
    files: ["opscrew/plan.yaml"],
    status: await giteaStatusOf(deps, after),
    connection,
    approveCommand,
  };
}

/**
 * Disables self-hosted Gitea under OpsCrew's safety gate. Keeps Docker volumes by default
 * (`keepData: true`); setting `keepData: false` triggers a destroy-grade `allowDestroy` approval
 * requiring typed confirmation of the app name.
 */
export async function giteaDisable(
  deps: PhaseDeps,
  plan: DeployPlan,
  options: GiteaDisableOptions = {},
): Promise<GiteaResult> {
  const flag = await commandFlags(deps.paths.root, deps.paths.environment, deps.paths.app);
  const keepData = options.keepData !== false;
  const command = `opscrew addon disable gitea${flag}${keepData ? "" : " --delete-data"}`;
  requireGiteaTarget(plan, command);
  await requireExclusiveGiteaServer(
    deps,
    plan,
    flag,
    command,
    "removing self-hosted Gitea on the server",
    options,
  );

  const proxy = edgeProxy(plan);
  const runAs: "root" | "login" = plan.target.provider === "own" ? "root" : "login";
  const hostPlan = planGitea({
    app: plan.app.name,
    runAs,
    disable: { proxy, keepData },
  });
  const hash = hostPlanHash(hostPlan);
  await saveHostPlan(deps, hostPlan, hash);

  if (options.planOnly === true) {
    return {
      hostPlanHash: hash,
      hostApplied: false,
      policies: [],
      files: [],
      status: await giteaStatusOf(deps, plan),
      approveCommand: command,
    };
  }

  // Constitution I: destructive teardown confirms by resource name (hostname or opscrew-gitea).
  const confirmResource = plan.gitea?.hostname ?? GITEA_HOST_PROJECT;
  const approval = await deps.approvals.request({
    kind: "host-apply",
    planHash: hash,
    title: keepData
      ? `Stop and remove self-hosted Gitea containers and proxy route (keep data volumes)`
      : `Destroy self-hosted Gitea containers, proxy route, AND all repositories/database volumes`,
    details: [
      `App: ${plan.app.name}`,
      `Resource: ${confirmResource}`,
      `Data volumes: ${keepData ? "kept on server" : "PERMANENTLY DELETED"}`,
      `Host plan SHA-256: ${hash}`,
    ].join("\n"),
    ...(!keepData ? { allowDestroy: true, confirmPhrase: confirmResource } : {}),
  });
  if (!approval.approved) {
    throw new OpsCrewError(
      "APPROVAL_REFUSED",
      "Self-hosted Gitea removal was not approved. Nothing was changed.",
      { hint: `Run \`${command} --approve ${hash}\` to approve this exact plan.` },
    );
  }

  const remote = await serverShell(deps, plan, options.services);
  const result = await applyHostPlan(remote, hostPlan, {
    approvedHash: hash,
    command,
    verifyLogin: async () => true,
  });

  if (!keepData) {
    await removeGiteaSecrets(deps.paths);
  }
  const after = withGitea(plan, undefined);
  await writeArtifact("plan", deps.paths.files.plan, after);
  await deps.audit.append({
    kind: "remote-exec",
    actor: "opscrew",
    action: keepData
      ? "disable self-hosted Gitea (keep data)"
      : "destroy self-hosted Gitea and data",
    phase: ADDON_PHASE,
    target: `${ADDON_PHASE}:gitea`,
    decision: "approved",
    detail: `planHash=${hash} keepData=${keepData}`,
  });

  return {
    hostPlanHash: hash,
    hostApplied: result.applied.length > 0,
    policies: [],
    files: ["opscrew/plan.yaml"],
    status: await giteaStatusOf(deps, after),
    approveCommand: command,
  };
}
