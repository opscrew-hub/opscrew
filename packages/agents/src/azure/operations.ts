/**
 * Azure operational phases (Feature 038, T3806):
 * status, logs (Log Analytics), verify, drift, backups/restore drills (approval-gated),
 * Key Vault secret rotation (out-of-band), advise, destroy (typed confirmation + hash-bound apply),
 * and retarget --to azure (`vm-compose` bridge).
 */
import { createHash } from "node:crypto";
import { mkdir } from "node:fs/promises";
import path from "node:path";
import type {
  IacEngine,
  ManagedCloudLogLine,
  ManagedCloudRestoreDrillResult,
  ManagedCloudSecretWrite,
  ManagedCloudSnapshotEntry,
  ManagedCloudStatusSummary,
  PlanSummary,
} from "@opscrew/contracts";
import { OpsCrewError, readTextIfExists } from "@opscrew/core";
import {
  type AzurePreset,
  type AzureTarget,
  AzureTargetSchema,
  type DeployPlan,
  type ProjectFacts,
  readArtifact,
} from "@opscrew/plan-schema";
import type { PhaseDeps } from "../context";
import {
  type AzurePluginOptions,
  loadAzurePlugin,
  requireAzureTarget,
  resolveAzureConnector,
} from "./loader";

export interface AzurePlanInput extends AzurePluginOptions {
  readonly plan?: DeployPlan;
}

async function resolvePlanAndTarget(
  deps: PhaseDeps,
  options: AzurePlanInput,
): Promise<{ plan: DeployPlan; target: AzureTarget }> {
  const plan = options.plan ?? (await readArtifact("plan", deps.paths.files.plan));
  const target = requireAzureTarget(plan);
  return { plan, target };
}

function azureDbServerName(appName: string, environment: string): string {
  return `opscrew-${appName}-${environment}-db`.slice(0, 63);
}

export async function runAzureStatus(
  deps: PhaseDeps,
  options: AzurePlanInput = {},
): Promise<{ status: ManagedCloudStatusSummary; lines: string[] }> {
  const { plan, target } = await resolvePlanAndTarget(deps, options);
  const plugin = await loadAzurePlugin(deps, options);
  const connector = resolveAzureConnector(plugin, deps, options);
  const status = await connector.readStatus({
    appName: plan.app.name,
    environment: deps.paths.environment,
    region: target.region,
    computeKind: target.compute,
  });
  const lines = [
    `Azure ${target.preset} (${target.compute}) in ${status.region}: ${status.healthy ? "healthy" : "unhealthy"}`,
    `Compute: ${status.compute.kind} — ${status.compute.status}${status.compute.endpoint === undefined ? "" : ` (${status.compute.endpoint})`}`,
    ...status.services.map(
      (s) =>
        `Service ${s.name} (${s.service}): ${s.status}${s.detail === undefined ? "" : ` — ${s.detail}`}`,
    ),
  ].map((line) => deps.redactor.redact(line));
  return { status, lines };
}

export async function runAzureLogs(
  deps: PhaseDeps,
  options: AzurePlanInput & {
    readonly workspaceId?: string;
    readonly since?: Date;
    readonly limit?: number;
    readonly filterPattern?: string;
  } = {},
): Promise<{ workspaceId: string; lines: readonly ManagedCloudLogLine[] }> {
  const { plan, target } = await resolvePlanAndTarget(deps, options);
  const plugin = await loadAzurePlugin(deps, options);
  const connector = resolveAzureConnector(plugin, deps, options);
  const workspaceId =
    options.workspaceId ??
    deps.env.AZURE_LOG_ANALYTICS_WORKSPACE_ID ??
    `log-opscrew-${plan.app.name}-${deps.paths.environment}`;
  const lines = await connector.readLogs({
    logGroup: workspaceId,
    region: target.region,
    ...(options.since === undefined ? {} : { since: options.since }),
    ...(options.limit === undefined ? {} : { limit: options.limit }),
    ...(options.filterPattern === undefined ? {} : { filterPattern: options.filterPattern }),
  });
  return { workspaceId, lines };
}

export async function runAzureVerify(
  deps: PhaseDeps,
  options: AzurePlanInput & { readonly url?: string } = {},
): Promise<{
  readonly ok: boolean;
  readonly checks: readonly {
    readonly id: string;
    readonly ok: boolean;
    readonly detail: string;
  }[];
}> {
  const { plan, target } = await resolvePlanAndTarget(deps, options);
  const plugin = await loadAzurePlugin(deps, options);
  const connector = resolveAzureConnector(plugin, deps, options);
  const checks: Array<{ id: string; ok: boolean; detail: string }> = [];

  const identity = await connector.verifyCredentials();
  checks.push({
    id: "azure-credentials",
    ok: identity.ok,
    detail: identity.ok
      ? `Authenticated to Azure subscription ${identity.accountId ?? "unknown"}`
      : deps.redactor.redact(identity.error ?? "Azure authentication failed"),
  });
  if (!identity.ok) {
    return { ok: false, checks };
  }

  const status = await connector.readStatus({
    appName: plan.app.name,
    environment: deps.paths.environment,
    region: target.region,
    computeKind: target.compute,
  });
  checks.push({
    id: "azure-compute",
    ok: status.healthy,
    detail: `${status.compute.kind}: ${status.compute.status}`,
  });

  const probeUrl =
    options.url ??
    status.compute.endpoint ??
    (plan.dns.domain === undefined
      ? undefined
      : `https://${plan.dns.domain}${plan.app.healthPath ?? "/"}`);
  if (probeUrl !== undefined) {
    try {
      const response = await deps.fetch(probeUrl, { method: "GET" });
      const healthyHttp = response.status >= 200 && response.status < 400;
      checks.push({
        id: "azure-https-endpoint",
        ok: healthyHttp,
        detail: `${probeUrl} responded HTTP ${response.status}`,
      });
    } catch (error) {
      checks.push({
        id: "azure-https-endpoint",
        ok: false,
        detail: deps.redactor.redact(
          `${probeUrl} probe failed: ${error instanceof Error ? error.message : String(error)}`,
        ),
      });
    }
  }

  return { ok: checks.every((c) => c.ok), checks };
}

export async function runAzureDrift(
  deps: PhaseDeps,
  options: AzurePlanInput & {
    readonly engine: IacEngine;
    readonly githubRepo: string;
  },
): Promise<{
  readonly driftedFiles: readonly string[];
  readonly driftedResources: number;
  readonly planSummary: PlanSummary;
}> {
  const { plan, target } = await resolvePlanAndTarget(deps, options);
  const plugin = await loadAzurePlugin(deps, options);
  const infraDir = path.resolve(deps.paths.root, plan.infra.dir);

  const expectedFiles = plugin.renderHcl({
    appName: plan.app.name,
    environment: deps.paths.environment,
    target,
    ...(plan.dns.domain === undefined ? {} : { domain: plan.dns.domain }),
    dnsProvider: plan.dns.provider,
    githubRepo: options.githubRepo,
    branch: plan.cicd.branch,
    containerPort: plan.app.port,
  });

  const driftedFiles: string[] = [];
  for (const file of expectedFiles) {
    const onDisk = await readTextIfExists(path.join(infraDir, file.path));
    if (onDisk !== file.content) {
      driftedFiles.push(`${plan.infra.dir}/${file.path}`);
    }
  }

  const planFile = path.join(deps.paths.stateDir, `azure-drift-${deps.paths.environment}.tfplan`);
  await mkdir(path.dirname(planFile), { recursive: true });
  await options.engine.init(infraDir, { env: deps.env });
  const planSummary = await options.engine.plan(infraDir, planFile, {
    refreshOnly: true,
    env: deps.env,
  });

  return {
    driftedFiles,
    driftedResources: (planSummary.drift ?? []).length + planSummary.changes.length,
    planSummary,
  };
}

export async function runAzureSnapshotList(
  deps: PhaseDeps,
  options: AzurePlanInput = {},
): Promise<readonly ManagedCloudSnapshotEntry[]> {
  const { plan, target } = await resolvePlanAndTarget(deps, options);
  const plugin = await loadAzurePlugin(deps, options);
  const connector = resolveAzureConnector(plugin, deps, options);
  return connector.listSnapshots({
    region: target.region,
    identifierPrefix: azureDbServerName(plan.app.name, deps.paths.environment),
  });
}

export async function runAzureSnapshotTake(
  deps: PhaseDeps,
  options: AzurePlanInput & { readonly instanceId?: string; readonly snapshotId?: string } = {},
): Promise<ManagedCloudSnapshotEntry> {
  const { plan, target } = await resolvePlanAndTarget(deps, options);
  const plugin = await loadAzurePlugin(deps, options);
  const connector = resolveAzureConnector(plugin, deps, options);
  const dbComponent = target.components.database;
  if (dbComponent === undefined) {
    throw new OpsCrewError(
      "PHASE_PRECONDITION",
      `Azure plan for ${plan.app.name} has no managed database component to snapshot.`,
    );
  }
  const stamp = deps.clock
    .now()
    .toISOString()
    .replace(/[-:]/g, "")
    .replace(/\.\d+Z$/, "Z")
    .toLowerCase();
  const dbId = azureDbServerName(plan.app.name, deps.paths.environment);
  return connector.takeSnapshot({
    region: target.region,
    service: dbComponent.service,
    instanceId: options.instanceId ?? dbId,
    snapshotId: options.snapshotId ?? `${dbId}-${stamp}`,
  });
}

/**
 * Runs an isolated private PITR restore drill for Azure Flexible Server (ADR 0034).
 * Always enforces SHA-256 plan-hash approval via `ApprovalGate`: either a fresh per-run approval
 * or a pre-installed scheduled standing approval verified by `standingApprovalHash`.
 */
export async function runAzureRestoreDrill(
  deps: PhaseDeps,
  options: AzurePlanInput & {
    readonly snapshotId: string;
    readonly drillInstanceId?: string;
    readonly delegatedSubnetId?: string;
    readonly standingApprovalHash?: string;
  },
): Promise<ManagedCloudRestoreDrillResult> {
  const { plan, target } = await resolvePlanAndTarget(deps, options);
  const plugin = await loadAzurePlugin(deps, options);
  const connector = resolveAzureConnector(plugin, deps, options);
  const dbComponent = target.components.database;
  const dbId = azureDbServerName(plan.app.name, deps.paths.environment);
  const drillInstanceId = options.drillInstanceId ?? `${dbId}-drill`;

  if (options.standingApprovalHash !== undefined) {
    await deps.approvals.assertApprovedRemoteExec(options.standingApprovalHash);
  } else {
    const drillHash = createHash("sha256")
      .update(
        JSON.stringify({
          action: "azure-restore-drill",
          app: plan.app.name,
          environment: deps.paths.environment,
          region: target.region,
          snapshotId: options.snapshotId,
          drillInstanceId,
          delegatedSubnetId: options.delegatedSubnetId ?? null,
        }),
      )
      .digest("hex");
    const decision = await deps.approvals.request({
      kind: "remote-exec",
      title: `Run isolated Azure PITR restore drill for ${plan.app.name} (${options.snapshotId})`,
      details: `Restores point-in-time backup ${options.snapshotId} into private throwaway Flexible Server ${drillInstanceId} (publicNetworkAccess=Disabled), verifies Ready, and deletes it.`,
      planHash: drillHash,
    });
    if (!decision.approved) {
      throw new OpsCrewError(
        "PLAN_NOT_APPROVED",
        `Azure restore drill was not approved (${decision.reason ?? "declined"}).`,
      );
    }
    await deps.approvals.assertApprovedRemoteExec(drillHash);
  }

  return connector.runRestoreDrill({
    region: target.region,
    snapshotId: options.snapshotId,
    service: dbComponent?.service ?? "flexible-postgres",
    drillInstanceId,
    ...(options.delegatedSubnetId === undefined
      ? {}
      : { dbSubnetGroupName: options.delegatedSubnetId }),
  });
}

export async function runAzureRotateSecrets(
  deps: PhaseDeps,
  options: AzurePlanInput & { readonly secrets: readonly ManagedCloudSecretWrite[] },
): Promise<{ readonly planHash: string; readonly written: readonly string[] }> {
  if (options.secrets.length === 0) {
    throw new OpsCrewError("INVALID_INPUT", "At least one secret must be specified to rotate.");
  }
  const { plan, target } = await resolvePlanAndTarget(deps, options);
  const plugin = await loadAzurePlugin(deps, options);
  const connector = resolveAzureConnector(plugin, deps, options);

  const canonical = JSON.stringify({
    app: plan.app.name,
    environment: deps.paths.environment,
    region: target.region,
    secrets: [...options.secrets]
      .map((s) => ({ store: s.store, name: s.name }))
      .sort((a, b) => a.name.localeCompare(b.name)),
  });
  const planHash = createHash("sha256").update(canonical).digest("hex");

  const decision = await deps.approvals.request({
    kind: "remote-exec",
    title: `Rotate ${options.secrets.length} Azure Key Vault secret(s) for ${plan.app.name} (${target.region})`,
    details: `Out-of-band update in Azure Key Vault: ${options.secrets.map((s) => s.name).join(", ")}`,
    planHash,
  });
  if (!decision.approved) {
    throw new OpsCrewError(
      "PLAN_NOT_APPROVED",
      `Azure secret rotation was not approved (${decision.reason ?? "declined"}). Nothing was rotated.`,
    );
  }
  await deps.approvals.assertApprovedRemoteExec(planHash);

  const res = await connector.writeSecrets({
    region: target.region,
    secrets: options.secrets,
  });
  await deps.audit.append({
    at: deps.clock.now().toISOString(),
    kind: "secret-set",
    actor: "opscrew",
    action: "azure-rotate-secrets",
    target: planHash,
    decision: "allow",
    detail: `Rotated ${res.written.length} secret(s) out-of-band: ${res.written.join(", ")}`,
  });
  return { planHash, written: res.written };
}

export interface AzureAdviceItem {
  readonly id: string;
  readonly severity: "info" | "warn";
  readonly title: string;
  readonly detail: string;
  readonly estimatedMonthlySavingsUsd?: number;
}

export async function runAzureAdvise(
  deps: PhaseDeps,
  options: AzurePlanInput = {},
): Promise<readonly AzureAdviceItem[]> {
  const { plan, target } = await resolvePlanAndTarget(deps, options);
  const items: AzureAdviceItem[] = [];

  if (target.components.network?.config.natGateway === true) {
    items.push({
      id: "azure-avoid-nat-gateway",
      severity: "warn",
      title: "Avoid Azure NAT Gateway fixed monthly cost",
      detail:
        "Azure NAT Gateway adds ~$37/mo fixed cost. Set `--set pins.noNat=true --set network.natGateway=false` unless a static outbound IP is mandatory.",
      estimatedMonthlySavingsUsd: target.components.network.monthlyCostUsd,
    });
  }

  if (target.components.edge?.service === "azure-front-door" && target.preset !== "production-ha") {
    items.push({
      id: "azure-avoid-front-door",
      severity: "warn",
      title: "Avoid Azure Front Door base fee on non-HA plans",
      detail:
        "Azure Front Door Standard adds ~$35/mo base cost. Keep Cloudflare or built-in Container Apps TLS (`--set pins.noFrontDoor=true`).",
      estimatedMonthlySavingsUsd: target.components.edge.monthlyCostUsd,
    });
  }

  if (
    target.pins.budgetCapUsd !== undefined &&
    plan.cost.monthly.amount > target.pins.budgetCapUsd
  ) {
    items.push({
      id: "azure-over-budget",
      severity: "warn",
      title: "Estimated Azure monthly cost exceeds budget cap",
      detail: `Estimated $${plan.cost.monthly.amount.toFixed(2)}/mo exceeds pinned budget cap of $${target.pins.budgetCapUsd.toFixed(2)}/mo.`,
    });
  }

  if (target.exceptions.length > 0) {
    items.push({
      id: "azure-guardrail-exceptions",
      severity: "warn",
      title: `${target.exceptions.length} active Azure guardrail exception(s)`,
      detail: `Review exceptions: ${target.exceptions.map((e) => `${e.guardrail} (${e.reason})`).join("; ")}.`,
    });
  }

  if (items.length === 0) {
    items.push({
      id: "azure-posture-clean",
      severity: "info",
      title: "Azure cost and security posture looks clean",
      detail: `Azure ${target.preset} (${target.compute}, ${target.region}, ~$${plan.cost.monthly.amount.toFixed(2)}/mo USD) has all default guardrails enabled and no active cost traps.`,
    });
  }

  return items;
}

export async function runAzureDestroy(
  deps: PhaseDeps,
  options: AzurePlanInput & { readonly engine: IacEngine },
): Promise<{
  readonly planSummary: PlanSummary;
  readonly destroyed: boolean;
}> {
  const { plan, target } = await resolvePlanAndTarget(deps, options);
  const infraDir = path.resolve(deps.paths.root, plan.infra.dir);
  const planFile = path.join(deps.paths.stateDir, `azure-destroy-${deps.paths.environment}.tfplan`);
  await mkdir(path.dirname(planFile), { recursive: true });

  await options.engine.init(infraDir, { env: deps.env });
  const planSummary = await options.engine.plan(infraDir, planFile, {
    destroy: true,
    env: deps.env,
  });

  if (planSummary.changes.length === 0) {
    deps.reporter.info("No Azure resources to destroy.");
    return { planSummary, destroyed: false };
  }

  const decision = await deps.approvals.request({
    kind: "iac-apply",
    title: `Destroy Azure deployment ${plan.app.name} in ${target.region}`,
    details: `Destroys ${planSummary.counts.delete} Azure resource(s) permanently. Type "${plan.app.name}" to confirm.`,
    planHash: planSummary.planHash,
    allowDestroy: true,
    confirmPhrase: plan.app.name,
  });
  if (!decision.approved) {
    throw new OpsCrewError(
      "DESTROY_NOT_APPROVED",
      `Azure destroy was not approved (${decision.reason ?? "declined"}). Nothing was deleted.`,
    );
  }
  await deps.approvals.assertApprovedPlan(planSummary.planHash, { allowDestroy: true });

  await options.engine.apply(
    infraDir,
    planFile,
    {
      approvedPlanHash: planSummary.planHash,
      allowDestroy: true,
    },
    { env: deps.env },
  );

  deps.reporter.success(`Destroyed Azure deployment ${plan.app.name} in ${target.region}.`);
  return { planSummary, destroyed: true };
}

export async function planAzureRetarget(
  deps: PhaseDeps,
  options: AzurePluginOptions & {
    readonly currentPlan: DeployPlan;
    readonly facts: ProjectFacts;
    readonly preset?: AzurePreset;
    readonly region?: "eu-central" | "eu-north" | "us-east" | "us-west" | "ap-southeast";
  },
): Promise<{
  readonly target: AzureTarget;
  readonly estimatedMonthlyUsd: number;
  readonly steps: readonly string[];
}> {
  const plugin = await loadAzurePlugin(deps, options);
  const preset = options.preset ?? "lean";
  const requirements = {
    schemaVersion: 1,
    expectedMonthlyUsers: "1k-10k",
    budgetMonthly: {
      amount: Math.max(25, Math.ceil(options.currentPlan.cost.monthly.amount * 2)),
      currency: "USD",
    },
    provider: "azure",
    region: options.region ?? "eu-central",
    uptime: preset === "production-ha" ? "high" : "standard",
    dataCriticality: "important",
    ...(options.currentPlan.dns.domain === undefined
      ? {}
      : { domain: options.currentPlan.dns.domain }),
    dnsProvider: options.currentPlan.dns.provider,
  };
  const designed = plugin.designTarget({
    facts: options.facts,
    requirements,
    preset,
  });
  let target = AzureTargetSchema.parse(designed.target);
  let monthlyUsd = designed.estimatedMonthlyUsd;
  if (options.preset === undefined && target.compute !== "vm-compose") {
    const overridden = plugin.applyOverrides({
      target,
      setFlags: ["compute=vm-compose"],
    });
    target = AzureTargetSchema.parse(overridden.target);
    monthlyUsd = overridden.afterMonthlyUsd;
  }

  return {
    target,
    estimatedMonthlyUsd: monthlyUsd,
    steps: [
      `Install Azure plugin if absent (\`opscrew plugin add azure\`) and authenticate Azure credentials.`,
      `Provision Azure ${target.preset} (${target.compute} in ${target.region}, ~$${monthlyUsd.toFixed(2)}/mo USD) alongside your existing ${options.currentPlan.target.provider} deployment.`,
      `Replicate data / restore latest snapshot into Azure and verify health via \`opscrew verify\`.`,
      `Switch DNS to the Azure endpoint (keep Cloudflare \`asuid\` TXT validation record DNS-only / proxied=false).`,
      `Keep the previous ${options.currentPlan.target.provider} deployment warm until cutover is confirmed, then finish teardown.`,
    ],
  };
}
