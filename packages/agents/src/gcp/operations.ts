/**
 * GCP operational phases (Feature 039, T3906):
 * status, logs (Cloud Logging), verify, drift, Cloud SQL backups & approval-gated restore drills,
 * out-of-band Secret Manager rotation, advise, typed destroy confirmation, and `planGcpRetarget`.
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
  type DeployPlan,
  type GcpPreset,
  type GcpTarget,
  GcpTargetSchema,
  type ProjectFacts,
  readArtifact,
} from "@opscrew/plan-schema";
import type { PhaseDeps } from "../context";
import {
  type GcpPluginOptions,
  loadGcpPlugin,
  requireGcpTarget,
  resolveGcpConnector,
} from "./loader";

export interface GcpPlanInput extends GcpPluginOptions {
  readonly plan?: DeployPlan;
}

async function resolvePlanAndTarget(
  deps: PhaseDeps,
  options: GcpPlanInput,
): Promise<{ plan: DeployPlan; target: GcpTarget }> {
  const plan = options.plan ?? (await readArtifact("plan", deps.paths.files.plan));
  const target = requireGcpTarget(plan);
  return { plan, target };
}

function gcpDbInstanceName(appName: string, environment: string): string {
  return `opscrew-${appName}-${environment}-db`.slice(0, 63);
}

export async function runGcpStatus(
  deps: PhaseDeps,
  options: GcpPlanInput = {},
): Promise<{ status: ManagedCloudStatusSummary; lines: string[] }> {
  const { plan, target } = await resolvePlanAndTarget(deps, options);
  const plugin = await loadGcpPlugin(deps, options);
  const connector = resolveGcpConnector(plugin, deps, options);
  const status = await connector.readStatus({
    appName: plan.app.name,
    environment: deps.paths.environment,
    region: target.region,
    computeKind: target.compute,
  });
  const lines = [
    `GCP ${target.preset} (${target.compute}) in ${status.region}: ${status.healthy ? "healthy" : "unhealthy"}`,
    `Compute: ${status.compute.kind} — ${status.compute.status}${status.compute.endpoint === undefined ? "" : ` (${status.compute.endpoint})`}`,
  ].map((line) => deps.redactor.redact(line));
  return { status, lines };
}

export async function runGcpLogs(
  deps: PhaseDeps,
  options: GcpPlanInput & {
    readonly serviceName?: string;
    readonly since?: Date;
    readonly limit?: number;
    readonly filterPattern?: string;
  } = {},
): Promise<{ serviceName: string; lines: readonly ManagedCloudLogLine[] }> {
  const { plan, target } = await resolvePlanAndTarget(deps, options);
  const plugin = await loadGcpPlugin(deps, options);
  const connector = resolveGcpConnector(plugin, deps, options);
  const serviceName = options.serviceName ?? `opscrew-${plan.app.name}-${deps.paths.environment}`;
  const lines = await connector.readLogs({
    logGroup: serviceName,
    region: target.region,
    computeKind: target.compute,
    ...(options.since === undefined ? {} : { since: options.since }),
    ...(options.limit === undefined ? {} : { limit: options.limit }),
    ...(options.filterPattern === undefined ? {} : { filterPattern: options.filterPattern }),
  });
  return { serviceName, lines };
}

export async function runGcpVerify(
  deps: PhaseDeps,
  options: GcpPlanInput & { readonly url?: string } = {},
): Promise<{
  readonly ok: boolean;
  readonly checks: readonly {
    readonly id: string;
    readonly ok: boolean;
    readonly detail: string;
  }[];
}> {
  const { plan, target } = await resolvePlanAndTarget(deps, options);
  const plugin = await loadGcpPlugin(deps, options);
  const connector = resolveGcpConnector(plugin, deps, options);
  const checks: Array<{ id: string; ok: boolean; detail: string }> = [];

  const identity = await connector.verifyCredentials();
  checks.push({
    id: "gcp-credentials",
    ok: identity.ok,
    detail: identity.ok
      ? `Authenticated to GCP project ${identity.accountId ?? "unknown"}`
      : deps.redactor.redact(identity.error ?? "GCP authentication failed"),
  });
  if (!identity.ok) return { ok: false, checks };

  const status = await connector.readStatus({
    appName: plan.app.name,
    environment: deps.paths.environment,
    region: target.region,
    computeKind: target.compute,
  });
  checks.push({
    id: "gcp-compute",
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
      checks.push({
        id: "gcp-https-endpoint",
        ok: response.status >= 200 && response.status < 400,
        detail: `${probeUrl} responded HTTP ${response.status}`,
      });
    } catch (error) {
      checks.push({
        id: "gcp-https-endpoint",
        ok: false,
        detail: deps.redactor.redact(
          `${probeUrl} probe failed: ${error instanceof Error ? error.message : String(error)}`,
        ),
      });
    }
  }

  return { ok: checks.every((c) => c.ok), checks };
}

export async function runGcpDrift(
  deps: PhaseDeps,
  options: GcpPlanInput & {
    readonly engine: IacEngine;
    readonly githubRepo: string;
  },
): Promise<{
  readonly driftedFiles: readonly string[];
  readonly driftedResources: number;
  readonly planSummary: PlanSummary;
}> {
  const { plan, target } = await resolvePlanAndTarget(deps, options);
  const plugin = await loadGcpPlugin(deps, options);
  const infraDir = path.resolve(deps.paths.root, plan.infra.dir);

  const secretNames = plan.app.env.filter((e) => e.secret).map((e) => e.name);
  const expectedFiles = plugin.renderHcl({
    appName: plan.app.name,
    environment: deps.paths.environment,
    target,
    ...(plan.dns.domain === undefined ? {} : { domain: plan.dns.domain }),
    dnsProvider: plan.dns.provider,
    githubRepo: options.githubRepo,
    branch: plan.cicd.branch,
    containerPort: plan.app.port,
    ...(secretNames.length > 0 ? { secretNames } : {}),
  });

  const driftedFiles: string[] = [];
  for (const file of expectedFiles) {
    const onDisk = await readTextIfExists(path.join(infraDir, file.path));
    if (onDisk !== file.content) {
      driftedFiles.push(`${plan.infra.dir}/${file.path}`);
    }
  }

  const planFile = path.join(deps.paths.stateDir, `gcp-drift-${deps.paths.environment}.tfplan`);
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

export async function runGcpSnapshotList(
  deps: PhaseDeps,
  options: GcpPlanInput = {},
): Promise<readonly ManagedCloudSnapshotEntry[]> {
  const { plan, target } = await resolvePlanAndTarget(deps, options);
  const plugin = await loadGcpPlugin(deps, options);
  const connector = resolveGcpConnector(plugin, deps, options);
  return connector.listSnapshots({
    region: target.region,
    identifierPrefix: gcpDbInstanceName(plan.app.name, deps.paths.environment),
    ...(target.components.database?.service === undefined
      ? {}
      : { service: target.components.database.service }),
  });
}

export async function runGcpSnapshotTake(
  deps: PhaseDeps,
  options: GcpPlanInput & { readonly instanceId?: string; readonly snapshotId?: string } = {},
): Promise<ManagedCloudSnapshotEntry> {
  const { plan, target } = await resolvePlanAndTarget(deps, options);
  const plugin = await loadGcpPlugin(deps, options);
  const connector = resolveGcpConnector(plugin, deps, options);
  const dbComponent = target.components.database;
  if (dbComponent === undefined) {
    throw new OpsCrewError(
      "PHASE_PRECONDITION",
      `GCP plan for ${plan.app.name} has no managed Cloud SQL database component to snapshot.`,
    );
  }
  const stamp = deps.clock
    .now()
    .toISOString()
    .replace(/[-:]/g, "")
    .replace(/\.\d+Z$/, "Z")
    .toLowerCase();
  const dbId = gcpDbInstanceName(plan.app.name, deps.paths.environment);
  return connector.takeSnapshot({
    region: target.region,
    service: dbComponent.service,
    instanceId: options.instanceId ?? dbId,
    snapshotId: options.snapshotId ?? `${dbId}-${stamp}`,
  });
}

export function gcpStandingRestoreDrillHash(input: {
  readonly app: string;
  readonly environment: string;
  readonly region: string;
  readonly drillInstanceId: string;
}): string {
  return createHash("sha256")
    .update(
      JSON.stringify({
        action: "gcp-restore-drill-standing",
        app: input.app,
        environment: input.environment,
        region: input.region,
        drillInstanceId: input.drillInstanceId,
      }),
    )
    .digest("hex");
}

export async function runGcpRestoreDrill(
  deps: PhaseDeps,
  options: GcpPlanInput & {
    readonly snapshotId?: string;
    readonly drillInstanceId?: string;
    readonly standingApprovalHash?: string;
  },
): Promise<ManagedCloudRestoreDrillResult> {
  const { plan, target } = await resolvePlanAndTarget(deps, options);
  const plugin = await loadGcpPlugin(deps, options);
  const connector = resolveGcpConnector(plugin, deps, options);
  const dbComponent = target.components.database;
  const dbId = gcpDbInstanceName(plan.app.name, deps.paths.environment);
  const defaultDrillId = `${dbId}-drill`;
  const drillInstanceId = options.drillInstanceId ?? defaultDrillId;

  if (drillInstanceId === dbId || !drillInstanceId.endsWith("-drill")) {
    throw new OpsCrewError(
      "INVALID_INPUT",
      `Refused GCP restore drill: drillInstanceId "${drillInstanceId}" must differ from source instance "${dbId}" and end with "-drill".`,
    );
  }

  let snapshotId = options.snapshotId;

  if (options.standingApprovalHash !== undefined) {
    if (options.drillInstanceId !== undefined && options.drillInstanceId !== defaultDrillId) {
      throw new OpsCrewError(
        "INVALID_INPUT",
        `Scheduled standing restore drill cannot override drillInstanceId (expected "${defaultDrillId}").`,
      );
    }
    const expectedHash = gcpStandingRestoreDrillHash({
      app: plan.app.name,
      environment: deps.paths.environment,
      region: target.region,
      drillInstanceId: defaultDrillId,
    });
    if (options.standingApprovalHash !== expectedHash) {
      throw new OpsCrewError(
        "PLAN_NOT_APPROVED",
        "Standing restore-drill approval hash does not match this app, environment, region, and fixed throwaway drill instance (ADR 0034).",
      );
    }
    await deps.approvals.assertApprovedRemoteExec(expectedHash);
    // ADR 0034: scheduled standing drill always restores ONLY the latest snapshot.
    const latestList = await connector.listSnapshots({
      region: target.region,
      identifierPrefix: dbId,
      ...(dbComponent?.service === undefined ? {} : { service: dbComponent.service }),
    });
    const latest = latestList[0];
    if (latest === undefined) {
      throw new OpsCrewError(
        "PHASE_PRECONDITION",
        `No Cloud SQL backup found for ${dbId}; cannot run scheduled restore drill.`,
      );
    }
    snapshotId = latest.id;
  } else {
    if (!snapshotId) {
      throw new OpsCrewError(
        "INVALID_INPUT",
        "snapshotId is required for an interactive GCP restore drill.",
      );
    }
    const drillHash = createHash("sha256")
      .update(
        JSON.stringify({
          action: "gcp-restore-drill",
          app: plan.app.name,
          environment: deps.paths.environment,
          region: target.region,
          snapshotId,
          drillInstanceId,
        }),
      )
      .digest("hex");
    const decision = await deps.approvals.request({
      kind: "remote-exec",
      title: `Run isolated Cloud SQL restore drill for ${plan.app.name} (${snapshotId})`,
      details: `Clones Cloud SQL backup ${snapshotId} into private throwaway instance ${drillInstanceId}, verifies RUNNABLE, and deletes it.`,
      planHash: drillHash,
    });
    if (!decision.approved) {
      throw new OpsCrewError(
        "PLAN_NOT_APPROVED",
        `GCP restore drill was not approved (${decision.reason ?? "declined"}).`,
      );
    }
    await deps.approvals.assertApprovedRemoteExec(drillHash);
  }

  return connector.runRestoreDrill({
    region: target.region,
    snapshotId,
    service: dbComponent?.service ?? "cloud-sql-postgres",
    drillInstanceId,
  });
}

export async function runGcpRotateSecrets(
  deps: PhaseDeps,
  options: GcpPlanInput & { readonly secrets: readonly ManagedCloudSecretWrite[] },
): Promise<{ readonly planHash: string; readonly written: readonly string[] }> {
  if (options.secrets.length === 0) {
    throw new OpsCrewError("INVALID_INPUT", "At least one secret must be specified to rotate.");
  }
  const { plan, target } = await resolvePlanAndTarget(deps, options);
  const plugin = await loadGcpPlugin(deps, options);
  const connector = resolveGcpConnector(plugin, deps, options);

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
    title: `Rotate ${options.secrets.length} GCP Secret Manager secret(s) for ${plan.app.name} (${target.region})`,
    details: `Out-of-band Secret Manager version update: ${options.secrets.map((s) => s.name).join(", ")}`,
    planHash,
  });
  if (!decision.approved) {
    throw new OpsCrewError(
      "PLAN_NOT_APPROVED",
      `GCP secret rotation was not approved (${decision.reason ?? "declined"}). Nothing was rotated.`,
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
    action: "gcp-rotate-secrets",
    target: planHash,
    decision: "allow",
    detail: `Rotated ${res.written.length} secret(s) out-of-band: ${res.written.join(", ")}`,
  });
  return { planHash, written: res.written };
}

export interface GcpAdviceItem {
  readonly id: string;
  readonly severity: "info" | "warn";
  readonly title: string;
  readonly detail: string;
  readonly estimatedMonthlySavingsUsd?: number;
}

export async function runGcpAdvise(
  deps: PhaseDeps,
  options: GcpPlanInput = {},
): Promise<readonly GcpAdviceItem[]> {
  const { plan, target } = await resolvePlanAndTarget(deps, options);
  const items: GcpAdviceItem[] = [];

  if (target.components.network?.config.cloudNat === true) {
    items.push({
      id: "gcp-avoid-cloud-nat",
      severity: "warn",
      title: "Avoid Cloud NAT gateway & per-GiB charges",
      detail:
        "Use Direct VPC Egress (PRIVATE_RANGES_ONLY) with `--set pins.noNat=true --set network.cloudNat=false` unless a static outbound IP is required.",
      estimatedMonthlySavingsUsd: target.components.network.monthlyCostUsd,
    });
  }
  if (target.components.database?.config.tier === "db-f1-micro" && target.preset !== "lean") {
    items.push({
      id: "gcp-cloudsql-sla",
      severity: "warn",
      title: "Cloud SQL db-f1-micro has no uptime SLA",
      detail: "Upgrade to db-custom-1-3840 (~$52/mo) for production SLA.",
    });
  }
  if (items.length === 0) {
    items.push({
      id: "gcp-posture-clean",
      severity: "info",
      title: "Google Cloud cost and security posture looks clean",
      detail: `GCP ${target.preset} (${target.compute}, ${target.region}, ~$${plan.cost.monthly.amount.toFixed(2)}/mo USD) has all default guardrails enabled.`,
    });
  }
  return items;
}

export async function runGcpDestroy(
  deps: PhaseDeps,
  options: GcpPlanInput & { readonly engine: IacEngine },
): Promise<{
  readonly planSummary: PlanSummary;
  readonly destroyed: boolean;
}> {
  const { plan, target } = await resolvePlanAndTarget(deps, options);
  const infraDir = path.resolve(deps.paths.root, plan.infra.dir);
  const planFile = path.join(deps.paths.stateDir, `gcp-destroy-${deps.paths.environment}.tfplan`);
  await mkdir(path.dirname(planFile), { recursive: true });

  await options.engine.init(infraDir, { env: deps.env });
  const planSummary = await options.engine.plan(infraDir, planFile, {
    destroy: true,
    env: deps.env,
  });
  if (planSummary.changes.length === 0) {
    deps.reporter.info("No GCP resources to destroy.");
    return { planSummary, destroyed: false };
  }

  const decision = await deps.approvals.request({
    kind: "iac-apply",
    title: `Destroy GCP deployment ${plan.app.name} in ${target.region}`,
    details: `Destroys ${planSummary.counts.delete} GCP resource(s) permanently. Type "${plan.app.name}" to confirm.`,
    planHash: planSummary.planHash,
    allowDestroy: true,
    confirmPhrase: plan.app.name,
  });
  if (!decision.approved) {
    throw new OpsCrewError(
      "DESTROY_NOT_APPROVED",
      `GCP destroy was not approved (${decision.reason ?? "declined"}). Nothing was deleted.`,
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

  deps.reporter.success(`Destroyed GCP deployment ${plan.app.name} in ${target.region}.`);
  return { planSummary, destroyed: true };
}

export async function planGcpRetarget(
  deps: PhaseDeps,
  options: GcpPluginOptions & {
    readonly currentPlan: DeployPlan;
    readonly facts: ProjectFacts;
    readonly preset?: GcpPreset;
    readonly region?: "eu-central" | "eu-north" | "us-east" | "us-west" | "ap-southeast";
  },
): Promise<{
  readonly target: GcpTarget;
  readonly estimatedMonthlyUsd: number;
  readonly steps: readonly string[];
}> {
  const plugin = await loadGcpPlugin(deps, options);
  const preset = options.preset ?? "lean";
  const requirements = {
    schemaVersion: 1,
    expectedMonthlyUsers: "1k-10k",
    budgetMonthly: {
      amount: Math.max(25, Math.ceil(options.currentPlan.cost.monthly.amount * 2)),
      currency: "USD",
    },
    provider: "gcp",
    region: options.region ?? "us-east",
    uptime: preset === "production-ha" ? "high" : "standard",
    dataCriticality: "important",
    ...(options.currentPlan.dns.domain === undefined
      ? {}
      : { domain: options.currentPlan.dns.domain }),
    dnsProvider: options.currentPlan.dns.provider,
  };
  const designed = plugin.designTarget({ facts: options.facts, requirements, preset });
  let target = GcpTargetSchema.parse(designed.target);
  let monthlyUsd = designed.estimatedMonthlyUsd;
  if (options.preset === undefined && target.compute !== "compute-engine") {
    const overridden = plugin.applyOverrides({ target, setFlags: ["compute=compute-engine"] });
    target = GcpTargetSchema.parse(overridden.target);
    monthlyUsd = overridden.afterMonthlyUsd;
  }

  return {
    target,
    estimatedMonthlyUsd: monthlyUsd,
    steps: [
      `Install GCP plugin if absent (\`opscrew plugin add gcp\`) and authenticate with Google Cloud.`,
      `Provision GCP ${target.preset} (${target.compute} in ${target.region}, ~$${monthlyUsd.toFixed(2)}/mo USD) alongside your existing ${options.currentPlan.target.provider} deployment.`,
      `Replicate data / restore latest backup into GCP and verify health via \`opscrew verify\`.`,
      `Switch DNS to GCP (keep Cloudflare \`_acme-challenge\` CNAME records DNS-only / proxied=false when using Certificate Manager).`,
      `Keep the previous ${options.currentPlan.target.provider} deployment warm until cutover is confirmed, then finish teardown.`,
    ],
  };
}
