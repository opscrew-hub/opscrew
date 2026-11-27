/**
 * AWS operational phases (Feature 034, T3409):
 * status, logs (CloudWatch), verify, drift, snapshot/restore drills, rotate (out-of-band),
 * advise, destroy (typed confirmation + hash-bound apply), and retarget --to aws (`ec2-compose`).
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
  type AwsPreset,
  type AwsTarget,
  AwsTargetSchema,
  type DeployPlan,
  type ProjectFacts,
  readArtifact,
} from "@opscrew/plan-schema";
import type { PhaseDeps } from "../context";
import {
  type AwsPluginOptions,
  loadAwsPlugin,
  requireAwsTarget,
  resolveAwsConnector,
} from "./loader";

export interface AwsPlanInput extends AwsPluginOptions {
  readonly plan?: DeployPlan;
}

async function resolvePlanAndTarget(
  deps: PhaseDeps,
  options: AwsPlanInput,
): Promise<{ plan: DeployPlan; target: AwsTarget }> {
  const plan = options.plan ?? (await readArtifact("plan", deps.paths.files.plan));
  const target = requireAwsTarget(plan);
  return { plan, target };
}

/** `opscrew status` for AWS targets: compute health, managed services, and CloudWatch alarms. */
export async function runAwsStatus(
  deps: PhaseDeps,
  options: AwsPlanInput = {},
): Promise<{ status: ManagedCloudStatusSummary; lines: string[] }> {
  const { plan, target } = await resolvePlanAndTarget(deps, options);
  const plugin = await loadAwsPlugin(deps, options);
  const connector = resolveAwsConnector(plugin, deps, options);
  const status = await connector.readStatus({
    appName: plan.app.name,
    environment: deps.paths.environment,
    region: target.region,
    computeKind: target.compute,
  });
  const lines = [
    `AWS ${target.preset} (${target.compute}) in ${status.region}: ${status.healthy ? "healthy" : "unhealthy"}`,
    `Compute: ${status.compute.kind} — ${status.compute.status}${status.compute.runningCount === undefined ? "" : ` (${status.compute.runningCount}/${status.compute.desiredCount ?? status.compute.runningCount} running)`}`,
    ...status.services.map(
      (s) =>
        `Service ${s.name} (${s.service}): ${s.status}${s.detail === undefined ? "" : ` — ${s.detail}`}`,
    ),
    ...(status.alarms ?? []).map(
      (a) => `Alarm ${a.name}: ${a.state}${a.reason === undefined ? "" : ` — ${a.reason}`}`,
    ),
  ].map((line) => deps.redactor.redact(line));
  return { status, lines };
}

/** `opscrew logs` for AWS targets: reads redacted CloudWatch Logs. */
export async function runAwsLogs(
  deps: PhaseDeps,
  options: AwsPlanInput & {
    readonly logGroup?: string;
    readonly since?: Date;
    readonly limit?: number;
    readonly filterPattern?: string;
  } = {},
): Promise<{ logGroup: string; lines: readonly ManagedCloudLogLine[] }> {
  const { plan, target } = await resolvePlanAndTarget(deps, options);
  const plugin = await loadAwsPlugin(deps, options);
  const connector = resolveAwsConnector(plugin, deps, options);
  const logGroup = options.logGroup ?? `/opscrew/${plan.app.name}/${deps.paths.environment}`;
  const lines = await connector.readLogs({
    logGroup,
    region: target.region,
    ...(options.since === undefined ? {} : { since: options.since }),
    ...(options.limit === undefined ? {} : { limit: options.limit }),
    ...(options.filterPattern === undefined ? {} : { filterPattern: options.filterPattern }),
  });
  return { logGroup, lines };
}

/** `opscrew verify` for AWS targets: checks credentials, compute health, alarms, and HTTPS endpoint. */
export async function runAwsVerify(
  deps: PhaseDeps,
  options: AwsPlanInput & { readonly url?: string } = {},
): Promise<{
  readonly ok: boolean;
  readonly checks: readonly {
    readonly id: string;
    readonly ok: boolean;
    readonly detail: string;
  }[];
}> {
  const { plan, target } = await resolvePlanAndTarget(deps, options);
  const plugin = await loadAwsPlugin(deps, options);
  const connector = resolveAwsConnector(plugin, deps, options);
  const checks: Array<{ id: string; ok: boolean; detail: string }> = [];

  const identity = await connector.verifyCredentials();
  checks.push({
    id: "aws-credentials",
    ok: identity.ok,
    detail: identity.ok
      ? `Authenticated to AWS account ${identity.accountId ?? "unknown"}`
      : deps.redactor.redact(identity.error ?? "AWS authentication failed"),
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
    id: "aws-compute",
    ok: status.healthy,
    detail: `${status.compute.kind}: ${status.compute.status}`,
  });

  const firingAlarms = (status.alarms ?? []).filter((a) => a.state === "ALARM");
  checks.push({
    id: "aws-alarms",
    ok: firingAlarms.length === 0,
    detail:
      firingAlarms.length === 0
        ? "No CloudWatch alarms firing"
        : `Alarms firing: ${firingAlarms.map((a) => a.name).join(", ")}`,
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
        id: "aws-https-endpoint",
        ok: healthyHttp,
        detail: `${probeUrl} responded HTTP ${response.status}`,
      });
    } catch (error) {
      checks.push({
        id: "aws-https-endpoint",
        ok: false,
        detail: deps.redactor.redact(
          `${probeUrl} probe failed: ${error instanceof Error ? error.message : String(error)}`,
        ),
      });
    }
  }

  return { ok: checks.every((c) => c.ok), checks };
}

/** `opscrew drift` for AWS targets: checks rendered HCL/workflow files + live OpenTofu refresh-only plan. */
export async function runAwsDrift(
  deps: PhaseDeps,
  options: AwsPlanInput & {
    readonly engine: IacEngine;
    readonly githubRepo: string;
    readonly endpointUrl?: string;
  },
): Promise<{
  readonly driftedFiles: readonly string[];
  readonly driftedResources: number;
  readonly planSummary: PlanSummary;
}> {
  const { plan, target } = await resolvePlanAndTarget(deps, options);
  const plugin = await loadAwsPlugin(deps, options);
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
    ...(options.endpointUrl === undefined ? {} : { endpointUrl: options.endpointUrl }),
  });

  const driftedFiles: string[] = [];
  for (const file of expectedFiles) {
    const onDisk = await readTextIfExists(path.join(infraDir, file.path));
    if (onDisk !== file.content) {
      driftedFiles.push(`${plan.infra.dir}/${file.path}`);
    }
  }

  const planFile = path.join(deps.paths.stateDir, `aws-drift-${deps.paths.environment}.tfplan`);
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

/** Canonical RDS identifier matching `aws_db_instance.app.identifier` in `@opscrew/provider-aws`. */
function awsDbIdentifier(appName: string, environment: string): string {
  return `opscrew-${appName}-${environment}`;
}

/** Lists managed RDS/AWS snapshots for the app. */
export async function runAwsSnapshotList(
  deps: PhaseDeps,
  options: AwsPlanInput = {},
): Promise<readonly ManagedCloudSnapshotEntry[]> {
  const { plan, target } = await resolvePlanAndTarget(deps, options);
  const plugin = await loadAwsPlugin(deps, options);
  const connector = resolveAwsConnector(plugin, deps, options);
  return connector.listSnapshots({
    region: target.region,
    identifierPrefix: awsDbIdentifier(plan.app.name, deps.paths.environment),
  });
}

/** Takes a manual RDS snapshot for the app's database. */
export async function runAwsSnapshotTake(
  deps: PhaseDeps,
  options: AwsPlanInput & { readonly instanceId?: string; readonly snapshotId?: string } = {},
): Promise<ManagedCloudSnapshotEntry> {
  const { plan, target } = await resolvePlanAndTarget(deps, options);
  const plugin = await loadAwsPlugin(deps, options);
  const connector = resolveAwsConnector(plugin, deps, options);
  const dbComponent = target.components.database;
  if (dbComponent === undefined) {
    throw new OpsCrewError(
      "PHASE_PRECONDITION",
      `AWS plan for ${plan.app.name} has no managed database component to snapshot.`,
    );
  }
  const stamp = deps.clock
    .now()
    .toISOString()
    .replace(/[-:]/g, "")
    .replace(/\.\d+Z$/, "Z")
    .toLowerCase();
  const dbId = awsDbIdentifier(plan.app.name, deps.paths.environment);
  const instanceId = options.instanceId ?? dbId;
  const snapshotId = options.snapshotId ?? `${dbId}-${stamp}`;
  return connector.takeSnapshot({
    region: target.region,
    service: dbComponent.service,
    instanceId,
    snapshotId,
  });
}

/**
 * Runs an isolated throwaway RDS restore drill (ADR 0034: `PubliclyAccessible=false`, private DB
 * subnet group, verified `available`, confirmed deleted). Requires plan-hash approval unless run
 * under a pre-installed scheduled standing approval (`standingApproval: true`).
 */
export async function runAwsRestoreDrill(
  deps: PhaseDeps,
  options: AwsPlanInput & {
    readonly snapshotId: string;
    readonly drillInstanceId?: string;
    readonly dbSubnetGroupName?: string;
    readonly vpcSecurityGroupIds?: readonly string[];
    readonly standingApproval?: boolean;
  },
): Promise<ManagedCloudRestoreDrillResult> {
  const { plan, target } = await resolvePlanAndTarget(deps, options);
  const plugin = await loadAwsPlugin(deps, options);
  const connector = resolveAwsConnector(plugin, deps, options);
  const dbComponent = target.components.database;
  const dbId = awsDbIdentifier(plan.app.name, deps.paths.environment);
  const drillInstanceId = options.drillInstanceId ?? `${dbId}-drill`;
  const dbSubnetGroupName = options.dbSubnetGroupName ?? `${dbId}-db`;

  if (options.standingApproval !== true) {
    const drillHash = createHash("sha256")
      .update(
        JSON.stringify({
          action: "aws-restore-drill",
          app: plan.app.name,
          environment: deps.paths.environment,
          region: target.region,
          snapshotId: options.snapshotId,
          drillInstanceId,
          dbSubnetGroupName,
        }),
      )
      .digest("hex");
    const decision = await deps.approvals.request({
      kind: "remote-exec",
      title: `Run isolated RDS restore drill for ${plan.app.name} (${options.snapshotId})`,
      details: `Restores snapshot ${options.snapshotId} into private throwaway RDS instance ${drillInstanceId} (PubliclyAccessible=false, subnet group ${dbSubnetGroupName}), verifies it becomes available, and deletes it.`,
      planHash: drillHash,
    });
    if (!decision.approved) {
      throw new OpsCrewError(
        "PLAN_NOT_APPROVED",
        `AWS restore drill was not approved (${decision.reason ?? "declined"}).`,
      );
    }
    await deps.approvals.assertApprovedRemoteExec(drillHash);
  }

  return connector.runRestoreDrill({
    region: target.region,
    snapshotId: options.snapshotId,
    service: dbComponent?.service ?? "rds-postgres",
    drillInstanceId,
    dbSubnetGroupName,
    ...(options.vpcSecurityGroupIds === undefined
      ? {}
      : { vpcSecurityGroupIds: options.vpcSecurityGroupIds }),
  });
}

/**
 * Rotates app secrets out-of-band in AWS Secrets Manager / SSM Parameter Store.
 * Bound to a SHA-256 hash over secret names/stores/region (never secret values) via `ApprovalGate`.
 */
export async function runAwsRotateSecrets(
  deps: PhaseDeps,
  options: AwsPlanInput & { readonly secrets: readonly ManagedCloudSecretWrite[] },
): Promise<{ readonly planHash: string; readonly written: readonly string[] }> {
  if (options.secrets.length === 0) {
    throw new OpsCrewError("INVALID_INPUT", "At least one secret must be specified to rotate.");
  }
  const { plan, target } = await resolvePlanAndTarget(deps, options);
  const plugin = await loadAwsPlugin(deps, options);
  const connector = resolveAwsConnector(plugin, deps, options);

  // Hash only metadata (names, stores, region, app) — NEVER secret values!
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
    title: `Rotate ${options.secrets.length} AWS secret(s) for ${plan.app.name} (${target.region})`,
    details: `Out-of-band update in AWS Secrets Manager / SSM: ${options.secrets.map((s) => s.name).join(", ")}`,
    planHash,
  });
  if (!decision.approved) {
    throw new OpsCrewError(
      "PLAN_NOT_APPROVED",
      `AWS secret rotation was not approved (${decision.reason ?? "declined"}). Nothing was rotated.`,
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
    action: "aws-rotate-secrets",
    target: planHash,
    decision: "allow",
    detail: `Rotated ${res.written.length} secret(s) out-of-band: ${res.written.join(", ")}`,
  });
  return { planHash, written: res.written };
}

export interface AwsAdviceItem {
  readonly id: string;
  readonly severity: "info" | "warn";
  readonly title: string;
  readonly detail: string;
  readonly estimatedMonthlySavingsUsd?: number;
}

/** `opscrew advise` for AWS targets: cost traps, right-sizing, retention, and guardrail posture. */
export async function runAwsAdvise(
  deps: PhaseDeps,
  options: AwsPlanInput = {},
): Promise<readonly AwsAdviceItem[]> {
  const { plan, target } = await resolvePlanAndTarget(deps, options);
  const items: AwsAdviceItem[] = [];

  const natComponent = Object.values(target.components).find((c) => c.service === "nat-gateway");
  if (natComponent !== undefined && target.preset !== "production-ha") {
    items.push({
      id: "aws-avoid-nat-gateway",
      severity: "warn",
      title: "Avoid NAT Gateway fixed monthly cost",
      detail:
        "A NAT Gateway adds ~$32/mo per AZ before traffic. Use public subnets with strict security groups + free S3/DynamoDB Gateway Endpoints (`--set pins.noNat=true`) unless private-subnet egress is required.",
      estimatedMonthlySavingsUsd: natComponent.monthlyCostUsd,
    });
  }

  if (
    target.pins.budgetCapUsd !== undefined &&
    plan.cost.monthly.amount > target.pins.budgetCapUsd
  ) {
    items.push({
      id: "aws-over-budget",
      severity: "warn",
      title: "Estimated AWS monthly cost exceeds budget cap",
      detail: `Estimated $${plan.cost.monthly.amount.toFixed(2)}/mo exceeds pinned budget cap of $${target.pins.budgetCapUsd.toFixed(2)}/mo. Try \`opscrew design --option aws-lean\` or override components with \`--set\`.`,
    });
  }

  if (target.observability.containerInsights && target.preset === "lean") {
    items.push({
      id: "aws-container-insights-lean",
      severity: "info",
      title: "Container Insights enabled on lean preset",
      detail:
        "CloudWatch Container Insights adds per-metric charges on small workloads. Standard ECS/CloudWatch Logs metrics are sufficient for lean setups.",
    });
  }

  if (target.exceptions.length > 0) {
    items.push({
      id: "aws-guardrail-exceptions",
      severity: "warn",
      title: `${target.exceptions.length} active AWS guardrail exception(s)`,
      detail: `Review exceptions: ${target.exceptions.map((e) => `${e.guardrail} (${e.reason})`).join("; ")}.`,
    });
  }

  if (items.length === 0) {
    items.push({
      id: "aws-posture-clean",
      severity: "info",
      title: "AWS cost and security posture looks clean",
      detail: `AWS ${target.preset} (${target.compute}, ${target.region}, ~$${plan.cost.monthly.amount.toFixed(2)}/mo USD) has all default guardrails enabled and no active cost traps.`,
    });
  }

  return items;
}

/**
 * `opscrew destroy` for AWS targets (Constitution I & IV):
 * Plans a destroy via `IacEngine`, requires `allowDestroy: true` + typed confirmation of
 * `plan.app.name` bound to the destroy plan's SHA-256 hash, and applies only after approval.
 */
export async function runAwsDestroy(
  deps: PhaseDeps,
  options: AwsPlanInput & { readonly engine: IacEngine },
): Promise<{
  readonly planSummary: PlanSummary;
  readonly destroyed: boolean;
}> {
  const { plan, target } = await resolvePlanAndTarget(deps, options);
  const infraDir = path.resolve(deps.paths.root, plan.infra.dir);
  const planFile = path.join(deps.paths.stateDir, `aws-destroy-${deps.paths.environment}.tfplan`);
  await mkdir(path.dirname(planFile), { recursive: true });

  await options.engine.init(infraDir, { env: deps.env });
  const planSummary = await options.engine.plan(infraDir, planFile, {
    destroy: true,
    env: deps.env,
  });

  if (planSummary.changes.length === 0) {
    deps.reporter.info("No AWS resources to destroy.");
    return { planSummary, destroyed: false };
  }

  const decision = await deps.approvals.request({
    kind: "iac-apply",
    title: `Destroy AWS deployment ${plan.app.name} in ${target.region}`,
    details: `Destroys ${planSummary.counts.delete} AWS resource(s) permanently. Type "${plan.app.name}" to confirm.`,
    planHash: planSummary.planHash,
    allowDestroy: true,
    confirmPhrase: plan.app.name,
  });
  if (!decision.approved) {
    throw new OpsCrewError(
      "DESTROY_NOT_APPROVED",
      `AWS destroy was not approved (${decision.reason ?? "declined"}). Nothing was deleted.`,
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

  deps.reporter.success(`Destroyed AWS deployment ${plan.app.name} in ${target.region}.`);
  return { planSummary, destroyed: true };
}

/**
 * `opscrew retarget --to aws` planner: produces a zero-rewrite `ec2-compose` (or requested preset)
 * AWS target and zero-downtime migration checklist from an existing deployment plan.
 */
export async function planAwsRetarget(
  deps: PhaseDeps,
  options: AwsPluginOptions & {
    readonly currentPlan: DeployPlan;
    readonly facts: ProjectFacts;
    readonly preset?: AwsPreset;
    readonly region?: "eu-central" | "eu-north" | "us-east" | "us-west" | "ap-southeast";
  },
): Promise<{
  readonly target: AwsTarget;
  readonly estimatedMonthlyUsd: number;
  readonly steps: readonly string[];
}> {
  const plugin = await loadAwsPlugin(deps, options);
  const preset = options.preset ?? "lean";
  const requirements = {
    schemaVersion: 1,
    expectedMonthlyUsers: "1k-10k",
    budgetMonthly: {
      amount: Math.max(25, Math.ceil(options.currentPlan.cost.monthly.amount * 2)),
      currency: "USD",
    },
    provider: "aws",
    region: options.region ?? "us-east",
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
  // Default retarget from VPS/Compose lands on `ec2-compose` unless caller chose `production-ha`.
  let target = AwsTargetSchema.parse(designed.target);
  let monthlyUsd = designed.estimatedMonthlyUsd;
  if (options.preset === undefined && target.compute !== "ec2-compose") {
    const overridden = plugin.applyOverrides({
      target,
      setFlags: ["compute.service=ec2-compose"],
    });
    target = AwsTargetSchema.parse(overridden.target);
    monthlyUsd = overridden.afterMonthlyUsd;
  }

  return {
    target,
    estimatedMonthlyUsd: monthlyUsd,
    steps: [
      `Install AWS plugin if absent (\`opscrew plugin add aws\`) and authenticate AWS credentials.`,
      `Provision AWS ${target.preset} (${target.compute} in ${target.region}, ~$${monthlyUsd.toFixed(2)}/mo USD) alongside your existing ${options.currentPlan.target.provider} deployment.`,
      `Replicate data / restore latest snapshot into AWS and verify health via \`opscrew verify\`.`,
      `Switch DNS to the AWS endpoint (keep ACM DNS-01 validation records unproxied if on Cloudflare).`,
      `Keep the previous ${options.currentPlan.target.provider} deployment warm until cutover is confirmed, then finish teardown.`,
    ],
  };
}
