/**
 * AWS provision phase orchestration (Feature 034, T3408).
 *
 * Enforces every non-negotiable safety boundary in core (Constitution I & IV):
 * 1. Credential verification via injected AWS connector (fail-closed).
 * 2. Vendored readable HCL + keyless GitHub Actions OIDC workflow rendered into repo.
 * 3. `tofu plan` + deterministic `@opscrew/secops` AWS policy gate (hard-blocks any violation).
 * 4. Plan-hash-bound approval (`ApprovalGate.request` + `assertApprovedPlan`) before `apply`.
 * 5. Out-of-band secret writes to AWS Secrets Manager / SSM (never in HCL, `.tfstate`, or logs).
 * 6. Cloudflare ACM DNS-01 CNAME records written with `proxied: false` when Cloudflare manages DNS.
 */
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import type {
  IacApplyResult,
  IacEngine,
  ManagedCloudRenderedFile,
  ManagedCloudSecretWrite,
  PlanSummary,
  PolicyResult,
} from "@opscrew/contracts";
import { OpsCrewError } from "@opscrew/core";
import { type DeployPlan, readArtifact } from "@opscrew/plan-schema";
import { blockingPolicyFailures, evaluatePlanPolicies } from "@opscrew/secops";
import type { PhaseDeps } from "../context";
import {
  type AwsPluginOptions,
  loadAwsPlugin,
  requireAwsTarget,
  resolveAwsConnector,
} from "./loader";

/** Minimal Cloudflare DNS writer used for ACM DNS-01 validation records (`proxied: false`). */
export interface AwsCloudflareDnsWriter {
  upsertDnsRecord(input: {
    readonly domain: string;
    readonly type: "CNAME";
    readonly name: string;
    readonly content: string;
    readonly proxied: false;
  }): Promise<void>;
}

export interface RunAwsProvisionOptions extends AwsPluginOptions {
  /** Injected IaC engine (`tofu` / `terraform`). */
  readonly engine: IacEngine;
  /** GitHub `owner/repo` string for OIDC `sub` claim pinning. */
  readonly githubRepo: string;
  /** Optional immutable GitHub org id (July 2026 OIDC claim). */
  readonly githubOrgId?: string;
  /** Optional immutable GitHub repo id (July 2026 OIDC claim). */
  readonly githubRepoId?: string;
  /** Explicit plan override (default: `opscrew/plan.yaml`). */
  readonly plan?: DeployPlan;
  /** App secrets to populate out-of-band AFTER approved apply (never embedded in state). */
  readonly secrets?: readonly ManagedCloudSecretWrite[];
  /** Optional Cloudflare DNS writer for ACM DNS-01 validation records (`proxied: false`). */
  readonly cloudflare?: AwsCloudflareDnsWriter;
  /** Optional custom AWS endpoint URL (e.g., `http://localhost:4566` for `floci`). */
  readonly endpointUrl?: string;
  /** When true, stops after rendering, planning, and policy checks without applying. */
  readonly planOnly?: boolean;
}

export interface AwsProvisionResult {
  readonly accountId?: string;
  readonly renderedFiles: readonly string[];
  readonly planSummary: PlanSummary;
  readonly policyResults: readonly PolicyResult[];
  readonly applied: boolean;
  readonly applyResult?: IacApplyResult;
  readonly writtenSecretNames: readonly string[];
  readonly acmRecordsWired: readonly {
    readonly name: string;
    readonly content: string;
    readonly proxied: false;
  }[];
}

function safeRepoPath(root: string, rel: string): string {
  const normalized = rel.replace(/\\/g, "/");
  if (normalized.startsWith("/") || normalized.split("/").includes("..")) {
    throw new OpsCrewError(
      "INVALID_INPUT",
      `Refused to write rendered plugin file outside the repository: "${rel}".`,
    );
  }
  const resolved = path.resolve(root, normalized);
  const relBack = path.relative(root, resolved);
  if (relBack.startsWith("..") || path.isAbsolute(relBack)) {
    throw new OpsCrewError(
      "INVALID_INPUT",
      `Refused to write rendered plugin file outside the repository: "${rel}".`,
    );
  }
  return resolved;
}

interface AcmValidationRecord {
  readonly name: string;
  readonly value: string;
}

function extractAcmValidationRecords(outputs: Record<string, unknown>): AcmValidationRecord[] {
  const raw = outputs.acm_validation_records;
  if (!Array.isArray(raw)) return [];
  const records: AcmValidationRecord[] = [];
  for (const item of raw) {
    if (
      typeof item === "object" &&
      item !== null &&
      typeof (item as Record<string, unknown>).name === "string" &&
      typeof (item as Record<string, unknown>).value === "string"
    ) {
      records.push({
        name: String((item as Record<string, unknown>).name),
        value: String((item as Record<string, unknown>).value),
      });
    }
  }
  return records;
}

/**
 * Renders AWS OpenTofu HCL & keyless OIDC workflow, plans, runs `@opscrew/secops` AWS policies,
 * enforces plan-hash-bound approval, applies, populates secrets out-of-band, and wires Cloudflare
 * ACM DNS-01 validation records (`proxied: false`).
 */
export async function runAwsProvision(
  deps: PhaseDeps,
  options: RunAwsProvisionOptions,
): Promise<AwsProvisionResult> {
  const plan = options.plan ?? (await readArtifact("plan", deps.paths.files.plan));
  const target = requireAwsTarget(plan);
  const plugin = await loadAwsPlugin(deps, options);
  const connector = resolveAwsConnector(plugin, deps, options);

  deps.reporter.step("Verifying AWS credentials");
  const identity = await connector.verifyCredentials();
  if (!identity.ok) {
    throw new OpsCrewError(
      "CREDENTIALS_INVALID",
      deps.redactor.redact(identity.error ?? "AWS credential verification failed."),
      { hint: plugin.credentials.instructions },
    );
  }

  const endpointUrl = options.endpointUrl ?? deps.env.AWS_ENDPOINT_URL;
  const hclFiles = plugin.renderHcl({
    appName: plan.app.name,
    environment: deps.paths.environment,
    target,
    ...(plan.dns.domain === undefined ? {} : { domain: plan.dns.domain }),
    dnsProvider: plan.dns.provider,
    githubRepo: options.githubRepo,
    ...(options.githubOrgId === undefined ? {} : { githubOrgId: options.githubOrgId }),
    ...(options.githubRepoId === undefined ? {} : { githubRepoId: options.githubRepoId }),
    branch: plan.cicd.branch,
    containerPort: plan.app.port,
    ...(endpointUrl === undefined ? {} : { endpointUrl }),
  });

  const workflowFile = plugin.renderWorkflow({
    appName: plan.app.name,
    environment: deps.paths.environment,
    target,
    branch: plan.cicd.branch,
    imageRegistry: plan.cicd.registry === "ghcr" ? "ghcr" : "ecr",
  });

  const renderedFiles: string[] = [];
  const infraDir = safeRepoPath(deps.paths.root, plan.infra.dir);
  await mkdir(infraDir, { recursive: true });

  const writeRendered = async (
    baseDir: string,
    file: ManagedCloudRenderedFile,
  ): Promise<string> => {
    const dest = safeRepoPath(baseDir, file.path);
    await mkdir(path.dirname(dest), { recursive: true });
    await writeFile(dest, file.content, "utf8");
    const rel = path.relative(deps.paths.root, dest).replace(/\\/g, "/");
    renderedFiles.push(rel);
    return rel;
  };

  for (const file of hclFiles) {
    await writeRendered(infraDir, file);
  }
  await writeRendered(deps.paths.root, {
    ...workflowFile,
    path: plan.cicd.workflowPath,
  });

  deps.reporter.step("Running OpenTofu init and plan for AWS");
  await options.engine.init(infraDir, { env: deps.env });
  const planFile = path.join(deps.paths.stateDir, `aws-${deps.paths.environment}.tfplan`);
  await mkdir(path.dirname(planFile), { recursive: true });
  const planSummary = await options.engine.plan(infraDir, planFile, { env: deps.env });

  const policyResults = evaluatePlanPolicies(planSummary.planJson, plan);
  const failures = blockingPolicyFailures(policyResults);
  if (failures.length > 0) {
    const details = failures.map((f) => `[${f.policyId}] ${f.message}`).join("; ");
    await deps.audit.append({
      at: deps.clock.now().toISOString(),
      kind: "iac",
      actor: "opscrew",
      action: "aws-policy-check",
      target: planSummary.planHash,
      decision: "refused",
      detail: deps.redactor.redact(details),
    });
    throw new OpsCrewError(
      "PHASE_PRECONDITION",
      `Blocked AWS plan due to ${failures.length} security policy failure(s): ${deps.redactor.redact(details)}`,
      {
        hint: "Fix the offending resources or record an explicit guardrail exception in `opscrew/plan.yaml` if applicable.",
      },
    );
  }

  if (options.planOnly === true) {
    return {
      ...(identity.accountId === undefined ? {} : { accountId: identity.accountId }),
      renderedFiles,
      planSummary,
      policyResults,
      applied: false,
      writtenSecretNames: [],
      acmRecordsWired: [],
    };
  }

  const approvalTitle = `Apply AWS ${target.preset} plan for ${plan.app.name} (${target.region})`;
  const approvalDetails = `${planSummary.counts.create} to create, ${planSummary.counts.update} to update, ${planSummary.counts.delete} to delete, ${planSummary.counts.replace} to replace (~$${plan.cost.monthly.amount.toFixed(2)}/mo USD).`;
  const decision = await deps.approvals.request({
    kind: "iac-apply",
    title: approvalTitle,
    details: approvalDetails,
    planHash: planSummary.planHash,
    policy: policyResults,
    ...(planSummary.hasDestroy ? { allowDestroy: true, confirmPhrase: plan.app.name } : {}),
  });
  if (!decision.approved) {
    throw new OpsCrewError(
      "PLAN_NOT_APPROVED",
      `AWS apply was not approved (${decision.reason ?? "declined"}). Nothing was changed in AWS.`,
    );
  }
  await deps.approvals.assertApprovedPlan(planSummary.planHash, {
    allowDestroy: planSummary.hasDestroy,
  });

  deps.reporter.step("Applying approved AWS plan");
  const applyResult = await options.engine.apply(
    infraDir,
    planFile,
    {
      approvedPlanHash: planSummary.planHash,
      ...(planSummary.hasDestroy ? { allowDestroy: true } : {}),
    },
    { env: deps.env },
  );

  let writtenSecretNames: readonly string[] = [];
  if (options.secrets !== undefined && options.secrets.length > 0) {
    deps.reporter.step(
      `Writing ${options.secrets.length} secret(s) out-of-band to AWS Secrets Manager / SSM (never stored in Terraform state)`,
    );
    const secretRes = await connector.writeSecrets({
      region: target.region,
      secrets: options.secrets,
    });
    writtenSecretNames = secretRes.written;
    await deps.audit.append({
      at: deps.clock.now().toISOString(),
      kind: "secret-set",
      actor: "opscrew",
      action: "aws-secrets-write",
      target: planSummary.planHash,
      decision: "allow",
      detail: `Wrote ${writtenSecretNames.length} secret(s) out-of-band: ${writtenSecretNames.join(", ")}`,
    });
  }

  const acmRecordsWired: Array<{ name: string; content: string; proxied: false }> = [];
  if (
    target.pins.keepCloudflareDns !== false &&
    plan.dns.provider === "cloudflare" &&
    plan.dns.domain !== undefined &&
    options.cloudflare !== undefined
  ) {
    const records = extractAcmValidationRecords(applyResult.outputs);
    for (const rec of records) {
      await options.cloudflare.upsertDnsRecord({
        domain: plan.dns.domain,
        type: "CNAME",
        name: rec.name,
        content: rec.value,
        proxied: false,
      });
      acmRecordsWired.push({ name: rec.name, content: rec.value, proxied: false });
    }
  }

  deps.reporter.success(
    `Applied AWS plan for ${plan.app.name} in ${target.region} (plan hash ${planSummary.planHash.slice(0, 12)}).`,
  );

  return {
    ...(identity.accountId === undefined ? {} : { accountId: identity.accountId }),
    renderedFiles,
    planSummary,
    policyResults,
    applied: true,
    applyResult,
    writtenSecretNames,
    acmRecordsWired,
  };
}
