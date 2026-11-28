/**
 * GCP provision phase orchestration (Feature 039, T3906).
 * Enforces credential check, vendored HCL/WIF workflow rendering, fail-closed GCP SecOps gate,
 * SHA-256 plan-hash-bound approval, out-of-band Secret Manager version writes, and Cloudflare
 * Certificate Manager DNS-01 CNAME records (`proxied: false`).
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
  type GcpPluginOptions,
  loadGcpPlugin,
  requireGcpTarget,
  resolveGcpConnector,
} from "./loader";

export interface GcpCloudflareDnsWriter {
  upsertDnsRecord(input: {
    readonly domain: string;
    readonly type: "CNAME";
    readonly name: string;
    readonly content: string;
    readonly proxied: false;
  }): Promise<void>;
}

export interface RunGcpProvisionOptions extends GcpPluginOptions {
  readonly engine: IacEngine;
  readonly githubRepo: string;
  readonly plan?: DeployPlan;
  readonly secrets?: readonly ManagedCloudSecretWrite[];
  readonly cloudflare?: GcpCloudflareDnsWriter;
  readonly planOnly?: boolean;
}

export interface GcpProvisionResult {
  readonly accountId?: string;
  readonly renderedFiles: readonly string[];
  readonly planSummary: PlanSummary;
  readonly policyResults: readonly PolicyResult[];
  readonly applied: boolean;
  readonly applyResult?: IacApplyResult;
  readonly writtenSecretNames: readonly string[];
  readonly acmeRecordsWired: readonly {
    readonly name: string;
    readonly content: string;
    readonly proxied: false;
  }[];
  readonly acmeRecordsPending: readonly {
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

function extractAcmeValidationRecords(
  outputs: Record<string, unknown>,
): Array<{ readonly name: string; readonly value: string }> {
  const raw = outputs.acme_validation_records;
  if (!Array.isArray(raw)) return [];
  const records: Array<{ name: string; value: string }> = [];
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

export async function runGcpProvision(
  deps: PhaseDeps,
  options: RunGcpProvisionOptions,
): Promise<GcpProvisionResult> {
  const plan = options.plan ?? (await readArtifact("plan", deps.paths.files.plan));
  const target = requireGcpTarget(plan);
  const plugin = await loadGcpPlugin(deps, options);
  const connector = resolveGcpConnector(plugin, deps, options);

  deps.reporter.step("Verifying Google Cloud credentials");
  const identity = await connector.verifyCredentials();
  if (!identity.ok) {
    throw new OpsCrewError(
      "CREDENTIALS_INVALID",
      deps.redactor.redact(identity.error ?? "Google Cloud credential verification failed."),
      { hint: plugin.credentials.instructions },
    );
  }

  const declaredSecretNames = Array.from(
    new Set([
      ...plan.app.env.filter((e) => e.secret).map((e) => e.name),
      ...(options.secrets ?? []).map((s) => s.name),
    ]),
  );

  const hclFiles = plugin.renderHcl({
    appName: plan.app.name,
    environment: deps.paths.environment,
    target,
    ...(plan.dns.domain === undefined ? {} : { domain: plan.dns.domain }),
    dnsProvider: plan.dns.provider,
    githubRepo: options.githubRepo,
    branch: plan.cicd.branch,
    containerPort: plan.app.port,
    ...(declaredSecretNames.length > 0 ? { secretNames: declaredSecretNames } : {}),
  });

  const workflowFile = plugin.renderWorkflow({
    appName: plan.app.name,
    environment: deps.paths.environment,
    target,
    branch: plan.cicd.branch,
    imageRegistry: plan.cicd.registry === "ghcr" ? "ghcr" : "artifact-registry",
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

  deps.reporter.step("Running OpenTofu init and plan for Google Cloud");
  await options.engine.init(infraDir, { env: deps.env });
  const planFile = path.join(deps.paths.stateDir, `gcp-${deps.paths.environment}.tfplan`);
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
      action: "gcp-policy-check",
      target: planSummary.planHash,
      decision: "refused",
      detail: deps.redactor.redact(details),
    });
    throw new OpsCrewError(
      "PHASE_PRECONDITION",
      `Blocked GCP plan due to ${failures.length} security policy failure(s): ${deps.redactor.redact(details)}`,
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
      acmeRecordsWired: [],
      acmeRecordsPending: [],
    };
  }

  const decision = await deps.approvals.request({
    kind: "iac-apply",
    title: `Apply GCP ${target.preset} plan for ${plan.app.name} (${target.region})`,
    details: `${planSummary.counts.create} to create, ${planSummary.counts.update} to update, ${planSummary.counts.delete} to delete, ${planSummary.counts.replace} to replace (~$${plan.cost.monthly.amount.toFixed(2)}/mo USD).`,
    planHash: planSummary.planHash,
    policy: policyResults,
    ...(planSummary.hasDestroy ? { allowDestroy: true, confirmPhrase: plan.app.name } : {}),
  });
  if (!decision.approved) {
    throw new OpsCrewError(
      "PLAN_NOT_APPROVED",
      `GCP apply was not approved (${decision.reason ?? "declined"}). Nothing was changed in Google Cloud.`,
    );
  }
  await deps.approvals.assertApprovedPlan(planSummary.planHash, {
    allowDestroy: planSummary.hasDestroy,
  });

  deps.reporter.step("Applying approved GCP plan");
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
      `Writing ${options.secrets.length} secret(s) out-of-band to Google Secret Manager (never stored in Terraform state)`,
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
      action: "gcp-secrets-write",
      target: planSummary.planHash,
      decision: "allow",
      detail: `Wrote ${writtenSecretNames.length} secret(s) out-of-band: ${writtenSecretNames.join(", ")}`,
    });
  }

  const acmeRecordsWired: Array<{ name: string; content: string; proxied: false }> = [];
  const acmeRecordsPending: Array<{ name: string; content: string; proxied: false }> = [];
  const records = extractAcmeValidationRecords(applyResult.outputs);
  if (
    records.length > 0 &&
    target.pins.keepCloudflareDns !== false &&
    plan.dns.provider === "cloudflare" &&
    plan.dns.domain !== undefined &&
    options.cloudflare !== undefined
  ) {
    for (const rec of records) {
      await options.cloudflare.upsertDnsRecord({
        domain: plan.dns.domain,
        type: "CNAME",
        name: rec.name,
        content: rec.value,
        proxied: false,
      });
      acmeRecordsWired.push({ name: rec.name, content: rec.value, proxied: false });
    }
  } else if (records.length > 0) {
    for (const rec of records) {
      acmeRecordsPending.push({ name: rec.name, content: rec.value, proxied: false });
    }
    deps.reporter.warn(
      `Certificate Manager DNS-01 CNAME record(s) must be added by hand as DNS-only (proxied = false): ${records.map((r) => `${r.name} -> ${r.value}`).join(", ")}`,
    );
  }

  deps.reporter.success(
    `Applied GCP plan for ${plan.app.name} in ${target.region} (plan hash ${planSummary.planHash.slice(0, 12)}).`,
  );

  return {
    ...(identity.accountId === undefined ? {} : { accountId: identity.accountId }),
    renderedFiles,
    planSummary,
    policyResults,
    applied: true,
    applyResult,
    writtenSecretNames,
    acmeRecordsWired,
    acmeRecordsPending,
  };
}
