/**
 * Azure provision phase orchestration (Feature 038, T3806).
 *
 * Enforces every non-negotiable safety boundary in core (Constitution I & IV):
 * 1. Credential verification via injected Azure connector (fail-closed).
 * 2. Vendored readable HCL + keyless GitHub Actions OIDC workflow rendered into repo.
 * 3. `tofu plan` + deterministic `@opscrew/secops` Azure policy gate (hard-blocks any violation).
 * 4. Plan-hash-bound approval (`ApprovalGate.request` + `assertApprovedPlan`) before `apply`.
 * 5. Out-of-band secret writes to Azure Key Vault (never in HCL, `.tfstate`, or logs).
 * 6. Cloudflare `asuid.<domain>` TXT verification records written with `proxied: false`.
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
  type AzurePluginOptions,
  loadAzurePlugin,
  requireAzureTarget,
  resolveAzureConnector,
} from "./loader";

/** Minimal Cloudflare DNS writer used for Azure custom-domain `asuid` TXT records (`proxied: false`). */
export interface AzureCloudflareDnsWriter {
  upsertDnsRecord(input: {
    readonly domain: string;
    readonly type: "TXT";
    readonly name: string;
    readonly content: string;
    readonly proxied: false;
  }): Promise<void>;
}

export interface RunAzureProvisionOptions extends AzurePluginOptions {
  readonly engine: IacEngine;
  readonly githubRepo: string;
  readonly plan?: DeployPlan;
  readonly secrets?: readonly ManagedCloudSecretWrite[];
  readonly cloudflare?: AzureCloudflareDnsWriter;
  readonly planOnly?: boolean;
}

export interface AzureProvisionResult {
  readonly accountId?: string;
  readonly renderedFiles: readonly string[];
  readonly planSummary: PlanSummary;
  readonly policyResults: readonly PolicyResult[];
  readonly applied: boolean;
  readonly applyResult?: IacApplyResult;
  readonly writtenSecretNames: readonly string[];
  readonly asuidRecordsWired: readonly {
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

interface AsuidValidationRecord {
  readonly name: string;
  readonly value: string;
}

function extractAsuidValidationRecords(outputs: Record<string, unknown>): AsuidValidationRecord[] {
  const raw = outputs.asuid_validation_records;
  if (!Array.isArray(raw)) return [];
  const records: AsuidValidationRecord[] = [];
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

export async function runAzureProvision(
  deps: PhaseDeps,
  options: RunAzureProvisionOptions,
): Promise<AzureProvisionResult> {
  const plan = options.plan ?? (await readArtifact("plan", deps.paths.files.plan));
  const target = requireAzureTarget(plan);
  const plugin = await loadAzurePlugin(deps, options);
  const connector = resolveAzureConnector(plugin, deps, options);

  deps.reporter.step("Verifying Azure credentials");
  const identity = await connector.verifyCredentials();
  if (!identity.ok) {
    throw new OpsCrewError(
      "CREDENTIALS_INVALID",
      deps.redactor.redact(identity.error ?? "Azure credential verification failed."),
      { hint: plugin.credentials.instructions },
    );
  }

  const hclFiles = plugin.renderHcl({
    appName: plan.app.name,
    environment: deps.paths.environment,
    target,
    ...(plan.dns.domain === undefined ? {} : { domain: plan.dns.domain }),
    dnsProvider: plan.dns.provider,
    githubRepo: options.githubRepo,
    branch: plan.cicd.branch,
    containerPort: plan.app.port,
  });

  const workflowFile = plugin.renderWorkflow({
    appName: plan.app.name,
    environment: deps.paths.environment,
    target,
    branch: plan.cicd.branch,
    imageRegistry: plan.cicd.registry === "ghcr" ? "ghcr" : "acr",
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

  deps.reporter.step("Running OpenTofu init and plan for Azure");
  await options.engine.init(infraDir, { env: deps.env });
  const planFile = path.join(deps.paths.stateDir, `azure-${deps.paths.environment}.tfplan`);
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
      action: "azure-policy-check",
      target: planSummary.planHash,
      decision: "refused",
      detail: deps.redactor.redact(details),
    });
    throw new OpsCrewError(
      "PHASE_PRECONDITION",
      `Blocked Azure plan due to ${failures.length} security policy failure(s): ${deps.redactor.redact(details)}`,
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
      asuidRecordsWired: [],
    };
  }

  const approvalTitle = `Apply Azure ${target.preset} plan for ${plan.app.name} (${target.region})`;
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
      `Azure apply was not approved (${decision.reason ?? "declined"}). Nothing was changed in Azure.`,
    );
  }
  await deps.approvals.assertApprovedPlan(planSummary.planHash, {
    allowDestroy: planSummary.hasDestroy,
  });

  deps.reporter.step("Applying approved Azure plan");
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
      `Writing ${options.secrets.length} secret(s) out-of-band to Azure Key Vault (never stored in Terraform state)`,
    );
    const kvUri =
      typeof applyResult.outputs.key_vault_uri === "string"
        ? applyResult.outputs.key_vault_uri
        : undefined;
    const secretConnector =
      kvUri !== undefined && options.connector === undefined
        ? resolveAzureConnector(plugin, deps, {
            ...options,
            envOverrides: { AZURE_KEY_VAULT_URL: kvUri },
          })
        : connector;
    const secretRes = await secretConnector.writeSecrets({
      region: target.region,
      secrets: options.secrets,
    });
    writtenSecretNames = secretRes.written;
    await deps.audit.append({
      at: deps.clock.now().toISOString(),
      kind: "secret-set",
      actor: "opscrew",
      action: "azure-secrets-write",
      target: planSummary.planHash,
      decision: "allow",
      detail: `Wrote ${writtenSecretNames.length} secret(s) out-of-band: ${writtenSecretNames.join(", ")}`,
    });
  }

  const asuidRecordsWired: Array<{ name: string; content: string; proxied: false }> = [];
  if (
    target.pins.keepCloudflareDns !== false &&
    plan.dns.provider === "cloudflare" &&
    plan.dns.domain !== undefined &&
    options.cloudflare !== undefined
  ) {
    const records = extractAsuidValidationRecords(applyResult.outputs);
    for (const rec of records) {
      await options.cloudflare.upsertDnsRecord({
        domain: plan.dns.domain,
        type: "TXT",
        name: rec.name,
        content: rec.value,
        proxied: false,
      });
      asuidRecordsWired.push({ name: rec.name, content: rec.value, proxied: false });
    }
  }

  deps.reporter.success(
    `Applied Azure plan for ${plan.app.name} in ${target.region} (plan hash ${planSummary.planHash.slice(0, 12)}).`,
  );

  return {
    ...(identity.accountId === undefined ? {} : { accountId: identity.accountId }),
    renderedFiles,
    planSummary,
    policyResults,
    applied: true,
    applyResult,
    writtenSecretNames,
    asuidRecordsWired,
  };
}
