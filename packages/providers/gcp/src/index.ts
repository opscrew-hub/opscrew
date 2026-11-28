/**
 * `@opscrew/provider-gcp` — Official installable Google Cloud (GCP) managed-services provider
 * plugin (Feature 039, ADR 0040). Zero runtime `@opscrew/*` workspace imports.
 */
import type { ManagedCloudProviderDefinition } from "@opscrew/contracts";
import type { ProjectFacts, Requirements } from "@opscrew/plan-schema";
import { createGcpConnector, GcpProviderError } from "./connector";
import { designGcpTarget } from "./design";
import { renderGcpHcl } from "./hcl";
import { applyGcpOverrides, parseGcpSetFlag } from "./overrides";
import { GCP_REGIONS } from "./pricing";
import { StandaloneGcpTargetSchema } from "./schema";
import { renderGcpDeployWorkflow } from "./workflow";

const CONTRACT_VERSION = 1 as const;

export {
  createGcpConnector,
  type GcpCredentials,
  GcpProviderError,
  gcpDbInstanceName,
  gcpServiceName,
} from "./connector";
export {
  type DesignGcpInput,
  type DesignGcpResult,
  defaultGcpPreset,
  designGcpTarget,
} from "./design";
export {
  GCP_PROVIDER_VERSION,
  gcpWifAttributeCondition,
  hclString,
  type RenderGcpHclContext,
  renderGcpHcl,
} from "./hcl";
export {
  applyGcpOverrides,
  type GcpOverrideEntry,
  type GcpOverrideResult,
  parseGcpSetFlag,
} from "./overrides";
export {
  estimateGcpMonthlyCost,
  GCP_PRICES_AS_OF,
  GCP_REGIONS,
  GCP_UNIT_RATES_USD,
  gcpRegionFor,
  gcpRegionMultiplier,
  regionalUsd,
  roundUsd,
} from "./pricing";
export { type RenderGcpWorkflowInput, renderGcpDeployWorkflow } from "./workflow";

export const GCP_CREDENTIALS_SPEC = {
  envVars: [
    "GOOGLE_CLOUD_PROJECT",
    "GOOGLE_OAUTH_ACCESS_TOKEN",
    "GCP_PROJECT_ID",
    "GCP_ACCESS_TOKEN",
  ],
  secretPatterns: [
    {
      id: "gcp-service-account-private-key",
      title: "Google Cloud Service Account Private Key",
      pattern: /"private_key_id"\s*:\s*"[a-f0-9]{40}"/g,
    },
    {
      id: "gcp-api-key",
      title: "Google Cloud API Key",
      pattern: /\bAIza[0-9A-Za-z\-_]{35}\b/g,
    },
  ],
  consoleUrl: "https://console.cloud.google.com/iam-admin/workload-identity-pools",
  instructions:
    "Set GOOGLE_CLOUD_PROJECT and a short-lived GOOGLE_OAUTH_ACCESS_TOKEN (`gcloud auth print-access-token`). GitHub Actions deploys use keyless Workload Identity Federation with zero Service Account JSON keys.",
} as const;

export const GCP_MANAGED_PROVIDER: ManagedCloudProviderDefinition = {
  contractVersion: CONTRACT_VERSION,
  id: "gcp",
  displayName: "Google Cloud (GCP)",
  packageName: "@opscrew/provider-gcp",
  credentials: GCP_CREDENTIALS_SPEC,
  regions: GCP_REGIONS,
  presets: ["lean", "balanced", "production-ha"],
  createConnector: createGcpConnector,
  designTarget: (input) => {
    const res = designGcpTarget({
      facts: input.facts as ProjectFacts,
      requirements: input.requirements as Requirements,
      ...(input.preset === undefined ? {} : { preset: input.preset }),
      ...(input.pins === undefined ? {} : { pins: input.pins as Record<string, unknown> }),
    });
    return {
      target: res.target,
      estimatedMonthlyUsd: res.totalMonthlyUsd,
      costLines: Object.entries(res.target.components).map(([component, c]) => ({
        component,
        label: c.service,
        monthlyUsd: c.monthlyCostUsd,
      })),
      costTrapWarnings: res.warnings,
      notes: Object.entries(res.target.components).map(
        ([component, c]) => `${component}: ${c.why}`,
      ),
    };
  },
  applyOverrides: ({ target, setFlags }) => {
    const parsedTarget = StandaloneGcpTargetSchema.parse(target);
    const entries = setFlags.map(parseGcpSetFlag);
    const result = applyGcpOverrides(parsedTarget, setFlags);
    return {
      target: result.target,
      beforeMonthlyUsd: result.beforeMonthlyUsd,
      afterMonthlyUsd: result.afterMonthlyUsd,
      deltaMonthlyUsd: result.deltaMonthlyUsd,
      applied: entries.map((e) => {
        const [component = e.path, ...rest] = e.path.split(".");
        return {
          component,
          field: rest.join("."),
          value: e.rawValue,
        };
      }),
      warnings: result.warnings,
    };
  },
  renderHcl: (input) => {
    const parts = input.githubRepo.trim().split("/");
    const owner = parts[0]?.trim();
    const repo = parts[1]?.trim();
    if (parts.length !== 2 || !owner || !repo) {
      throw new GcpProviderError(
        "INVALID_INPUT",
        `Invalid githubRepo "${input.githubRepo}": expected "<owner>/<repo>" so WIF CEL pinning is exact.`,
      );
    }
    return renderGcpHcl({
      appName: input.appName,
      environment: input.environment,
      target: StandaloneGcpTargetSchema.parse(input.target),
      ...(input.domain === undefined ? {} : { domain: input.domain }),
      ...(input.dnsProvider === undefined ? {} : { dnsProvider: input.dnsProvider }),
      ...(input.containerPort === undefined ? {} : { containerPort: input.containerPort }),
      github: {
        owner,
        repo,
        environmentName: input.environment,
        ...(input.branch === undefined ? {} : { branch: input.branch }),
      },
    });
  },
  renderWorkflow: (input) =>
    renderGcpDeployWorkflow({
      appName: input.appName,
      environment: input.environment,
      workflowPath: `.github/workflows/opscrew-deploy${input.environment === "prod" ? "" : `-${input.environment}`}.yml`,
      target: StandaloneGcpTargetSchema.parse(input.target),
      branch: input.branch ?? "main",
    }),
};

export default GCP_MANAGED_PROVIDER;
