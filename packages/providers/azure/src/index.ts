/**
 * `@opscrew/provider-azure` — Official installable Microsoft Azure managed-services provider plugin
 * (Feature 038, ADR 0040).
 */
import type { ManagedCloudProviderDefinition } from "@opscrew/contracts";
import type { ProjectFacts, Requirements } from "@opscrew/plan-schema";
import { AzureProviderError, createAzureConnector } from "./connector";
import { designAzureTarget } from "./design";
import { renderAzureHcl } from "./hcl";
import { applyAzureOverrides, parseAzureSetFlag } from "./overrides";
import { AZURE_REGIONS } from "./pricing";
import { StandaloneAzureTargetSchema } from "./schema";
import { renderAzureDeployWorkflow } from "./workflow";

const CONTRACT_VERSION = 1 as const;

export {
  type AzureCredentials,
  AzureProviderError,
  azureAppResourceName,
  azureDbServerName,
  azureKeyVaultName,
  azureResourceGroupName,
  createAzureConnector,
} from "./connector";
export {
  type DesignAzureInput,
  type DesignAzureResult,
  defaultAzurePreset,
  designAzureTarget,
} from "./design";
export {
  AZURE_PROVIDER_VERSION,
  azureGithubOidcSubject,
  azureStorageAccountName,
  hclString,
  type RenderAzureHclContext,
  renderAzureHcl,
} from "./hcl";
export {
  type AzureOverrideEntry,
  type AzureOverrideResult,
  applyAzureOverrides,
  parseAzureSetFlag,
} from "./overrides";
export {
  AZURE_PRICES_AS_OF,
  AZURE_REGIONS,
  AZURE_UNIT_RATES_USD,
  azureRegionFor,
  azureRegionMultiplier,
  estimateAzureMonthlyCost,
  regionalUsd,
  roundUsd,
} from "./pricing";
export { type RenderAzureWorkflowInput, renderAzureDeployWorkflow } from "./workflow";

/** Azure credential specification (names and secret patterns only — never values). */
export const AZURE_CREDENTIALS_SPEC = {
  envVars: [
    "AZURE_SUBSCRIPTION_ID",
    "AZURE_TENANT_ID",
    "AZURE_CLIENT_ID",
    "AZURE_CLIENT_SECRET",
    "AZURE_ACCESS_TOKEN",
  ],
  secretPatterns: [
    {
      id: "azure-client-secret",
      title: "Azure AD Client Secret",
      pattern: /\b[A-Za-z0-9_~.-]{3}~[A-Za-z0-9_~.-]{31,37}\b/g,
    },
  ],
  consoleUrl:
    "https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/RegisteredApps",
  instructions:
    "Configure short-lived Azure credentials via `az login` + `AZURE_ACCESS_TOKEN` or `AZURE_SUBSCRIPTION_ID` + service principal env vars (deployments from GitHub Actions use keyless OIDC Federated Identity Credentials with zero stored secrets).",
} as const;

/** Plain-data managed-cloud provider definition exported by `@opscrew/provider-azure`. */
export const AZURE_MANAGED_PROVIDER: ManagedCloudProviderDefinition = {
  contractVersion: CONTRACT_VERSION,
  id: "azure",
  displayName: "Microsoft Azure",
  packageName: "@opscrew/provider-azure",
  credentials: AZURE_CREDENTIALS_SPEC,
  regions: AZURE_REGIONS,
  presets: ["lean", "balanced", "production-ha"],
  createConnector: createAzureConnector,
  designTarget: (input) => {
    const res = designAzureTarget({
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
    const parsedTarget = StandaloneAzureTargetSchema.parse(target);
    const entries = setFlags.map(parseAzureSetFlag);
    const result = applyAzureOverrides(parsedTarget, setFlags);
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
      throw new AzureProviderError(
        "INVALID_INPUT",
        `Invalid githubRepo "${input.githubRepo}": expected "<owner>/<repo>" so OIDC subject pinning is exact.`,
      );
    }
    return renderAzureHcl({
      appName: input.appName,
      environment: input.environment,
      target: StandaloneAzureTargetSchema.parse(input.target),
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
    renderAzureDeployWorkflow({
      appName: input.appName,
      environment: input.environment,
      workflowPath: `.github/workflows/opscrew-deploy${input.environment === "prod" ? "" : `-${input.environment}`}.yml`,
      target: StandaloneAzureTargetSchema.parse(input.target),
      branch: input.branch ?? "main",
      ...(input.clientIdVar === undefined ? {} : { clientIdVar: input.clientIdVar }),
      ...(input.tenantIdVar === undefined ? {} : { tenantIdVar: input.tenantIdVar }),
      ...(input.subscriptionIdVar === undefined
        ? {}
        : { subscriptionIdVar: input.subscriptionIdVar }),
    }),
};

export default AZURE_MANAGED_PROVIDER;
