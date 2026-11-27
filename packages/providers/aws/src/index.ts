/**
 * `@opscrew/provider-aws` — Official installable AWS managed-services provider plugin
 * (Feature 034, ADR 0040).
 */
import {
  MANAGED_CLOUD_CONTRACT_VERSION,
  type ManagedCloudProviderDefinition,
} from "@opscrew/contracts";
import { AwsTargetSchema, type ProjectFacts, type Requirements } from "@opscrew/plan-schema";
import { createAwsConnector } from "./connector";
import { designAwsTarget } from "./design";
import { renderAwsHcl } from "./hcl";
import { applyAwsOverrides, parseAwsSetFlag } from "./overrides";
import { AWS_REGIONS } from "./pricing";
import { renderAwsDeployWorkflow } from "./workflow";

export { type AwsCredentials, createAwsConnector, signAwsV4Request } from "./connector";
export {
  type DesignAwsInput,
  type DesignAwsResult,
  defaultAwsPreset,
  designAwsTarget,
} from "./design";
export {
  AWS_PROVIDER_VERSION,
  githubOidcSubject,
  type RenderAwsHclContext,
  renderAwsHcl,
} from "./hcl";
export {
  type AwsOverrideEntry,
  type AwsOverrideResult,
  applyAwsOverrides,
  parseAwsSetFlag,
} from "./overrides";
export {
  AWS_PRICES_AS_OF,
  AWS_REGIONS,
  AWS_UNIT_RATES_USD,
  awsRegionFor,
  awsRegionMultiplier,
  estimateAwsMonthlyCost,
  regionalUsd,
  roundUsd,
} from "./pricing";
export { type RenderAwsWorkflowInput, renderAwsDeployWorkflow } from "./workflow";

/** AWS credential specification (names and secret patterns only — never values). */
export const AWS_CREDENTIALS_SPEC = {
  envVars: ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_REGION"],
  profileEnvVars: ["AWS_PROFILE"],
  secretPatterns: [
    {
      id: "aws-access-key-id",
      title: "AWS Access Key ID",
      pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
    },
  ],
  consoleUrl: "https://console.aws.amazon.com/iam/",
  instructions:
    "Configure short-lived AWS credentials via `aws sso login` / `AWS_PROFILE` or `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` (deployments from GitHub Actions use keyless OIDC with zero stored AWS keys).",
} as const;

/** Plain-data managed-cloud provider definition exported by `@opscrew/provider-aws`. */
export const AWS_MANAGED_PROVIDER: ManagedCloudProviderDefinition = {
  contractVersion: MANAGED_CLOUD_CONTRACT_VERSION,
  id: "aws",
  displayName: "Amazon Web Services (AWS)",
  packageName: "@opscrew/provider-aws",
  credentials: AWS_CREDENTIALS_SPEC,
  regions: AWS_REGIONS,
  presets: ["lean", "balanced", "production-ha"],
  createConnector: createAwsConnector,
  designTarget: (input) => {
    const res = designAwsTarget({
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
    const parsedTarget = AwsTargetSchema.parse(target);
    const entries = setFlags.map(parseAwsSetFlag);
    const result = applyAwsOverrides(parsedTarget, setFlags);
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
    const [owner = "owner", repo = input.appName] = input.githubRepo.split("/");
    return renderAwsHcl({
      appName: input.appName,
      environment: input.environment,
      infraDir: ".",
      target: AwsTargetSchema.parse(input.target),
      ...(input.domain === undefined ? {} : { domain: input.domain }),
      github: {
        owner,
        repo,
        ...(input.githubOrgId === undefined ? {} : { ownerId: Number(input.githubOrgId) }),
        ...(input.githubRepoId === undefined ? {} : { repoId: Number(input.githubRepoId) }),
        ...(input.branch === undefined ? {} : { branch: input.branch }),
      },
      ...(input.endpointUrl === undefined ? {} : { endpointUrl: input.endpointUrl }),
    });
  },
  renderWorkflow: (input) =>
    renderAwsDeployWorkflow({
      appName: input.appName,
      environment: input.environment,
      workflowPath: `.github/workflows/opscrew-deploy${input.environment === "prod" ? "" : `-${input.environment}`}.yml`,
      target: AwsTargetSchema.parse(input.target),
      branch: input.branch ?? "main",
    }),
};

export default AWS_MANAGED_PROVIDER;
