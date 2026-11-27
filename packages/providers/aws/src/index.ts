/**
 * `@opscrew/provider-aws` — Official installable AWS managed-services provider plugin
 * (Feature 034, ADR 0040).
 */
import {
  MANAGED_CLOUD_CONTRACT_VERSION,
  type ManagedCloudProviderDefinition,
} from "@opscrew/contracts";
import { createAwsConnector } from "./connector";
import { AWS_REGIONS } from "./pricing";

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
};

export default AWS_MANAGED_PROVIDER;
