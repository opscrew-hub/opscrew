/**
 * Contract for separately installed managed-cloud provider plugins (ADR 0040, feature 034: AWS,
 * later Azure 038 and Google Cloud 039).
 *
 * Only plain data, regular expressions and pure/injected functions cross this boundary — never zod
 * schemas or class instances — so a plugin installed into `~/.opscrew/plugins/<id>` can carry its
 * own dependencies while core validates every output with core's own schemas and retains all
 * approval gates, policy enforcement, IaC apply, and secret redaction (Constitution I and IV).
 */

import type { CommandResult, FetchLike } from "./io";
import type { ProviderRedactor } from "./provider";

/** Current version of {@link ManagedCloudProviderDefinition}. Checked before dynamic `import()`. */
export const MANAGED_CLOUD_CONTRACT_VERSION = 1 as const;

/** Official managed-cloud provider ids supported by the installable plugin system. */
export type ManagedCloudProviderId = "aws" | "azure" | "gcp";

/** Credential requirements for a managed-cloud provider (names only — never values). */
export interface ManagedCloudCredentialSpec {
  /** Environment variables checked for API/CLI authentication. */
  readonly envVars: readonly string[];
  /** Optional profile/config hints (e.g., `AWS_PROFILE`, `~/.aws/credentials`). */
  readonly profileEnvVars?: readonly string[];
  /** Regex patterns used by core's redactor and secret scanner to detect leaked tokens/keys. */
  readonly secretPatterns: readonly {
    readonly id: string;
    readonly title: string;
    readonly pattern: RegExp;
  }[];
  /** Console URL where the user manages credentials or OIDC roles. */
  readonly consoleUrl: string;
  /** Plain-English instructions for obtaining least-privilege credentials. */
  readonly instructions: string;
}

/** A cloud region offered by a managed-cloud provider. */
export interface ManagedCloudRegion {
  readonly id: string;
  readonly label: string;
  readonly geography: "eu-central" | "eu-north" | "us-east" | "us-west" | "ap-southeast";
  /** Relative pricing multiplier against the reference region (e.g., `1.0` for `us-east-1`). */
  readonly priceMultiplier: number;
  /** True when the region supports newer compute primitives (e.g., AWS Lambda Web Functions). */
  readonly supportsLambdaWeb?: boolean;
}

/** An itemized monthly cost line returned by a managed-cloud provider's pricer. */
export interface ManagedCloudCostLine {
  readonly component: string;
  readonly label: string;
  readonly monthlyUsd: number;
  readonly notes?: string;
}

/** A rendered infrastructure, workflow, or documentation file produced by a plugin. */
export interface ManagedCloudRenderedFile {
  readonly path: string;
  readonly content: string;
  readonly kind: "iac" | "workflow" | "runtime" | "docs";
}

/** Out-of-band secret write performed after plan-hash approval (never embedded in Terraform state). */
export interface ManagedCloudSecretWrite {
  readonly store: "secrets-manager" | "ssm-parameter";
  readonly name: string;
  readonly value: string;
  readonly description?: string;
}

/** Live status summary returned by a managed-cloud connector (read-only). */
export interface ManagedCloudStatusSummary {
  readonly healthy: boolean;
  readonly region: string;
  readonly accountId?: string;
  readonly compute: {
    readonly kind: string;
    readonly status: string;
    readonly desiredCount?: number;
    readonly runningCount?: number;
    readonly endpoint?: string;
  };
  readonly services: readonly {
    readonly name: string;
    readonly service: string;
    readonly status: string;
    readonly detail?: string;
  }[];
  readonly alarms?: readonly {
    readonly name: string;
    readonly state: "OK" | "ALARM" | "INSUFFICIENT_DATA";
    readonly reason?: string;
  }[];
}

/** A single redacted log line fetched from managed cloud logging (e.g., CloudWatch Logs). */
export interface ManagedCloudLogLine {
  readonly timestamp: string;
  readonly stream: string;
  readonly message: string;
}

/** A managed database/storage snapshot metadata record. */
export interface ManagedCloudSnapshotEntry {
  readonly id: string;
  readonly service: string;
  readonly engine: string;
  readonly createdAt: string;
  readonly status: string;
  readonly sizeGb?: number;
}

/** Result of an isolated throwaway restore drill (ADR 0034). */
export interface ManagedCloudRestoreDrillResult {
  readonly snapshotId: string;
  readonly service: string;
  readonly verified: boolean;
  readonly durationMs: number;
  readonly cleanedUp: boolean;
  readonly detail: string;
}

/** Dependencies injected by core into a managed-cloud connector (never global network/env). */
export interface ManagedCloudConnectorDeps {
  readonly fetch: FetchLike;
  readonly env: Readonly<Record<string, string | undefined>>;
  readonly redactor: ProviderRedactor;
  readonly now?: () => Date;
  readonly sleep?: (ms: number) => Promise<void>;
  readonly maxPollAttempts?: number;
}

/**
 * Typed cloud API adapter created by a managed-cloud plugin.
 * Read-only methods run freely; mutating methods are called ONLY by core after plan-hash approval.
 */
export interface ManagedCloudConnector {
  verifyCredentials(): Promise<{
    readonly ok: boolean;
    readonly accountId?: string;
    readonly principalArn?: string;
    readonly error?: string;
  }>;
  readStatus(input: {
    readonly appName: string;
    readonly environment: string;
    readonly region: string;
    readonly computeKind: string;
  }): Promise<ManagedCloudStatusSummary>;
  readLogs(input: {
    readonly logGroup: string;
    readonly region: string;
    readonly since?: Date;
    readonly limit?: number;
    readonly filterPattern?: string;
  }): Promise<readonly ManagedCloudLogLine[]>;
  writeSecrets(input: {
    readonly region: string;
    readonly secrets: readonly ManagedCloudSecretWrite[];
  }): Promise<{ readonly written: readonly string[] }>;
  listSnapshots(input: {
    readonly region: string;
    readonly identifierPrefix: string;
  }): Promise<readonly ManagedCloudSnapshotEntry[]>;
  takeSnapshot(input: {
    readonly region: string;
    readonly service: string;
    readonly instanceId: string;
    readonly snapshotId: string;
  }): Promise<ManagedCloudSnapshotEntry>;
  runRestoreDrill(input: {
    readonly region: string;
    readonly snapshotId: string;
    readonly service: string;
    readonly drillInstanceId: string;
    readonly dbSubnetGroupName?: string;
    readonly vpcSecurityGroupIds?: readonly string[];
  }): Promise<ManagedCloudRestoreDrillResult>;
}

/** Plain-data definition exported as default / named export by `@opscrew/provider-<id>`. */
export interface ManagedCloudProviderDefinition {
  readonly contractVersion: typeof MANAGED_CLOUD_CONTRACT_VERSION;
  readonly id: ManagedCloudProviderId;
  readonly displayName: string;
  readonly packageName: string;
  readonly credentials: ManagedCloudCredentialSpec;
  readonly regions: readonly ManagedCloudRegion[];
  readonly presets: readonly ("lean" | "balanced" | "production-ha")[];
  readonly createConnector: (deps: ManagedCloudConnectorDeps) => ManagedCloudConnector;
  /** Pure target designer; core validates the returned `target` with its own zod schema. */
  readonly designTarget?: (input: {
    readonly facts: unknown;
    readonly requirements: unknown;
    readonly preset?: "lean" | "balanced" | "production-ha";
    readonly pins?: unknown;
  }) => {
    readonly target: unknown;
    readonly estimatedMonthlyUsd: number;
    readonly costLines: readonly ManagedCloudCostLine[];
    readonly costTrapWarnings: readonly string[];
    readonly notes: readonly string[];
  };
  /** Pure `--set` override applier; core validates the returned `target` with its own zod schema. */
  readonly applyOverrides?: (input: {
    readonly target: unknown;
    readonly setFlags: readonly string[];
  }) => {
    readonly target: unknown;
    readonly beforeMonthlyUsd: number;
    readonly afterMonthlyUsd: number;
    readonly deltaMonthlyUsd: number;
    readonly applied: readonly {
      readonly component: string;
      readonly field: string;
      readonly value: string;
    }[];
    readonly warnings: readonly string[];
  };
  /** Pure vendored OpenTofu/Terraform HCL renderer. */
  readonly renderHcl?: (input: {
    readonly appName: string;
    readonly environment: string;
    readonly target: unknown;
    readonly domain?: string;
    readonly dnsProvider?: string;
    readonly githubRepo: string;
    readonly githubOrgId?: string;
    readonly githubRepoId?: string;
    readonly branch?: string;
    readonly containerPort?: number;
    readonly endpointUrl?: string;
  }) => readonly ManagedCloudRenderedFile[];
  /** Pure keyless OIDC GitHub Actions deploy workflow renderer. */
  readonly renderWorkflow?: (input: {
    readonly appName: string;
    readonly environment: string;
    readonly target: unknown;
    readonly branch?: string;
    readonly imageRegistry?: "ghcr" | "ecr";
    readonly roleArnVar?: string;
  }) => ManagedCloudRenderedFile;
}

/** Provenance policy enforced by core when verifying an official plugin package from npm. */
export interface PluginProvenancePolicy {
  readonly repository: string;
  readonly workflowPath: string;
  readonly refPrefix: string;
}

/** Entry in core's allowlist of official installable provider packages. */
export interface OfficialPluginSpec {
  readonly id: ManagedCloudProviderId;
  readonly packageName: string;
  readonly version: string;
  readonly contractVersion: typeof MANAGED_CLOUD_CONTRACT_VERSION;
  readonly displayName: string;
  readonly companionClaudePlugin?: string;
  readonly provenance: PluginProvenancePolicy;
}

/** Metadata recorded on disk under `~/.opscrew/plugins/<id>/opscrew-plugin.json`. */
export interface InstalledPluginRecord {
  readonly id: ManagedCloudProviderId;
  readonly packageName: string;
  readonly version: string;
  readonly contractVersion: number;
  readonly installedAt: string;
  readonly verifiedProvenance: boolean;
  readonly installDir: string;
}

/** Verifier hook used by core's plugin installer (injectable for deterministic tests). */
export type PluginSignatureVerifier = (input: {
  readonly installDir: string;
  readonly spec: OfficialPluginSpec;
  readonly runNpm: (args: readonly string[]) => Promise<CommandResult>;
}) => Promise<{ readonly verified: boolean; readonly detail: string }>;
