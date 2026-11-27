/**
 * Dynamic loader for the separately-installed `@opscrew/provider-aws` managed-cloud plugin
 * (Feature 034, ADR 0040). Core never bundles `@opscrew/provider-aws` directly.
 */
import type { ManagedCloudConnector, ManagedCloudProviderDefinition } from "@opscrew/contracts";
import { loadManagedProviderPlugin, OpsCrewError } from "@opscrew/core";
import { type AwsTarget, AwsTargetSchema, type DeployPlan } from "@opscrew/plan-schema";
import type { PhaseDeps } from "../context";

/** Loaded AWS plugin with all pure hooks verified present. */
export interface LoadedAwsPlugin extends ManagedCloudProviderDefinition {
  readonly designTarget: NonNullable<ManagedCloudProviderDefinition["designTarget"]>;
  readonly applyOverrides: NonNullable<ManagedCloudProviderDefinition["applyOverrides"]>;
  readonly renderHcl: NonNullable<ManagedCloudProviderDefinition["renderHcl"]>;
  readonly renderWorkflow: NonNullable<ManagedCloudProviderDefinition["renderWorkflow"]>;
}

/** Options accepted by every AWS phase to support plugin/connector injection in tests. */
export interface AwsPluginOptions {
  /** Pre-loaded plugin override (for deterministic unit tests). */
  readonly plugin?: ManagedCloudProviderDefinition;
  /** Pre-built connector override (for deterministic unit tests). */
  readonly connector?: ManagedCloudConnector;
  /** Allow resolving the workspace package when not yet installed in `<homeDir>/plugins/aws`. */
  readonly allowWorkspaceFallback?: boolean;
}

/** Loads and validates the `@opscrew/provider-aws` managed-cloud plugin. */
export async function loadAwsPlugin(
  deps: Pick<PhaseDeps, "paths" | "runner" | "env" | "reporter">,
  options: AwsPluginOptions = {},
): Promise<LoadedAwsPlugin> {
  const loaded =
    options.plugin ??
    (await loadManagedProviderPlugin("aws", {
      homeDir: deps.paths.homeDir,
      runner: deps.runner,
      env: deps.env,
      reporter: deps.reporter,
      allowWorkspaceFallback: options.allowWorkspaceFallback ?? true,
    }));
  if (
    typeof loaded.designTarget !== "function" ||
    typeof loaded.applyOverrides !== "function" ||
    typeof loaded.renderHcl !== "function" ||
    typeof loaded.renderWorkflow !== "function"
  ) {
    throw new OpsCrewError(
      "ARTIFACT_INVALID",
      `Installed AWS provider plugin (${loaded.packageName}) is missing required design/render hooks.`,
      { hint: "Reinstall the plugin with `opscrew plugin add aws`." },
    );
  }
  return loaded as LoadedAwsPlugin;
}

/** Creates an injected AWS connector from `plugin` and `deps` (or returns `options.connector`). */
export function resolveAwsConnector(
  plugin: ManagedCloudProviderDefinition,
  deps: Pick<PhaseDeps, "fetch" | "env" | "redactor" | "clock">,
  options: AwsPluginOptions = {},
): ManagedCloudConnector {
  if (options.connector !== undefined) return options.connector;
  return plugin.createConnector({
    fetch: deps.fetch,
    env: deps.env,
    redactor: deps.redactor,
    now: () => deps.clock.now(),
  });
}

/** Extracts and validates the `AwsTarget` from `plan`, throwing `PHASE_PRECONDITION` if not AWS. */
export function requireAwsTarget(plan: DeployPlan): AwsTarget {
  if (plan.target.provider !== "aws") {
    throw new OpsCrewError(
      "PHASE_PRECONDITION",
      `This plan targets ${plan.target.provider}, not AWS.`,
      { hint: "Run `opscrew interview` and choose AWS, or `opscrew retarget --to aws`." },
    );
  }
  return AwsTargetSchema.parse(plan.target);
}
