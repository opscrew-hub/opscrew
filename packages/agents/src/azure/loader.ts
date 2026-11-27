/**
 * Dynamic loader for the separately-installed `@opscrew/provider-azure` managed-cloud plugin
 * (Feature 038, ADR 0040). Core never bundles `@opscrew/provider-azure` directly.
 */
import type { ManagedCloudConnector, ManagedCloudProviderDefinition } from "@opscrew/contracts";
import { loadManagedProviderPlugin, OpsCrewError } from "@opscrew/core";
import { type AzureTarget, AzureTargetSchema, type DeployPlan } from "@opscrew/plan-schema";
import type { PhaseDeps } from "../context";

export interface LoadedAzurePlugin extends ManagedCloudProviderDefinition {
  readonly designTarget: NonNullable<ManagedCloudProviderDefinition["designTarget"]>;
  readonly applyOverrides: NonNullable<ManagedCloudProviderDefinition["applyOverrides"]>;
  readonly renderHcl: NonNullable<ManagedCloudProviderDefinition["renderHcl"]>;
  readonly renderWorkflow: NonNullable<ManagedCloudProviderDefinition["renderWorkflow"]>;
}

export interface AzurePluginOptions {
  /** Pre-loaded plugin override (for deterministic unit tests). */
  readonly plugin?: ManagedCloudProviderDefinition;
  /** Pre-built connector override (for deterministic unit tests). */
  readonly connector?: ManagedCloudConnector;
  /** Explicitly opt in to workspace fallback in monorepo tests (default `false`, fail-closed). */
  readonly allowWorkspaceFallback?: boolean;
}

export async function loadAzurePlugin(
  deps: Pick<PhaseDeps, "paths" | "runner" | "env" | "reporter">,
  options: AzurePluginOptions = {},
): Promise<LoadedAzurePlugin> {
  const loaded =
    options.plugin ??
    (await loadManagedProviderPlugin("azure", {
      homeDir: deps.paths.homeDir,
      runner: deps.runner,
      env: deps.env,
      reporter: deps.reporter,
      allowWorkspaceFallback: options.allowWorkspaceFallback ?? false,
    }));
  if (
    typeof loaded.designTarget !== "function" ||
    typeof loaded.applyOverrides !== "function" ||
    typeof loaded.renderHcl !== "function" ||
    typeof loaded.renderWorkflow !== "function"
  ) {
    throw new OpsCrewError(
      "ARTIFACT_INVALID",
      `Installed Azure provider plugin (${loaded.packageName}) is missing required design/render hooks.`,
      { hint: "Reinstall the plugin with `opscrew plugin add azure`." },
    );
  }
  return loaded as LoadedAzurePlugin;
}

export function resolveAzureConnector(
  plugin: ManagedCloudProviderDefinition,
  deps: Pick<PhaseDeps, "fetch" | "env" | "redactor" | "clock">,
  options: AzurePluginOptions = {},
): ManagedCloudConnector {
  if (options.connector !== undefined) return options.connector;
  return plugin.createConnector({
    fetch: deps.fetch,
    env: deps.env,
    redactor: deps.redactor,
    now: () => deps.clock.now(),
  });
}

export function requireAzureTarget(plan: DeployPlan): AzureTarget {
  if (plan.target.provider !== "azure") {
    throw new OpsCrewError(
      "PHASE_PRECONDITION",
      `This plan targets ${plan.target.provider}, not Azure.`,
      { hint: "Run `opscrew interview` and choose Azure, or install `@opscrew/provider-azure`." },
    );
  }
  return AzureTargetSchema.parse(plan.target);
}
