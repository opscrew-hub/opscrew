/**
 * Dynamic loader for the separately-installed `@opscrew/provider-gcp` managed-cloud plugin
 * (Feature 039, ADR 0040). Core never bundles `@opscrew/provider-gcp` directly.
 */
import type { ManagedCloudConnector, ManagedCloudProviderDefinition } from "@opscrew/contracts";
import { loadManagedProviderPlugin, OpsCrewError } from "@opscrew/core";
import { type DeployPlan, type GcpTarget, GcpTargetSchema } from "@opscrew/plan-schema";
import type { PhaseDeps } from "../context";

export interface LoadedGcpPlugin extends ManagedCloudProviderDefinition {
  readonly designTarget: NonNullable<ManagedCloudProviderDefinition["designTarget"]>;
  readonly applyOverrides: NonNullable<ManagedCloudProviderDefinition["applyOverrides"]>;
  readonly renderHcl: NonNullable<ManagedCloudProviderDefinition["renderHcl"]>;
  readonly renderWorkflow: NonNullable<ManagedCloudProviderDefinition["renderWorkflow"]>;
}

export interface GcpPluginOptions {
  readonly plugin?: ManagedCloudProviderDefinition;
  readonly connector?: ManagedCloudConnector;
  readonly allowWorkspaceFallback?: boolean;
}

export async function loadGcpPlugin(
  deps: Pick<PhaseDeps, "paths" | "runner" | "env" | "reporter">,
  options: GcpPluginOptions = {},
): Promise<LoadedGcpPlugin> {
  const loaded =
    options.plugin ??
    (await loadManagedProviderPlugin("gcp", {
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
      `Installed GCP provider plugin (${loaded.packageName}) is missing required design/render hooks.`,
      { hint: "Reinstall the plugin with `opscrew plugin add gcp`." },
    );
  }
  return loaded as LoadedGcpPlugin;
}

export function resolveGcpConnector(
  plugin: ManagedCloudProviderDefinition,
  deps: Pick<PhaseDeps, "fetch" | "env" | "redactor" | "clock">,
  options: GcpPluginOptions = {},
): ManagedCloudConnector {
  if (options.connector !== undefined) return options.connector;
  return plugin.createConnector({
    fetch: deps.fetch,
    env: deps.env,
    redactor: deps.redactor,
    now: () => deps.clock.now(),
    sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  });
}

export function requireGcpTarget(plan: DeployPlan): GcpTarget {
  if (plan.target.provider !== "gcp") {
    throw new OpsCrewError(
      "PHASE_PRECONDITION",
      `This plan targets ${plan.target.provider}, not Google Cloud.`,
      {
        hint: "Run `opscrew interview` and choose Google Cloud, or install `@opscrew/provider-gcp`.",
      },
    );
  }
  return GcpTargetSchema.parse(plan.target);
}
