/**
 * AWS design phase orchestration (Feature 034, T3408).
 *
 * Delegates preset sizing, pricing, and `--set` overrides to the dynamically loaded
 * `@opscrew/provider-aws` plugin while validating every returned target and final plan with core's
 * own zod schemas (`AwsTargetSchema`, `DeployPlanSchema`).
 */
import type { ManagedCloudCostLine } from "@opscrew/contracts";
import { OpsCrewError } from "@opscrew/core";
import {
  type AwsPreset,
  type AwsTarget,
  AwsTargetSchema,
  type CostEstimate,
  type DeployPlan,
  DeployPlanSchema,
  type DesignOption,
  infraDirFor,
  type ProjectFacts,
  type Requirements,
  readArtifact,
  workflowPathFor,
} from "@opscrew/plan-schema";
import type { PhaseDeps } from "../context";
import { readEnvironmentRequirements } from "../environments/requirements";
import { writePlan } from "../shared";
import { type AwsPluginOptions, loadAwsPlugin } from "./loader";

const PRESETS: readonly AwsPreset[] = ["lean", "balanced", "production-ha"];

export interface RunAwsDesignOptions extends AwsPluginOptions {
  /** Option id (`aws-lean` / `lean`, `aws-balanced` / `balanced`, `aws-production-ha` / `production-ha`). */
  readonly optionId?: string;
  /** Interactive option picker when `optionId` is not set. */
  readonly choose?: (options: readonly DesignOption[]) => Promise<string>;
  /** Repeatable `--set <component>.<field>=<value>` overrides applied to the chosen preset. */
  readonly setFlags?: readonly string[];
  /** Explicit project facts override (default: `opscrew/architecture.json`). */
  readonly facts?: ProjectFacts;
  /** Explicit requirements override (default: `opscrew/requirements.yaml`). */
  readonly requirements?: Requirements;
  /** Default git branch for generated CI/CD workflow. */
  readonly branch?: string;
  /** App name override (defaults to sanitized project directory/facts name). */
  readonly appName?: string;
}

export interface AwsDesignResult {
  readonly options: DesignOption[];
  readonly chosen: DesignOption;
  readonly target: AwsTarget;
  readonly plan: DeployPlan;
  readonly priceSource: "live" | "static";
  readonly warnings: string[];
  readonly lines: string[];
  readonly costLines: readonly ManagedCloudCostLine[];
  readonly appliedOverrides: readonly {
    readonly component: string;
    readonly field: string;
    readonly value: string;
  }[];
}

function defaultPresetFor(requirements: Requirements): AwsPreset {
  if (requirements.uptime === "high" || requirements.expectedMonthlyUsers === ">100k") {
    return "production-ha";
  }
  if (
    requirements.uptime === "best-effort" ||
    requirements.expectedMonthlyUsers === "<1k" ||
    requirements.budgetMonthly.amount <= 45
  ) {
    return "lean";
  }
  return "balanced";
}

function normalizePresetChoice(optionId: string): AwsPreset | undefined {
  const cleaned = optionId.trim().toLowerCase().replace(/^aws-/, "");
  if (cleaned === "lean" || cleaned === "balanced" || cleaned === "production-ha") {
    return cleaned;
  }
  return undefined;
}

function sanitizeAppName(raw: string): string {
  const cleaned = raw
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 41);
  return cleaned.length > 0 && /^[a-z0-9]/.test(cleaned) ? cleaned : "app";
}

function buildAwsCostEstimate(target: AwsTarget, asOf: string): CostEstimate {
  const breakdown = Object.entries(target.components).map(([name, comp]) => ({
    item: `${name}: ${comp.service}`,
    provider: "aws",
    monthly: { amount: Math.round(comp.monthlyCostUsd * 100) / 100, currency: "USD" as const },
    billing: "monthly" as const,
  }));
  const monthlyAmount =
    Math.round(breakdown.reduce((sum, line) => sum + line.monthly.amount, 0) * 100) / 100;
  return {
    monthly: { amount: monthlyAmount, currency: "USD" },
    breakdown,
    pricesIncludeVat: false,
    source: "static",
    asOf,
  };
}

/**
 * Designs an AWS managed-services deployment plan across `lean`, `balanced`, and `production-ha`
 * presets, applies any `--set` overrides, validates against `AwsTargetSchema` & `DeployPlanSchema`,
 * and persists `opscrew/plan.yaml`.
 */
export async function runAwsDesign(
  deps: PhaseDeps,
  options: RunAwsDesignOptions = {},
): Promise<AwsDesignResult> {
  const facts =
    options.facts ?? (await readArtifact("architecture", deps.paths.files.architecture)).facts;
  const requirements = options.requirements ?? (await readEnvironmentRequirements(deps.paths));
  const plugin = await loadAwsPlugin(deps, options);
  const nowIso = deps.clock.now().toISOString();

  const recommendedPreset = defaultPresetFor(requirements);
  const designedByPreset = new Map<
    AwsPreset,
    {
      target: AwsTarget;
      estimatedMonthlyUsd: number;
      costLines: readonly ManagedCloudCostLine[];
      costTrapWarnings: readonly string[];
      notes: readonly string[];
    }
  >();

  for (const preset of PRESETS) {
    const raw = plugin.designTarget({ facts, requirements, preset });
    const validatedTarget = AwsTargetSchema.parse(raw.target);
    designedByPreset.set(preset, {
      target: validatedTarget,
      estimatedMonthlyUsd: raw.estimatedMonthlyUsd,
      costLines: raw.costLines,
      costTrapWarnings: raw.costTrapWarnings,
      notes: raw.notes,
    });
  }

  const designOptions: DesignOption[] = PRESETS.map((preset) => {
    const entry = designedByPreset.get(preset);
    if (entry === undefined) {
      throw new OpsCrewError("INTERNAL", `Missing designed preset "${preset}".`);
    }
    const cost = buildAwsCostEstimate(entry.target, nowIso);
    const summaryParts = [
      `AWS ${preset} (${entry.target.compute}, ${entry.target.region})`,
      ...Object.entries(entry.target.components).map(([name, c]) => `${name}: ${c.service}`),
    ];
    return {
      id: `aws-${preset}`,
      title: `AWS ${preset} — ${entry.target.compute}`,
      summary: summaryParts.join("; "),
      target: {
        provider: "aws",
        location: entry.target.region,
        serverType: entry.target.compute,
        vcpus: preset === "production-ha" ? 2 : 1,
        memoryGb: preset === "production-ha" ? 4 : preset === "balanced" ? 2 : 1,
        diskGb: 20,
        cpuType: "shared",
        architecture: "arm",
      },
      services: [],
      externalServices: [],
      backups: requirements.dataCriticality !== "none",
      cost,
      fitsBudget: cost.monthly.amount <= requirements.budgetMonthly.amount,
      recommended: preset === recommendedPreset,
      tradeoffs: [...entry.notes, ...entry.costTrapWarnings],
    };
  });

  let chosenPreset: AwsPreset = recommendedPreset;
  if (options.optionId !== undefined) {
    const parsed = normalizePresetChoice(options.optionId);
    if (parsed === undefined) {
      throw new OpsCrewError("INVALID_INPUT", `Unknown AWS design option "${options.optionId}".`, {
        hint: `Choose one of: ${designOptions.map((o) => o.id).join(", ")}.`,
      });
    }
    chosenPreset = parsed;
  } else if (options.choose !== undefined) {
    const pickedId = await options.choose(designOptions);
    const parsed = normalizePresetChoice(pickedId);
    if (parsed === undefined) {
      throw new OpsCrewError("INVALID_INPUT", `Unknown AWS design option "${pickedId}".`);
    }
    chosenPreset = parsed;
  }

  const baseDesign = designedByPreset.get(chosenPreset);
  if (baseDesign === undefined) {
    throw new OpsCrewError("INTERNAL", `Missing designed preset "${chosenPreset}".`);
  }
  let finalTarget = baseDesign.target;
  const warnings: string[] = [...baseDesign.costTrapWarnings];
  const lines: string[] = [...baseDesign.notes];
  let appliedOverrides: readonly { component: string; field: string; value: string }[] = [];

  if (options.setFlags !== undefined && options.setFlags.length > 0) {
    const overridden = plugin.applyOverrides({
      target: finalTarget,
      setFlags: options.setFlags,
    });
    finalTarget = AwsTargetSchema.parse(overridden.target);
    appliedOverrides = overridden.applied;
    warnings.push(...overridden.warnings);
    const sign = overridden.deltaMonthlyUsd >= 0 ? "+" : "";
    lines.push(
      `Applied ${overridden.applied.length} override(s): monthly estimate $${overridden.beforeMonthlyUsd.toFixed(2)} -> $${overridden.afterMonthlyUsd.toFixed(2)} (${sign}$${overridden.deltaMonthlyUsd.toFixed(2)}/mo).`,
    );
  }

  for (const [componentName, component] of Object.entries(finalTarget.components)) {
    lines.push(
      `${componentName}: ${component.service} ($${component.monthlyCostUsd.toFixed(2)}/mo) — ${component.why}`,
    );
  }
  if (finalTarget.exceptions.length > 0) {
    warnings.push(
      `Guardrail exceptions recorded: ${finalTarget.exceptions.map((e) => `${e.guardrail} (${e.reason})`).join(", ")}.`,
    );
  }

  for (const warning of warnings) {
    deps.reporter.warn(deps.redactor.redact(warning));
  }

  const finalCost = buildAwsCostEstimate(finalTarget, nowIso);
  const envName = deps.paths.environment;
  const baseName = sanitizeAppName(options.appName ?? facts.name);
  const appName = envName === "prod" ? baseName : sanitizeAppName(`${baseName}-${envName}`);
  const domain = requirements.domain?.trim();
  const dnsProvider =
    domain !== undefined &&
    domain.length > 0 &&
    (finalTarget.pins.keepCloudflareDns || requirements.dnsProvider === "cloudflare")
      ? ("cloudflare" as const)
      : ("none" as const);

  const deployTagsMode = requirements.deployTags ?? "off";
  const plan: DeployPlan = DeployPlanSchema.parse({
    schemaVersion: 1,
    createdAt: nowIso,
    updatedAt: nowIso,
    app: {
      name: appName,
      port: facts.port ?? 3000,
      healthPath: facts.healthEndpoint ?? "/health",
      env: [],
    },
    target: finalTarget,
    processes: { workers: [], cron: [] },
    services: [],
    externalServices: [],
    cost: finalCost,
    codeChanges: [],
    infra: {
      engine: "tofu",
      dir: infraDirFor(deps.paths.app, envName),
    },
    dns: {
      provider: dnsProvider,
      ...(domain !== undefined && domain.length > 0 ? { domain } : {}),
      proxied: dnsProvider === "cloudflare" && finalTarget.pins.keepCloudflareDns,
    },
    cicd: {
      provider: "github-actions",
      workflowPath: workflowPathFor(deps.paths.app, envName),
      registry: "ghcr",
      branch: options.branch ?? "main",
      deployTags: {
        enabled: deployTagsMode !== "off",
        release: deployTagsMode === "tag-and-release",
      },
    },
    supplyChain: {
      sign: requirements.signImages ?? false,
    },
  });

  await writePlan(deps, deps.paths.files.plan, plan);

  const chosenOption = designOptions.find((o) => o.id === `aws-${chosenPreset}`);
  if (chosenOption === undefined) {
    throw new OpsCrewError("INTERNAL", `Missing option entry for preset "${chosenPreset}".`);
  }
  const updatedChosen: DesignOption = {
    ...chosenOption,
    cost: finalCost,
    fitsBudget: finalCost.monthly.amount <= requirements.budgetMonthly.amount,
  };
  deps.reporter.success(
    `Designed AWS ${finalTarget.preset} plan (${finalTarget.compute}, ${finalTarget.region}, ~$${finalCost.monthly.amount.toFixed(2)}/mo USD).`,
  );

  return {
    options: designOptions.map((o) => (o.id === updatedChosen.id ? updatedChosen : o)),
    chosen: updatedChosen,
    target: finalTarget,
    plan,
    priceSource: "static",
    warnings,
    lines,
    costLines: baseDesign.costLines,
    appliedOverrides,
  };
}
