/**
 * Override engine for `opscrew design --set <component>.<field>=<value>` on GCP targets
 * (Feature 039, T3902, ADR 0040 D6). Re-validates guardrails, re-prices, and returns a plain-English
 * cost & field diff before apply.
 */
import type { GcpTarget } from "@opscrew/plan-schema";
import { GcpProviderError } from "./connector";
import { estimateGcpMonthlyCost, GCP_UNIT_RATES_USD, regionalUsd, roundUsd } from "./pricing";
import { StandaloneGcpTargetSchema } from "./schema";

export interface GcpOverrideEntry {
  readonly path: string;
  readonly rawValue: string;
  readonly value: string | number | boolean;
}

export interface GcpOverrideResult {
  readonly target: GcpTarget;
  readonly beforeMonthlyUsd: number;
  readonly afterMonthlyUsd: number;
  readonly deltaMonthlyUsd: number;
  readonly changes: readonly string[];
  readonly warnings: readonly string[];
}

function parseScalar(raw: string): string | number | boolean {
  if (raw === "true") return true;
  if (raw === "false") return false;
  if (/^-?\d+(?:\.\d+)?$/.test(raw)) return Number(raw);
  return raw;
}

export function parseGcpSetFlag(expr: string): GcpOverrideEntry {
  const eq = expr.indexOf("=");
  if (eq <= 0 || eq === expr.length - 1) {
    throw new GcpProviderError(
      "INVALID_INPUT",
      `Invalid --set override "${expr}": expected <component>.<field>=<value> (for example, network.cloudNat=false or database.regionalHa=true).`,
    );
  }
  const path = expr.slice(0, eq).trim();
  const rawValue = expr.slice(eq + 1).trim();
  if (!/^[a-zA-Z][a-zA-Z0-9_-]*(?:\.[a-zA-Z][a-zA-Z0-9_-]*)*$/.test(path)) {
    throw new GcpProviderError(
      "INVALID_INPUT",
      `Invalid --set path "${path}": use dot-separated field names such as database.regionalHa or observability.logsRetentionDays.`,
    );
  }
  return { path, rawValue, value: parseScalar(rawValue) };
}

function repriceComponent(
  name: string,
  service: string,
  config: Record<string, string | number | boolean>,
  currentUsd: number,
  region: string,
): number {
  if (name === "network") {
    return config.cloudNat === true ? regionalUsd(GCP_UNIT_RATES_USD.cloudNatMonthly, region) : 0;
  }
  if (name === "edge") {
    return service === "global-alb-cloud-cdn"
      ? regionalUsd(GCP_UNIT_RATES_USD.globalAlbMonthly, region)
      : 0;
  }
  if (name === "compute") {
    if (service === "compute-engine") {
      return regionalUsd(GCP_UNIT_RATES_USD.computeEngineSmallMonthly, region);
    }
    const min = typeof config.minInstances === "number" ? config.minInstances : 0;
    const base =
      min >= 2
        ? GCP_UNIT_RATES_USD.cloudRunHaMonthly
        : min === 1
          ? GCP_UNIT_RATES_USD.cloudRunBalancedMonthly
          : GCP_UNIT_RATES_USD.cloudRunLeanMonthly;
    return regionalUsd(base, region);
  }
  if (name === "database" && service.startsWith("cloud-sql-")) {
    const base =
      config.tier === "db-f1-micro"
        ? GCP_UNIT_RATES_USD.cloudSqlMicroMonthly
        : GCP_UNIT_RATES_USD.cloudSqlDedicatedSingleMonthly;
    return regionalUsd(base * (config.regionalHa === true ? 2 : 1), region);
  }
  return currentUsd;
}

export function applyGcpOverrides(
  target: GcpTarget,
  expressions: readonly string[],
): GcpOverrideResult {
  const before = estimateGcpMonthlyCost(target);
  const draft: GcpTarget = structuredClone(target);
  const changes: string[] = [];

  for (const expr of expressions) {
    const entry = parseGcpSetFlag(expr);
    const parts = entry.path.split(".");
    const [head, field, sub] = parts;

    if (parts.length === 1 && (head === "region" || head === "preset" || head === "compute")) {
      const prev = draft[head];
      (draft as unknown as Record<string, unknown>)[head] = entry.value;
      if (
        head === "compute" &&
        typeof entry.value === "string" &&
        draft.components.compute !== undefined
      ) {
        draft.components.compute.service = entry.value;
        draft.components.compute.monthlyCostUsd = repriceComponent(
          "compute",
          entry.value,
          draft.components.compute.config,
          draft.components.compute.monthlyCostUsd,
          draft.region,
        );
      }
      changes.push(`${head}: ${String(prev)} -> ${String(entry.value)}`);
      continue;
    }

    if (head === "pins" && field !== undefined && parts.length === 2) {
      const prev = (draft.pins as Record<string, unknown>)[field];
      (draft.pins as Record<string, unknown>)[field] = entry.value;
      changes.push(`pins.${field}: ${String(prev ?? "unset")} -> ${String(entry.value)}`);
      continue;
    }

    if (head === "observability" && field !== undefined && parts.length === 2) {
      const prev = (draft.observability as Record<string, unknown>)[field];
      (draft.observability as Record<string, unknown>)[field] = entry.value;
      changes.push(`observability.${field}: ${String(prev)} -> ${String(entry.value)}`);
      continue;
    }

    if (head === "guardrails" && field !== undefined && parts.length === 2) {
      const prev = (draft.guardrails as Record<string, unknown>)[field];
      (draft.guardrails as Record<string, unknown>)[field] = entry.value;
      changes.push(`guardrails.${field}: ${String(prev)} -> ${String(entry.value)}`);
      continue;
    }

    if (head !== undefined && field !== undefined) {
      const comp = draft.components[head];
      if (comp === undefined) {
        const known = Object.keys(draft.components).join(", ");
        throw new GcpProviderError(
          "INVALID_INPUT",
          `Unknown GCP component "${head}" in --set ${expr}. Available components: ${known}.`,
        );
      }
      if (field === "service" && parts.length === 2 && typeof entry.value === "string") {
        const prev = comp.service;
        comp.service = entry.value;
        if (head === "compute") {
          (draft as unknown as Record<string, unknown>).compute = entry.value;
        }
        comp.monthlyCostUsd = repriceComponent(
          head,
          comp.service,
          comp.config,
          comp.monthlyCostUsd,
          draft.region,
        );
        changes.push(`${head}.service: ${prev} -> ${entry.value}`);
        continue;
      }
      const configKey = field === "config" && sub !== undefined ? sub : field;
      const prev = comp.config[configKey];
      comp.config[configKey] = entry.value;
      comp.monthlyCostUsd = repriceComponent(
        head,
        comp.service,
        comp.config,
        comp.monthlyCostUsd,
        draft.region,
      );
      changes.push(`${head}.${configKey}: ${String(prev ?? "unset")} -> ${String(entry.value)}`);
      continue;
    }

    throw new GcpProviderError("INVALID_INPUT", `Unsupported --set override "${expr}".`);
  }

  const parsed = StandaloneGcpTargetSchema.safeParse(draft);
  if (!parsed.success) {
    const first = parsed.error.issues[0];
    const where = first?.path.join(".") ?? "target";
    throw new GcpProviderError(
      "INVALID_INPUT",
      `Override rejected at ${where}: ${first?.message ?? "invalid GCP target"}.`,
    );
  }

  const after = estimateGcpMonthlyCost(parsed.data);
  return {
    target: parsed.data,
    beforeMonthlyUsd: before.totalMonthlyUsd,
    afterMonthlyUsd: after.totalMonthlyUsd,
    deltaMonthlyUsd: roundUsd(after.totalMonthlyUsd - before.totalMonthlyUsd),
    changes,
    warnings: after.warnings,
  };
}
