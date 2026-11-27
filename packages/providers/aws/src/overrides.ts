/**
 * Override engine for `opscrew design --set <component>.<field>=<value>` on AWS targets
 * (Feature 034, US2, ADR 0040 D6). Re-validates guardrails, re-prices, and returns a plain-English
 * cost & field diff before apply.
 */
import { type AwsTarget, AwsTargetSchema } from "@opscrew/plan-schema";
import { AwsProviderError } from "./connector";
import { AWS_UNIT_RATES_USD, estimateAwsMonthlyCost, regionalUsd, roundUsd } from "./pricing";

export interface AwsOverrideEntry {
  readonly path: string;
  readonly rawValue: string;
  readonly value: string | number | boolean;
}

export interface AwsOverrideResult {
  readonly target: AwsTarget;
  readonly beforeMonthlyUsd: number;
  readonly afterMonthlyUsd: number;
  readonly deltaMonthlyUsd: number;
  readonly changes: readonly string[];
  readonly warnings: readonly string[];
}

/** Parses `true`/`false`/number/string literals from a CLI `--set key=value` string. */
function parseScalar(raw: string): string | number | boolean {
  if (raw === "true") return true;
  if (raw === "false") return false;
  if (/^-?\d+(?:\.\d+)?$/.test(raw)) return Number(raw);
  return raw;
}

/** Parses one `--set <path>=<value>` flag into a typed override entry. */
export function parseAwsSetFlag(expr: string): AwsOverrideEntry {
  const eq = expr.indexOf("=");
  if (eq <= 0 || eq === expr.length - 1) {
    throw new AwsProviderError(
      "INVALID_INPUT",
      `Invalid --set override "${expr}": expected <component>.<field>=<value> (for example, network.natGateway=false or database.multiAz=true).`,
    );
  }
  const path = expr.slice(0, eq).trim();
  const rawValue = expr.slice(eq + 1).trim();
  if (!/^[a-zA-Z][a-zA-Z0-9_-]*(?:\.[a-zA-Z][a-zA-Z0-9_-]*)*$/.test(path)) {
    throw new AwsProviderError(
      "INVALID_INPUT",
      `Invalid --set path "${path}": use dot-separated field names such as database.multiAz or observability.logsRetentionDays.`,
    );
  }
  return { path, rawValue, value: parseScalar(rawValue) };
}

/** Recomputes component cost adjustments when key cost-driving config fields change. */
function repriceComponent(
  name: string,
  service: string,
  config: Record<string, string | number | boolean>,
  currentUsd: number,
  region: string,
): number {
  if (name === "network") {
    if (config.natGateway === false) return 0;
    const azs = typeof config.natAzs === "number" && config.natAzs > 0 ? config.natAzs : 1;
    return regionalUsd(AWS_UNIT_RATES_USD.natGatewayPerAzMonthly * azs, region);
  }
  if (name === "database" && service === "rds-postgres") {
    const base =
      config.instanceClass === "db.t4g.small"
        ? AWS_UNIT_RATES_USD.rdsSmallSingleAzMonthly
        : AWS_UNIT_RATES_USD.rdsMicroSingleAzMonthly;
    return regionalUsd(base * (config.multiAz === true ? 2 : 1), region);
  }
  if (name === "database" && service === "aurora-postgres-serverless-v2") {
    return regionalUsd(
      config.minAcu === 0
        ? AWS_UNIT_RATES_USD.auroraServerlessPauseMonthly
        : AWS_UNIT_RATES_USD.auroraServerlessHalfAcuMonthly,
      region,
    );
  }
  return currentUsd;
}

/**
 * Applies one or more `--set <component>.<field>=<value>` overrides to an `AwsTarget`, validates
 * the updated target through `AwsTargetSchema` (enforcing guardrails & pin rules), re-prices, and
 * reports the exact before/after monthly cost difference.
 */
export function applyAwsOverrides(
  target: AwsTarget,
  expressions: readonly string[],
): AwsOverrideResult {
  const before = estimateAwsMonthlyCost(target);
  const draft: AwsTarget = structuredClone(target);
  const changes: string[] = [];

  for (const expr of expressions) {
    const entry = parseAwsSetFlag(expr);
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
      }
      changes.push(`${head}: ${String(prev)} → ${String(entry.value)}`);
      continue;
    }

    if (head === "pins" && field !== undefined && parts.length === 2) {
      const prev = (draft.pins as Record<string, unknown>)[field];
      (draft.pins as Record<string, unknown>)[field] = entry.value;
      changes.push(`pins.${field}: ${String(prev ?? "unset")} → ${String(entry.value)}`);
      continue;
    }

    if (head === "observability" && field !== undefined && parts.length === 2) {
      const prev = (draft.observability as Record<string, unknown>)[field];
      (draft.observability as Record<string, unknown>)[field] = entry.value;
      changes.push(`observability.${field}: ${String(prev)} → ${String(entry.value)}`);
      continue;
    }

    if (head === "guardrails" && field !== undefined && parts.length === 2) {
      const prev = (draft.guardrails as Record<string, unknown>)[field];
      (draft.guardrails as Record<string, unknown>)[field] = entry.value;
      changes.push(`guardrails.${field}: ${String(prev)} → ${String(entry.value)}`);
      continue;
    }

    if (head !== undefined && field !== undefined) {
      const comp = draft.components[head];
      if (comp === undefined) {
        const known = Object.keys(draft.components).join(", ");
        throw new AwsProviderError(
          "INVALID_INPUT",
          `Unknown AWS component "${head}" in --set ${expr}. Available components: ${known}.`,
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
        changes.push(`${head}.service: ${prev} → ${entry.value}`);
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
      changes.push(`${head}.${configKey}: ${String(prev ?? "unset")} → ${String(entry.value)}`);
      continue;
    }

    throw new AwsProviderError("INVALID_INPUT", `Unsupported --set override "${expr}".`);
  }

  const parsed = AwsTargetSchema.safeParse(draft);
  if (!parsed.success) {
    const first = parsed.error.issues[0];
    const where = first?.path.join(".") ?? "target";
    throw new AwsProviderError(
      "INVALID_INPUT",
      `Override rejected at ${where}: ${first?.message ?? "invalid AWS target"}.`,
    );
  }

  const after = estimateAwsMonthlyCost(parsed.data);
  return {
    target: parsed.data,
    beforeMonthlyUsd: before.totalMonthlyUsd,
    afterMonthlyUsd: after.totalMonthlyUsd,
    deltaMonthlyUsd: roundUsd(after.totalMonthlyUsd - before.totalMonthlyUsd),
    changes,
    warnings: after.warnings,
  };
}
