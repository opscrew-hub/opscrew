/**
 * Override engine for `opscrew design --set <component>.<field>=<value>` on Azure targets
 * (Feature 038, T3802, ADR 0040 D6). Re-validates guardrails, re-prices, and returns a plain-English
 * cost & field diff before apply.
 */
import { type AzureTarget, AzureTargetSchema } from "@opscrew/plan-schema";
import { AzureProviderError } from "./connector";
import { AZURE_UNIT_RATES_USD, estimateAzureMonthlyCost, regionalUsd, roundUsd } from "./pricing";

export interface AzureOverrideEntry {
  readonly path: string;
  readonly rawValue: string;
  readonly value: string | number | boolean;
}

export interface AzureOverrideResult {
  readonly target: AzureTarget;
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

export function parseAzureSetFlag(expr: string): AzureOverrideEntry {
  const eq = expr.indexOf("=");
  if (eq <= 0 || eq === expr.length - 1) {
    throw new AzureProviderError(
      "INVALID_INPUT",
      `Invalid --set override "${expr}": expected <component>.<field>=<value> (for example, network.natGateway=false or database.zoneRedundant=true).`,
    );
  }
  const path = expr.slice(0, eq).trim();
  const rawValue = expr.slice(eq + 1).trim();
  if (!/^[a-zA-Z][a-zA-Z0-9_-]*(?:\.[a-zA-Z][a-zA-Z0-9_-]*)*$/.test(path)) {
    throw new AzureProviderError(
      "INVALID_INPUT",
      `Invalid --set path "${path}": use dot-separated field names such as database.zoneRedundant or observability.logsRetentionDays.`,
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
    return config.natGateway === true
      ? regionalUsd(AZURE_UNIT_RATES_USD.natGatewayMonthly, region)
      : 0;
  }
  if (name === "edge") {
    return service === "azure-front-door"
      ? regionalUsd(AZURE_UNIT_RATES_USD.frontDoorStandardMonthly, region)
      : 0;
  }
  if (name === "compute") {
    if (service === "app-service") {
      return regionalUsd(
        config.sku === "P0v3"
          ? AZURE_UNIT_RATES_USD.appServiceP0v3Monthly
          : AZURE_UNIT_RATES_USD.appServiceB1Monthly,
        region,
      );
    }
    if (service === "vm-compose") {
      return regionalUsd(AZURE_UNIT_RATES_USD.vmComposeB2atsMonthly, region);
    }
    if (service === "container-apps") {
      const min = typeof config.minReplicas === "number" ? config.minReplicas : 0;
      const base =
        min >= 2
          ? AZURE_UNIT_RATES_USD.containerAppsHaMonthly
          : min === 1
            ? AZURE_UNIT_RATES_USD.containerAppsBalancedMonthly
            : AZURE_UNIT_RATES_USD.containerAppsLeanMonthly;
      return regionalUsd(base, region);
    }
  }
  if (name === "database" && service === "flexible-postgres") {
    const base =
      config.sku === "GP_Standard_D2ds_v5"
        ? AZURE_UNIT_RATES_USD.flexiblePostgresD2dsSingleMonthly
        : config.sku === "B_Standard_B2ms"
          ? AZURE_UNIT_RATES_USD.flexiblePostgresB2msMonthly
          : AZURE_UNIT_RATES_USD.flexiblePostgresB1msMonthly;
    return regionalUsd(base * (config.zoneRedundant === true ? 2 : 1), region);
  }
  return currentUsd;
}

export function applyAzureOverrides(
  target: AzureTarget,
  expressions: readonly string[],
): AzureOverrideResult {
  const before = estimateAzureMonthlyCost(target);
  const draft: AzureTarget = structuredClone(target);
  const changes: string[] = [];

  for (const expr of expressions) {
    const entry = parseAzureSetFlag(expr);
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
        throw new AzureProviderError(
          "INVALID_INPUT",
          `Unknown Azure component "${head}" in --set ${expr}. Available components: ${known}.`,
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

    throw new AzureProviderError("INVALID_INPUT", `Unsupported --set override "${expr}".`);
  }

  const parsed = AzureTargetSchema.safeParse(draft);
  if (!parsed.success) {
    const first = parsed.error.issues[0];
    const where = first?.path.join(".") ?? "target";
    throw new AzureProviderError(
      "INVALID_INPUT",
      `Override rejected at ${where}: ${first?.message ?? "invalid Azure target"}.`,
    );
  }

  const after = estimateAzureMonthlyCost(parsed.data);
  return {
    target: parsed.data,
    beforeMonthlyUsd: before.totalMonthlyUsd,
    afterMonthlyUsd: after.totalMonthlyUsd,
    deltaMonthlyUsd: roundUsd(after.totalMonthlyUsd - before.totalMonthlyUsd),
    changes,
    warnings: after.warnings,
  };
}
