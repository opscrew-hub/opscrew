/**
 * Microsoft Azure region catalog and static monthly pricing estimator (Feature 038, T3802).
 *
 * Baselines reflect published Azure retail prices in `eastus2` adjusted by region multiplier.
 * Explicitly flags Azure cost traps: NAT Gateway (~$37/mo) and Azure Front Door Standard ($35/mo).
 */
import type { ManagedCloudCostLine, ManagedCloudRegion } from "@opscrew/contracts";
import type { AzureTarget } from "@opscrew/plan-schema";

export const AZURE_PRICES_AS_OF = "2026-11-27";

export const AZURE_REGIONS: readonly ManagedCloudRegion[] = [
  { id: "eastus2", label: "East US 2 (Virginia)", geography: "us-east", priceMultiplier: 1.0 },
  { id: "westus2", label: "West US 2 (Washington)", geography: "us-west", priceMultiplier: 1.03 },
  {
    id: "westeurope",
    label: "West Europe (Netherlands)",
    geography: "eu-central",
    priceMultiplier: 1.08,
  },
  { id: "swedencentral", label: "Sweden Central", geography: "eu-north", priceMultiplier: 1.02 },
  {
    id: "northeurope",
    label: "North Europe (Ireland)",
    geography: "eu-north",
    priceMultiplier: 1.05,
  },
  {
    id: "southeastasia",
    label: "Southeast Asia (Singapore)",
    geography: "ap-southeast",
    priceMultiplier: 1.09,
  },
];

export const AZURE_UNIT_RATES_USD = {
  containerAppsLeanMonthly: 8,
  containerAppsBalancedMonthly: 24,
  containerAppsHaMonthly: 48,
  appServiceB1Monthly: 13,
  appServiceP0v3Monthly: 68,
  vmComposeB2atsMonthly: 11,
  flexiblePostgresB1msMonthly: 15,
  flexiblePostgresB2msMonthly: 52,
  flexiblePostgresD2dsSingleMonthly: 125,
  flexiblePostgresD2dsHaMonthly: 250,
  flexibleMysqlB1msMonthly: 14,
  flexibleMysqlD2dsSingleMonthly: 118,
  managedRedisB0Monthly: 12,
  managedRedisB1HaMonthly: 42,
  blobStorageLrsMonthly: 1,
  blobStorageGrsMonthly: 2,
  keyVaultStandardMonthly: 0.5,
  logAnalyticsMonthly: 2,
  serviceBusStandardMonthly: 10,
  natGatewayMonthly: 37,
  frontDoorStandardMonthly: 35,
} as const;

export function roundUsd(amount: number): number {
  return Math.round(amount * 100) / 100;
}

export function azureRegionFor(
  geography: "eu-central" | "eu-north" | "us-east" | "us-west" | "ap-southeast",
): ManagedCloudRegion {
  return (
    AZURE_REGIONS.find((r) => r.geography === geography) ??
    AZURE_REGIONS[0] ?? {
      id: "eastus2",
      label: "East US 2 (Virginia)",
      geography: "us-east",
      priceMultiplier: 1.0,
    }
  );
}

export function azureRegionMultiplier(regionId: string): number {
  return AZURE_REGIONS.find((r) => r.id === regionId)?.priceMultiplier ?? 1.05;
}

export function regionalUsd(eastUs2Usd: number, regionId: string): number {
  return roundUsd(eastUs2Usd * azureRegionMultiplier(regionId));
}

export function estimateAzureMonthlyCost(target: AzureTarget): {
  readonly totalMonthlyUsd: number;
  readonly lines: readonly ManagedCloudCostLine[];
  readonly warnings: readonly string[];
} {
  const lines: ManagedCloudCostLine[] = Object.entries(target.components).map(
    ([component, decision]) => ({
      component,
      label: decision.service,
      monthlyUsd: roundUsd(decision.monthlyCostUsd),
    }),
  );
  const totalMonthlyUsd = roundUsd(lines.reduce((sum, l) => sum + l.monthlyUsd, 0));
  const warnings: string[] = [];

  if (target.components.network?.config.natGateway === true) {
    warnings.push(
      `Azure NAT Gateway adds ~$${regionalUsd(AZURE_UNIT_RATES_USD.natGatewayMonthly, target.region).toFixed(2)}/mo fixed cost; set \`--set pins.noNat=true\` and \`--set network.natGateway=false\` unless fixed outbound IP is required.`,
    );
  }
  if (target.components.edge?.service === "azure-front-door") {
    warnings.push(
      `Azure Front Door Standard adds ~$${regionalUsd(AZURE_UNIT_RATES_USD.frontDoorStandardMonthly, target.region).toFixed(2)}/mo base fee; keep Cloudflare or Container Apps built-in TLS on smaller apps.`,
    );
  }
  if (target.pins.budgetCapUsd !== undefined && totalMonthlyUsd > target.pins.budgetCapUsd) {
    warnings.push(
      `Estimated $${totalMonthlyUsd.toFixed(2)}/mo exceeds pinned budget cap of $${target.pins.budgetCapUsd.toFixed(2)}/mo.`,
    );
  }

  return { totalMonthlyUsd, lines, warnings };
}
