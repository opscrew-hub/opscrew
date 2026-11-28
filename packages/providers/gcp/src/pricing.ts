/**
 * Google Cloud (GCP) region catalog and static monthly pricing estimator (Feature 039, T3902).
 *
 * Baselines reflect `us-central1` estimates from `specs/039-google-cloud/research.md` adjusted by
 * region multiplier, explicitly surfacing GCP cost traps (Global External ALB ~$18/mo, Cloud NAT,
 * legacy Serverless VPC Access Connectors, and Cloud SQL dedicated-core jump).
 */
import type { ManagedCloudCostLine, ManagedCloudRegion } from "@opscrew/contracts";
import type { GcpTarget } from "@opscrew/plan-schema";

export const GCP_PRICES_AS_OF = "2026-11-27";

export const GCP_REGIONS: readonly ManagedCloudRegion[] = [
  { id: "us-central1", label: "Iowa (us-central1)", geography: "us-east", priceMultiplier: 1.0 },
  { id: "us-west1", label: "Oregon (us-west1)", geography: "us-west", priceMultiplier: 1.0 },
  {
    id: "europe-west1",
    label: "Belgium (europe-west1)",
    geography: "eu-central",
    priceMultiplier: 1.08,
  },
  {
    id: "europe-north1",
    label: "Finland (europe-north1)",
    geography: "eu-north",
    priceMultiplier: 1.06,
  },
  {
    id: "asia-southeast1",
    label: "Singapore (asia-southeast1)",
    geography: "ap-southeast",
    priceMultiplier: 1.1,
  },
];

export const GCP_UNIT_RATES_USD = {
  cloudRunLeanMonthly: 5,
  cloudRunBalancedMonthly: 22,
  cloudRunHaMonthly: 46,
  computeEngineSmallMonthly: 16,
  cloudSqlMicroMonthly: 11,
  cloudSqlDedicatedSingleMonthly: 52,
  cloudSqlDedicatedHaMonthly: 104,
  memorystoreValkeyNanoMonthly: 18,
  memorystoreValkeyHaMonthly: 48,
  gcsStandardMonthly: 1,
  secretManagerMonthly: 0.5,
  cloudLoggingMonthly: 1,
  pubSubMonthly: 4,
  globalAlbMonthly: 18,
  cloudNatMonthly: 32,
} as const;

export function roundUsd(amount: number): number {
  return Math.round(amount * 100) / 100;
}

export function gcpRegionFor(
  geography: "eu-central" | "eu-north" | "us-east" | "us-west" | "ap-southeast",
): ManagedCloudRegion {
  return (
    GCP_REGIONS.find((r) => r.geography === geography) ??
    GCP_REGIONS[0] ?? {
      id: "us-central1",
      label: "Iowa (us-central1)",
      geography: "us-east",
      priceMultiplier: 1.0,
    }
  );
}

export function gcpRegionMultiplier(regionId: string): number {
  return GCP_REGIONS.find((r) => r.id === regionId)?.priceMultiplier ?? 1.08;
}

export function regionalUsd(usCentral1Usd: number, regionId: string): number {
  return roundUsd(usCentral1Usd * gcpRegionMultiplier(regionId));
}

export function estimateGcpMonthlyCost(target: GcpTarget): {
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

  if (target.components.network?.config.cloudNat === true) {
    warnings.push(
      `Cloud NAT adds gateway + $0.045/GiB egress fees; use Direct VPC Egress (PRIVATE_RANGES_ONLY) with \`--set pins.noNat=true --set network.cloudNat=false\` unless a static outbound IP is mandatory.`,
    );
  }
  if (target.components.edge?.service === "global-alb-cloud-cdn") {
    warnings.push(
      `Global External Application Load Balancer adds ~$${regionalUsd(GCP_UNIT_RATES_USD.globalAlbMonthly, target.region).toFixed(2)}/mo base fee; required for production custom domains or Cloud CDN/Cloud Armor on Cloud Run (direct Cloud Run domain mapping is preview-only).`,
    );
  }
  if (target.components.database?.config.tier === "db-f1-micro") {
    warnings.push(
      "Cloud SQL db-f1-micro is a shared-core tier with no uptime SLA (great for lean/dev); upgrade to db-custom-1-3840 (~$52/mo) for production SLA.",
    );
  }
  if (target.pins.budgetCapUsd !== undefined && totalMonthlyUsd > target.pins.budgetCapUsd) {
    warnings.push(
      `Estimated $${totalMonthlyUsd.toFixed(2)}/mo exceeds pinned budget cap of $${target.pins.budgetCapUsd.toFixed(2)}/mo.`,
    );
  }

  return { totalMonthlyUsd, lines, warnings };
}
