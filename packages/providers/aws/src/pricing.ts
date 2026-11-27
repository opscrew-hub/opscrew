/**
 * Dated AWS baseline pricing catalog (`us-east-1`, On-Demand Linux, 730 h/mo; checked 2026-11-26 in
 * `specs/034-aws/research.md`) and itemized monthly cost estimator.
 */
import type { ManagedCloudCostLine, ManagedCloudRegion } from "@opscrew/contracts";
import type { AwsTarget, Region } from "@opscrew/plan-schema";

/** Date the static baseline prices were verified against official AWS pricing pages. */
export const AWS_PRICES_AS_OF = "2026-11-26" as const;

const DEFAULT_AWS_REGION: ManagedCloudRegion = {
  id: "us-east-1",
  label: "US East (N. Virginia)",
  geography: "us-east",
  priceMultiplier: 1.0,
  supportsLambdaWeb: true,
};

/** AWS commercial regions supported by OpsCrew, with relative pricing multipliers vs `us-east-1`. */
export const AWS_REGIONS: readonly ManagedCloudRegion[] = [
  DEFAULT_AWS_REGION,
  {
    id: "us-west-2",
    label: "US West (Oregon)",
    geography: "us-west",
    priceMultiplier: 1.0,
    supportsLambdaWeb: true,
  },
  {
    id: "eu-central-1",
    label: "Europe (Frankfurt)",
    geography: "eu-central",
    priceMultiplier: 1.12,
    supportsLambdaWeb: true,
  },
  {
    id: "eu-north-1",
    label: "Europe (Stockholm)",
    geography: "eu-north",
    priceMultiplier: 1.04,
    supportsLambdaWeb: false,
  },
  {
    id: "ap-southeast-1",
    label: "Asia Pacific (Singapore)",
    geography: "ap-southeast",
    priceMultiplier: 1.15,
    supportsLambdaWeb: true,
  },
] as const;

/** Default AWS region for each provider-neutral OpsCrew geography. */
export function awsRegionFor(geography: Region): ManagedCloudRegion {
  return AWS_REGIONS.find((r) => r.geography === geography) ?? DEFAULT_AWS_REGION;
}

/** Looks up an AWS region by code (e.g., `eu-central-1`), falling back to `1.05` multiplier if custom. */
export function awsRegionMultiplier(region: string): number {
  return AWS_REGIONS.find((r) => r.id === region)?.priceMultiplier ?? 1.05;
}

/** Reference monthly USD rates (`us-east-1`, 730 h/mo, verified 2026-11-26). */
export const AWS_UNIT_RATES_USD = {
  /** Public IPv4 address ($0.005/hr, global). */
  publicIpv4Monthly: 3.65,
  /** NAT Gateway base ($0.045/hr) + 1 EIP ($3.65/mo), per AZ. */
  natGatewayPerAzMonthly: 36.5,
  /** Application Load Balancer base ($0.0225/hr) + ~1 LCU floor. */
  albBaseMonthly: 18.0,
  /** Lightsail Containers Nano ($7) / Micro ($10) / Small ($25). */
  lightsailNanoMonthly: 7.0,
  lightsailMicroMonthly: 10.0,
  lightsailSmallMonthly: 25.0,
  /** EC2 t4g.micro ($6.13) + 20 GB gp3 ($1.60) + 1 IPv4 ($3.65). */
  ec2MicroComposeMonthly: 11.4,
  ec2SmallComposeMonthly: 18.0,
  /** ECS Fargate 0.25 vCPU / 0.5 GB Arm/Graviton (~$7.20) or 0.5 vCPU / 1 GB (~$14.40). */
  fargateQuarterMonthly: 7.5,
  fargateHalfMonthly: 14.5,
  fargateOneMonthly: 29.0,
  /** Lambda Web Functions low/spiky baseline (free-tier / minimal warm memory). */
  lambdaWebBaselineMonthly: 2.0,
  /** RDS db.t4g.micro Single-AZ ($11.68 + $2.30 gp3 20 GB). */
  rdsMicroSingleAzMonthly: 14.0,
  rdsSmallSingleAzMonthly: 28.0,
  /** Aurora Serverless v2 0 ACU auto-pause (storage floor ~$2) vs 0.5 ACU continuous (~$44). */
  auroraServerlessPauseMonthly: 2.0,
  auroraServerlessHalfAcuMonthly: 44.0,
  /** ElastiCache Valkey cache.t4g.micro ($9.34) vs Serverless Valkey floor ($6.13). */
  valkeyNodeMicroMonthly: 9.34,
  valkeyServerlessFloorMonthly: 6.13,
  /** Secrets Manager single bundled JSON secret ($0.40/mo) vs SSM Parameter Store Standard ($0). */
  secretsManagerSingleMonthly: 0.4,
  ssmStandardMonthly: 0,
  /** Route 53 hosted zone ($0.50/mo); Cloudflare DNS stays $0 on AWS. */
  route53ZoneMonthly: 0.5,
  /** CloudWatch Logs within 5 GB free tier ($0) vs paid ingestion estimate; Managed Grafana editor ($9/user/mo). */
  cloudWatchBasicMonthly: 0,
  containerInsightsMonthly: 5.0,
  managedGrafanaMonthly: 9.0,
  openSearchServerlessMinMonthly: 175.0,
} as const;

/** Rounds USD amounts cleanly to 2 decimal places. */
export function roundUsd(amount: number): number {
  return Math.round(amount * 100) / 100;
}

/** Scales a `us-east-1` baseline USD price to `region` (keeping global fixed fees unchanged when flagged). */
export function regionalUsd(usEast1Usd: number, region: string, globalFixed = false): number {
  if (usEast1Usd === 0) return 0;
  return roundUsd(globalFixed ? usEast1Usd : usEast1Usd * awsRegionMultiplier(region));
}

/** Itemizes monthly USD costs across all components and observability choices of an `AwsTarget`. */
export function estimateAwsMonthlyCost(target: AwsTarget): {
  readonly lines: readonly ManagedCloudCostLine[];
  readonly totalMonthlyUsd: number;
  readonly warnings: readonly string[];
} {
  const lines: ManagedCloudCostLine[] = [];
  const warnings: string[] = [];

  for (const [key, comp] of Object.entries(target.components)) {
    lines.push({
      component: key,
      label: `${key} (${comp.service})`,
      monthlyUsd: roundUsd(comp.monthlyCostUsd),
      notes: comp.why,
    });
    if (key === "network" && comp.config.natGateway === true) {
      warnings.push(
        `NAT Gateway is enabled (~$${roundUsd(comp.monthlyCostUsd)}/mo + $0.045/GB processed). Set \`pins.noNat: true\` or switch to the \`lean\` preset to avoid NAT charges.`,
      );
    }
    if (key === "database" && /documentdb/i.test(comp.service)) {
      warnings.push(
        "Amazon DocumentDB is wire-protocol-compatible with a subset of MongoDB APIs; verify your app's aggregation/index features or use MongoDB Atlas on AWS.",
      );
    }
  }

  if (target.observability.containerInsights) {
    lines.push({
      component: "observability-ci",
      label: "CloudWatch Container Insights",
      monthlyUsd: regionalUsd(AWS_UNIT_RATES_USD.containerInsightsMonthly, target.region),
    });
  }
  if (target.observability.managedGrafana) {
    lines.push({
      component: "observability-grafana",
      label: "Amazon Managed Grafana (1 editor)",
      monthlyUsd: AWS_UNIT_RATES_USD.managedGrafanaMonthly,
    });
  }
  if (target.observability.openSearch) {
    lines.push({
      component: "observability-opensearch",
      label: "Amazon OpenSearch Service (minimum capacity)",
      monthlyUsd: regionalUsd(AWS_UNIT_RATES_USD.openSearchServerlessMinMonthly, target.region),
    });
    warnings.push(
      "Amazon OpenSearch Service carries a high minimum monthly capacity charge (~$175+/mo). CloudWatch Logs (5 GB/mo free) is far cheaper for small and medium apps.",
    );
  }

  const totalMonthlyUsd = roundUsd(lines.reduce((sum, line) => sum + line.monthlyUsd, 0));
  if (target.pins.budgetCapUsd !== undefined && totalMonthlyUsd > target.pins.budgetCapUsd) {
    warnings.push(
      `Estimated monthly cost ($${totalMonthlyUsd}/mo) exceeds your pinned budget cap ($${target.pins.budgetCapUsd}/mo). Consider \`--set preset=lean\` or \`--set network.natGateway=false\`.`,
    );
  }

  return { lines, totalMonthlyUsd, warnings };
}
