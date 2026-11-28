/**
 * Deterministic Google Cloud (GCP) managed-services architecture designer (Feature 039, T3902).
 *
 * Maps `ProjectFacts` + `Requirements` onto `lean`, `balanced`, or `production-ha` presets:
 * - Cloud Run v2 default (Direct VPC Egress `PRIVATE_RANGES_ONLY`, zero legacy VPC connector VMs)
 * - Private Cloud SQL (`ipv4_enabled = false`, zero public IPv4 fee)
 * - Memorystore for Valkey (`google_memorystore_instance`, NEVER legacy `google_redis_instance`)
 * - Single-region uniform private GCS bucket co-located with Cloud Run
 * - Secret Manager shells ONLY (populated out-of-band)
 */
import type {
  GcpComponentDecision,
  GcpComputeKind,
  GcpPins,
  GcpPreset,
  GcpTarget,
  ProjectFacts,
  Requirements,
} from "@opscrew/plan-schema";
import { estimateGcpMonthlyCost, GCP_UNIT_RATES_USD, gcpRegionFor, regionalUsd } from "./pricing";
import { StandaloneGcpTargetSchema } from "./schema";

export interface DesignGcpInput {
  readonly facts: ProjectFacts;
  readonly requirements: Requirements;
  readonly preset?: GcpPreset;
  readonly pins?: Partial<GcpPins>;
}

export interface DesignGcpResult {
  readonly target: GcpTarget;
  readonly totalMonthlyUsd: number;
  readonly warnings: readonly string[];
}

export function defaultGcpPreset(requirements: Requirements): GcpPreset {
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

function hasService(facts: ProjectFacts, ...kinds: readonly string[]): boolean {
  const detected = facts.services ?? [];
  return detected.some((s) => kinds.includes(s.kind));
}

function selectCompute(
  preset: GcpPreset,
  region: string,
): {
  kind: GcpComputeKind;
  decision: GcpComponentDecision;
} {
  if (preset === "lean") {
    return {
      kind: "cloud-run",
      decision: {
        service: "cloud-run",
        why: "Cloud Run v2 scales to zero with a free monthly allowance (180k vCPU-s, 360k GiB-s, 2M req) and built-in *.run.app HTTPS.",
        alternatives: [
          {
            service: "compute-engine",
            monthlyCostUsd: regionalUsd(GCP_UNIT_RATES_USD.computeEngineSmallMonthly, region),
            whyNot: "Fixed VM + external IPv4 billing and manual OS/Docker patching.",
          },
        ],
        monthlyCostUsd: regionalUsd(GCP_UNIT_RATES_USD.cloudRunLeanMonthly, region),
        config: { minInstances: 0, maxInstances: 4, cpu: 1, memoryMb: 512 },
      },
    };
  }
  if (preset === "balanced") {
    return {
      kind: "cloud-run",
      decision: {
        service: "cloud-run",
        why: "Cloud Run v2 with 1 always-warm instance eliminates cold starts while auto-scaling seamlessly.",
        alternatives: [
          {
            service: "compute-engine",
            monthlyCostUsd: regionalUsd(GCP_UNIT_RATES_USD.computeEngineSmallMonthly, region),
            whyNot: "Requires manual zero-downtime rollout and OS maintenance.",
          },
        ],
        monthlyCostUsd: regionalUsd(GCP_UNIT_RATES_USD.cloudRunBalancedMonthly, region),
        config: { minInstances: 1, maxInstances: 8, cpu: 1, memoryMb: 512 },
      },
    };
  }
  return {
    kind: "cloud-run",
    decision: {
      service: "cloud-run",
      why: "Cloud Run v2 with 2+ warm instances behind Global External ALB + Cloud CDN for high availability.",
      alternatives: [],
      monthlyCostUsd: regionalUsd(GCP_UNIT_RATES_USD.cloudRunHaMonthly, region),
      config: { minInstances: 2, maxInstances: 16, cpu: 1, memoryMb: 1024 },
    },
  };
}

export function designGcpTarget(input: DesignGcpInput): DesignGcpResult {
  const preset = input.preset ?? defaultGcpPreset(input.requirements);
  const pins: GcpPins = { ...(input.pins ?? {}) };
  const region = pins.region ?? gcpRegionFor(input.requirements.region ?? "us-east").id;
  const compute = selectCompute(preset, region);

  const components: Record<string, GcpComponentDecision> = {
    compute: compute.decision,
    network: {
      service: "direct-vpc-egress",
      why: "Cloud Run Direct VPC Egress (PRIVATE_RANGES_ONLY) avoids legacy Serverless VPC Access Connector VMs (~$14-18/mo) and Cloud NAT fees.",
      alternatives: [
        {
          service: "serverless-vpc-connector",
          monthlyCostUsd: regionalUsd(16, region),
          whyNot:
            "Legacy 2x e2-micro always-on VMs; blocked by OpsCrew's noLegacyVpcConnector guardrail.",
        },
      ],
      monthlyCostUsd: 0,
      config: { cloudNat: false, directVpcEgress: true },
    },
    secrets: {
      service: "secret-manager",
      why: "Google Secret Manager (6 free active secret versions/mo); secret values populated out-of-band (never in .tfstate).",
      alternatives: [],
      monthlyCostUsd: regionalUsd(GCP_UNIT_RATES_USD.secretManagerMonthly, region),
      config: { outOfBandValues: true },
    },
    observability: {
      service: "cloud-logging",
      why: "Cloud Logging default bucket with explicit retention cap and Cloud Monitoring alert policies.",
      alternatives: [],
      monthlyCostUsd: regionalUsd(GCP_UNIT_RATES_USD.cloudLoggingMonthly, region),
      config: { retentionDays: preset === "production-ha" ? 90 : 30 },
    },
  };

  const wantsPostgres = hasService(input.facts, "postgres", "supabase");
  const wantsMysql = !wantsPostgres && hasService(input.facts, "mysql", "mariadb");
  if ((wantsPostgres || wantsMysql) && pins.existingDb === undefined) {
    const tier = preset === "lean" ? "db-f1-micro" : "db-custom-1-3840";
    const ha = preset === "production-ha";
    const baseUsd =
      preset === "lean"
        ? GCP_UNIT_RATES_USD.cloudSqlMicroMonthly
        : ha
          ? GCP_UNIT_RATES_USD.cloudSqlDedicatedHaMonthly
          : GCP_UNIT_RATES_USD.cloudSqlDedicatedSingleMonthly;
    components.database = {
      service: wantsPostgres ? "cloud-sql-postgres" : "cloud-sql-mysql",
      why:
        preset === "lean"
          ? "Private Cloud SQL (ipv4_enabled=false, built-in Cloud SQL Auth Proxy socket) with daily automated backups."
          : ha
            ? "Regional HA Cloud SQL dedicated-core instance with private VPC IP, PITR, and automated backups."
            : "Dedicated-core private Cloud SQL instance (ipv4_enabled=false) with SLA and automated daily backups.",
      alternatives: [],
      monthlyCostUsd: regionalUsd(baseUsd, region),
      config: {
        tier,
        regionalHa: ha,
        backupRetentionDays: ha ? 30 : 7,
        diskGb: 10,
      },
    };
  }

  if (hasService(input.facts, "redis")) {
    const ha = preset === "production-ha";
    components.cache = {
      service: "memorystore-valkey",
      why: "Memorystore for Valkey (google_memorystore_instance) over private VPC with IAM auth.",
      alternatives: [
        {
          service: "memorystore-redis",
          monthlyCostUsd: regionalUsd(20, region),
          whyNot: "Legacy Redis SKU; blocked by OpsCrew's noLegacyRedis guardrail.",
        },
      ],
      monthlyCostUsd: regionalUsd(
        ha
          ? GCP_UNIT_RATES_USD.memorystoreValkeyHaMonthly
          : GCP_UNIT_RATES_USD.memorystoreValkeyNanoMonthly,
        region,
      ),
      config: { nodeType: ha ? "STANDARD_SMALL" : "SHARED_CORE_NANO", replicaCount: ha ? 1 : 0 },
    };
  }

  if (hasService(input.facts, "s3")) {
    components.storage = {
      service: "gcs",
      why: "Single-region Google Cloud Storage bucket co-located with Cloud Run (uniform bucket-level access + enforced public access prevention).",
      alternatives: [],
      monthlyCostUsd: regionalUsd(GCP_UNIT_RATES_USD.gcsStandardMonthly, region),
      config: { uniformBucketLevelAccess: true, publicAccessPrevention: "enforced" },
    };
  }

  if (hasService(input.facts, "queue", "amqp")) {
    components.queues = {
      service: "pub-sub",
      why: "Google Cloud Pub/Sub provides durable serverless messaging with dead-letter topics and zero idle cost.",
      alternatives: [],
      monthlyCostUsd: regionalUsd(GCP_UNIT_RATES_USD.pubSubMonthly, region),
      config: { deadLettering: true },
    };
  }

  const hasCustomDomain = Boolean(input.requirements.domain?.trim());
  const wantsAlb =
    compute.kind === "cloud-run" &&
    pins.noGlobalAlb !== true &&
    (preset === "production-ha" || (preset === "balanced" && hasCustomDomain));
  if (wantsAlb) {
    components.edge = {
      service: "global-alb-cloud-cdn",
      why: "Global External Application Load Balancer + Certificate Manager DNS-01 TLS + Cloud CDN (production custom-domain pattern for Cloud Run).",
      alternatives: [
        {
          service: "cloud-run-default-tls",
          monthlyCostUsd: 0,
          whyNot: "Uses *.run.app only (direct Cloud Run domain mapping is preview-only).",
        },
      ],
      monthlyCostUsd: regionalUsd(GCP_UNIT_RATES_USD.globalAlbMonthly, region),
      config: { globalAlb: true, cloudCdn: true },
    };
  } else {
    components.edge = {
      service: "cloud-run-default-tls",
      why: "Free built-in *.run.app HTTPS avoids the ~$18/mo Global External ALB base fee on lean setups.",
      alternatives: [
        {
          service: "global-alb-cloud-cdn",
          monthlyCostUsd: regionalUsd(GCP_UNIT_RATES_USD.globalAlbMonthly, region),
          whyNot:
            "Adds ~$18/mo fixed base fee; enable on balanced/production-ha for production custom domains.",
        },
      ],
      monthlyCostUsd: 0,
      config: { globalAlb: false, cloudCdn: false },
    };
  }

  const target: GcpTarget = StandaloneGcpTargetSchema.parse({
    provider: "gcp",
    mode: "gcp-managed",
    region,
    preset,
    compute: compute.kind,
    components,
    pins,
    observability: {
      logsRetentionDays: preset === "production-ha" ? 90 : 30,
      cloudTrace: preset === "production-ha",
      alerts: true,
    },
  });

  const estimate = estimateGcpMonthlyCost(target);
  return {
    target,
    totalMonthlyUsd: estimate.totalMonthlyUsd,
    warnings: estimate.warnings,
  };
}
