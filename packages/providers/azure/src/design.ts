/**
 * Deterministic Azure managed-services architecture designer (Feature 038, T3802).
 *
 * Maps `ProjectFacts` + `Requirements` onto `lean`, `balanced`, or `production-ha` presets,
 * honoring user pins (`region`, `budgetCapUsd`, `noNat`, `noFrontDoor`, `existingVnetId`,
 * `existingDb`, `keepCloudflareDns`) and always using Azure Managed Redis (never retiring
 * `azurerm_redis_cache`).
 */
import {
  type AzureComponentDecision,
  type AzureComputeKind,
  type AzurePins,
  type AzurePreset,
  type AzureTarget,
  AzureTargetSchema,
  type ProjectFacts,
  type Requirements,
} from "@opscrew/plan-schema";
import {
  AZURE_UNIT_RATES_USD,
  azureRegionFor,
  estimateAzureMonthlyCost,
  regionalUsd,
} from "./pricing";

export interface DesignAzureInput {
  readonly facts: ProjectFacts;
  readonly requirements: Requirements;
  readonly preset?: AzurePreset;
  readonly pins?: Partial<AzurePins>;
}

export interface DesignAzureResult {
  readonly target: AzureTarget;
  readonly totalMonthlyUsd: number;
  readonly warnings: readonly string[];
}

export function defaultAzurePreset(requirements: Requirements): AzurePreset {
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
  preset: AzurePreset,
  region: string,
): {
  kind: AzureComputeKind;
  decision: AzureComponentDecision;
} {
  if (preset === "lean") {
    return {
      kind: "container-apps",
      decision: {
        service: "container-apps",
        why: "Azure Container Apps Consumption includes 180k vCPU-s free/mo, scale-to-zero, and built-in managed HTTPS ingress.",
        alternatives: [
          {
            service: "app-service",
            monthlyCostUsd: regionalUsd(AZURE_UNIT_RATES_USD.appServiceB1Monthly, region),
            whyNot: "Fixed B1 VM billing even during idle periods.",
          },
          {
            service: "vm-compose",
            monthlyCostUsd: regionalUsd(AZURE_UNIT_RATES_USD.vmComposeB2atsMonthly, region),
            whyNot: "Requires OS patching and manual container runtime upkeep.",
          },
        ],
        monthlyCostUsd: regionalUsd(AZURE_UNIT_RATES_USD.containerAppsLeanMonthly, region),
        config: { minReplicas: 0, maxReplicas: 3, cpu: 0.5, memoryGb: 1 },
      },
    };
  }
  if (preset === "balanced") {
    return {
      kind: "container-apps",
      decision: {
        service: "container-apps",
        why: "Azure Container Apps Consumption with 1 warm replica avoids cold starts while scaling automatically.",
        alternatives: [
          {
            service: "app-service",
            monthlyCostUsd: regionalUsd(AZURE_UNIT_RATES_USD.appServiceP0v3Monthly, region),
            whyNot: "Higher fixed cost for P0v3 tier with VNet integration.",
          },
        ],
        monthlyCostUsd: regionalUsd(AZURE_UNIT_RATES_USD.containerAppsBalancedMonthly, region),
        config: { minReplicas: 1, maxReplicas: 6, cpu: 0.5, memoryGb: 1 },
      },
    };
  }
  return {
    kind: "container-apps",
    decision: {
      service: "container-apps",
      why: "Zone-redundant Azure Container Apps with 2+ warm replicas for zero-downtime rolling revisions.",
      alternatives: [
        {
          service: "app-service",
          monthlyCostUsd: regionalUsd(AZURE_UNIT_RATES_USD.appServiceP0v3Monthly * 2, region),
          whyNot: "Requires 2x P0v3 instances for HA with slower container scale-out.",
        },
      ],
      monthlyCostUsd: regionalUsd(AZURE_UNIT_RATES_USD.containerAppsHaMonthly, region),
      config: { minReplicas: 2, maxReplicas: 10, cpu: 1, memoryGb: 2, zoneRedundant: true },
    },
  };
}

export function designAzureTarget(input: DesignAzureInput): DesignAzureResult {
  const preset = input.preset ?? defaultAzurePreset(input.requirements);
  const pins: AzurePins = {
    ...(input.pins ?? {}),
  };
  const region = pins.region ?? azureRegionFor(input.requirements.region ?? "us-east").id;
  const compute = selectCompute(preset, region);

  const components: Record<string, AzureComponentDecision> = {
    compute: compute.decision,
    network: {
      service: "vnet-private-delegation",
      why: "Private VNet with delegated DB subnet and zero NAT Gateway fixed cost (~$37/mo saved).",
      alternatives: [
        {
          service: "vnet-nat-gateway",
          monthlyCostUsd: regionalUsd(AZURE_UNIT_RATES_USD.natGatewayMonthly, region),
          whyNot: "Adds ~$37/mo fixed charge; only needed when static outbound IP is mandatory.",
        },
      ],
      monthlyCostUsd: 0,
      config: { natGateway: false, privateDnsZone: true },
    },
    secrets: {
      service: "key-vault",
      why: "Azure Key Vault Standard ($0/mo base) with RBAC and purge protection; values populated out-of-band (never in .tfstate).",
      alternatives: [],
      monthlyCostUsd: regionalUsd(AZURE_UNIT_RATES_USD.keyVaultStandardMonthly, region),
      config: { rbacAuthorization: true, purgeProtection: true },
    },
    observability: {
      service: "log-analytics",
      why: "Azure Monitor Log Analytics workspace (5 GB/mo free allowance) with explicit retention cap.",
      alternatives: [],
      monthlyCostUsd: regionalUsd(AZURE_UNIT_RATES_USD.logAnalyticsMonthly, region),
      config: { retentionDays: preset === "production-ha" ? 90 : 30 },
    },
  };

  // Database
  const wantsPostgres = hasService(input.facts, "postgres", "supabase");
  const wantsMysql = !wantsPostgres && hasService(input.facts, "mysql", "mariadb");
  if ((wantsPostgres || wantsMysql) && pins.existingDb === undefined) {
    if (wantsPostgres) {
      const sku =
        preset === "lean"
          ? "B_Standard_B1ms"
          : preset === "balanced"
            ? "B_Standard_B2ms"
            : "GP_Standard_D2ds_v5";
      const baseUsd =
        preset === "lean"
          ? AZURE_UNIT_RATES_USD.flexiblePostgresB1msMonthly
          : preset === "balanced"
            ? AZURE_UNIT_RATES_USD.flexiblePostgresB2msMonthly
            : AZURE_UNIT_RATES_USD.flexiblePostgresD2dsHaMonthly;
      components.database = {
        service: "flexible-postgres",
        why:
          preset === "production-ha"
            ? "Azure Database for PostgreSQL Flexible Server with zone-redundant HA, private VNet delegation, and geo-redundant backups."
            : "Azure Database for PostgreSQL Flexible Server in a private delegated VNet subnet with automated backups.",
        alternatives: [],
        monthlyCostUsd: regionalUsd(baseUsd, region),
        config: {
          sku,
          zoneRedundant: preset === "production-ha",
          backupRetentionDays: preset === "production-ha" ? 35 : 7,
          storageGb: 32,
        },
      };
    } else {
      const sku = preset === "lean" ? "B_Standard_B1ms" : "GP_Standard_D2ds_v5";
      const baseUsd =
        preset === "lean"
          ? AZURE_UNIT_RATES_USD.flexibleMysqlB1msMonthly
          : AZURE_UNIT_RATES_USD.flexibleMysqlD2dsSingleMonthly;
      components.database = {
        service: "flexible-mysql",
        why: "Azure Database for MySQL Flexible Server in a private delegated VNet subnet with automated backups.",
        alternatives: [],
        monthlyCostUsd: regionalUsd(baseUsd, region),
        config: {
          sku,
          zoneRedundant: preset === "production-ha",
          backupRetentionDays: preset === "production-ha" ? 35 : 7,
          storageGb: 32,
        },
      };
    }
  }

  // Cache — ALWAYS Azure Managed Redis (`azurerm_managed_redis`), NEVER retiring `azurerm_redis_cache`
  if (hasService(input.facts, "redis")) {
    const ha = preset === "production-ha";
    components.cache = {
      service: "managed-redis",
      why: "Azure Managed Redis (azurerm_managed_redis) replaces retiring Azure Cache for Redis with private VNet access.",
      alternatives: [
        {
          service: "azure-cache-for-redis",
          monthlyCostUsd: regionalUsd(16, region),
          whyNot:
            "Retiring SKU (azurerm_redis_cache); blocked by OpsCrew's noRetiringRedis guardrail.",
        },
      ],
      monthlyCostUsd: regionalUsd(
        ha
          ? AZURE_UNIT_RATES_USD.managedRedisB1HaMonthly
          : AZURE_UNIT_RATES_USD.managedRedisB0Monthly,
        region,
      ),
      config: { sku: ha ? "Balanced_B1" : "Balanced_B0", highAvailability: ha },
    };
  }

  // Object storage
  if (hasService(input.facts, "s3")) {
    const grs = preset === "production-ha";
    components.storage = {
      service: "blob-storage",
      why: "Azure Storage Account (private Blob container, TLS 1.2+, shared keys disabled, managed-identity RBAC).",
      alternatives: [],
      monthlyCostUsd: regionalUsd(
        grs
          ? AZURE_UNIT_RATES_USD.blobStorageGrsMonthly
          : AZURE_UNIT_RATES_USD.blobStorageLrsMonthly,
        region,
      ),
      config: { replication: grs ? "GRS" : "LRS", publicAccess: false },
    };
  }

  // Queues
  if (hasService(input.facts, "queue", "amqp")) {
    components.queues = {
      service: "service-bus",
      why: "Azure Service Bus Standard provides durable AMQP queues with dead-lettering and managed-identity auth.",
      alternatives: [],
      monthlyCostUsd: regionalUsd(AZURE_UNIT_RATES_USD.serviceBusStandardMonthly, region),
      config: { sku: "Standard" },
    };
  }

  // Edge / CDN — avoid $35/mo Front Door on lean/balanced or when Cloudflare DNS is kept
  const keepCloudflare =
    pins.keepCloudflareDns === true || input.requirements.dnsProvider === "cloudflare";
  if (preset === "production-ha" && pins.noFrontDoor !== true && !keepCloudflare) {
    components.edge = {
      service: "azure-front-door",
      why: "Azure Front Door Standard provides global Anycast HTTPS, WAF, and origin shielding for HA workloads.",
      alternatives: [
        {
          service: "cloudflare-edge",
          monthlyCostUsd: 0,
          whyNot:
            "Available at $0/mo if DNS stays on Cloudflare (`--set pins.keepCloudflareDns=true`).",
        },
      ],
      monthlyCostUsd: regionalUsd(AZURE_UNIT_RATES_USD.frontDoorStandardMonthly, region),
      config: { sku: "Standard_AzureFrontDoor" },
    };
  } else {
    components.edge = {
      service: keepCloudflare ? "cloudflare-edge" : "container-apps-tls",
      why: keepCloudflare
        ? "Keeps Cloudflare DNS + proxy at $0/mo (with `asuid` custom-domain TXT record DNS-only) and avoids $35/mo Front Door."
        : "Uses built-in managed HTTPS TLS on Container Apps at $0/mo and avoids $35/mo Azure Front Door base cost.",
      alternatives: [
        {
          service: "azure-front-door",
          monthlyCostUsd: regionalUsd(AZURE_UNIT_RATES_USD.frontDoorStandardMonthly, region),
          whyNot: "Adds $35/mo base fee; unnecessary when built-in TLS or Cloudflare is active.",
        },
      ],
      monthlyCostUsd: 0,
      config: { frontDoor: false },
    };
  }

  const target = AzureTargetSchema.parse({
    provider: "azure",
    mode: "azure-managed",
    region,
    preset,
    compute: compute.kind,
    components,
    pins,
    observability: {
      logsRetentionDays: preset === "production-ha" ? 90 : 30,
      applicationInsights: preset === "production-ha",
      alerts: true,
      managedGrafana: false,
    },
  });

  const estimate = estimateAzureMonthlyCost(target);
  return {
    target,
    totalMonthlyUsd: estimate.totalMonthlyUsd,
    warnings: estimate.warnings,
  };
}
