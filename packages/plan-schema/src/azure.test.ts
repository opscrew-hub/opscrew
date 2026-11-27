import { describe, expect, it } from "vitest";
import { AzureTargetSchema } from "./azure";
import { DeployProviderSchema, isManagedCloudProvider } from "./enums";
import { isAzureTarget, isManagedCloudTarget } from "./plan";

function baseAzureTarget(overrides: Record<string, unknown> = {}) {
  return {
    provider: "azure" as const,
    mode: "azure-managed" as const,
    region: "westeurope",
    preset: "lean" as const,
    compute: "container-apps" as const,
    components: {
      compute: {
        service: "container-apps",
        why: "Consumption plan includes 180k vCPU-s free/mo and built-in HTTPS ingress.",
        alternatives: [
          {
            service: "app-service",
            monthlyCostUsd: 13,
            whyNot: "Fixed B1 VM cost even when idle.",
          },
        ],
        monthlyCostUsd: 8,
        config: { minReplicas: 0, maxReplicas: 3 },
      },
      database: {
        service: "flexible-postgres",
        why: "PostgreSQL Flexible Server B1ms with automated backups and private VNet delegation.",
        alternatives: [],
        monthlyCostUsd: 15,
        config: { sku: "B_Standard_B1ms", zoneRedundant: false },
      },
      network: {
        service: "vnet-private-delegation",
        why: "Avoids ~$37/mo NAT Gateway while keeping PostgreSQL private inside the VNet.",
        alternatives: [],
        monthlyCostUsd: 0,
        config: { natGateway: false },
      },
    },
    ...overrides,
  };
}

describe("038 Azure target schema (T3801)", () => {
  it("accepts a valid Azure managed target with default-on guardrails and observability", () => {
    const parsed = AzureTargetSchema.parse(baseAzureTarget());
    expect(parsed.provider).toBe("azure");
    expect(parsed.guardrails).toEqual({
      privateDatabase: true,
      encryptionAtRest: true,
      automatedBackups: true,
      privateStorage: true,
      leastPrivilegeRbac: true,
      logRetention: true,
      noFrontDoorOnLean: true,
      noRetiringRedis: true,
    });
    expect(parsed.observability.logsRetentionDays).toBe(30);
    expect(parsed.observability.alerts).toBe(true);
    expect(isAzureTarget(parsed)).toBe(true);
    expect(isManagedCloudTarget(parsed)).toBe(true);
    expect(isManagedCloudProvider("azure")).toBe(true);
    expect(DeployProviderSchema.options).toContain("azure");
  });

  it("refuses disabling any guardrail silently, and accepts it with an explicit recorded exception", () => {
    const silent = AzureTargetSchema.safeParse(
      baseAzureTarget({
        guardrails: { privateDatabase: false },
      }),
    );
    expect(silent.success).toBe(false);
    if (!silent.success) {
      expect(silent.error.issues[0]?.message).toContain("cannot be disabled silently");
    }

    const recorded = AzureTargetSchema.safeParse(
      baseAzureTarget({
        guardrails: { privateDatabase: false },
        exceptions: [
          {
            guardrail: "privateDatabase",
            reason: "Temporary migration access from a fixed office CIDR, closed after import.",
          },
        ],
      }),
    );
    expect(recorded.success).toBe(true);
  });

  it("refuses retiring Azure Cache for Redis, Front Door on lean, invalid retention, and conflicting pins", () => {
    const retiringRedis = AzureTargetSchema.safeParse(
      baseAzureTarget({
        components: {
          cache: {
            service: "azure-cache-for-redis",
            why: "legacy",
            monthlyCostUsd: 16,
          },
        },
      }),
    );
    expect(retiringRedis.success).toBe(false);
    if (!retiringRedis.success) {
      expect(retiringRedis.error.issues[0]?.message).toContain("retiring Azure Cache for Redis");
    }

    const frontDoorOnLean = AzureTargetSchema.safeParse(
      baseAzureTarget({
        preset: "lean",
        components: {
          edge: {
            service: "azure-front-door",
            why: "cdn",
            monthlyCostUsd: 35,
          },
        },
      }),
    );
    expect(frontDoorOnLean.success).toBe(false);
    if (!frontDoorOnLean.success) {
      expect(frontDoorOnLean.error.issues[0]?.message).toContain("Azure Front Door");
    }

    const badRetention = AzureTargetSchema.safeParse(
      baseAzureTarget({
        observability: { logsRetentionDays: 14 },
      }),
    );
    expect(badRetention.success).toBe(false);

    const badNatPin = AzureTargetSchema.safeParse(
      baseAzureTarget({
        pins: { noNat: true },
        components: {
          network: {
            service: "vnet-nat",
            why: "NAT enabled",
            monthlyCostUsd: 37,
            config: { natGateway: true },
          },
        },
      }),
    );
    expect(badNatPin.success).toBe(false);
    if (!badNatPin.success) {
      expect(badNatPin.error.issues[0]?.message).toContain("conflicts with pins.noNat");
    }

    const badRegionPin = AzureTargetSchema.safeParse(
      baseAzureTarget({
        region: "westeurope",
        pins: { region: "eastus2" },
      }),
    );
    expect(badRegionPin.success).toBe(false);
  });
});
