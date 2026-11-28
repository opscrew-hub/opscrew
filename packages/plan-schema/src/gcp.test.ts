import { describe, expect, it } from "vitest";
import { DeployProviderSchema, isManagedCloudProvider } from "./enums";
import { GcpTargetSchema } from "./gcp";
import { isGcpTarget, isManagedCloudTarget } from "./plan";

function baseGcpTarget(overrides: Record<string, unknown> = {}) {
  return {
    provider: "gcp" as const,
    mode: "gcp-managed" as const,
    region: "us-central1",
    preset: "lean" as const,
    compute: "cloud-run" as const,
    components: {
      compute: {
        service: "cloud-run",
        why: "Scale-to-zero Cloud Run v2 with free monthly allowance and built-in *.run.app HTTPS.",
        alternatives: [],
        monthlyCostUsd: 5,
        config: { minInstances: 0, maxInstances: 4 },
      },
      database: {
        service: "cloud-sql-postgres",
        why: "Private Cloud SQL PostgreSQL with automated backups and built-in Cloud SQL connector.",
        alternatives: [],
        monthlyCostUsd: 11,
        config: { tier: "db-f1-micro", regionalHa: false },
      },
      network: {
        service: "direct-vpc-egress",
        why: "Cloud Run Direct VPC Egress (PRIVATE_RANGES_ONLY) with zero connector VMs and zero Cloud NAT.",
        alternatives: [],
        monthlyCostUsd: 0,
        config: { cloudNat: false },
      },
    },
    ...overrides,
  };
}

describe("039 GCP target schema (T3901)", () => {
  it("accepts a valid GCP managed target with default-on guardrails and observability", () => {
    const parsed = GcpTargetSchema.parse(baseGcpTarget());
    expect(parsed.provider).toBe("gcp");
    expect(parsed.guardrails).toEqual({
      privateDatabase: true,
      encryptionAtRest: true,
      automatedBackups: true,
      privateStorage: true,
      leastPrivilegeIam: true,
      noStaticSaKeys: true,
      noLegacyVpcConnector: true,
      noLegacyRedis: true,
      noGlobalAlbOnLean: true,
    });
    expect(parsed.observability.logsRetentionDays).toBe(30);
    expect(isGcpTarget(parsed)).toBe(true);
    expect(isManagedCloudTarget(parsed)).toBe(true);
    expect(isManagedCloudProvider("gcp")).toBe(true);
    expect(DeployProviderSchema.options).toContain("gcp");
  });

  it("refuses silent guardrail disabling and accepts explicit recorded exceptions", () => {
    const silent = GcpTargetSchema.safeParse(
      baseGcpTarget({ guardrails: { privateDatabase: false } }),
    );
    expect(silent.success).toBe(false);

    const recorded = GcpTargetSchema.safeParse(
      baseGcpTarget({
        guardrails: { privateDatabase: false },
        exceptions: [
          {
            guardrail: "privateDatabase",
            reason: "Temporary authorized-network import window from office CIDR.",
          },
        ],
      }),
    );
    expect(recorded.success).toBe(true);
  });

  it("refuses legacy Redis, legacy Serverless VPC Connector, Global ALB on lean, and conflicting pins", () => {
    expect(
      GcpTargetSchema.safeParse(
        baseGcpTarget({
          components: {
            cache: { service: "memorystore-redis", why: "legacy", monthlyCostUsd: 16 },
          },
        }),
      ).success,
    ).toBe(false);

    expect(
      GcpTargetSchema.safeParse(
        baseGcpTarget({
          components: {
            network: { service: "serverless-vpc-connector", why: "legacy", monthlyCostUsd: 16 },
          },
        }),
      ).success,
    ).toBe(false);

    expect(
      GcpTargetSchema.safeParse(
        baseGcpTarget({
          preset: "lean",
          components: {
            edge: { service: "global-alb-cloud-cdn", why: "lb", monthlyCostUsd: 18 },
          },
        }),
      ).success,
    ).toBe(false);

    expect(
      GcpTargetSchema.safeParse(
        baseGcpTarget({
          pins: { noNat: true },
          components: {
            network: {
              service: "direct-vpc-egress",
              why: "nat",
              monthlyCostUsd: 32,
              config: { cloudNat: true },
            },
          },
        }),
      ).success,
    ).toBe(false);
  });
});
