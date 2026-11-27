import { describe, expect, it } from "vitest";
import { AwsTargetSchema } from "./aws";
import { DeployProviderSchema, isManagedCloudProvider } from "./enums";
import { isAwsTarget, isManagedCloudTarget } from "./plan";

function baseAwsTarget(overrides: Record<string, unknown> = {}) {
  return {
    provider: "aws" as const,
    mode: "aws-managed" as const,
    region: "us-east-1",
    preset: "lean" as const,
    compute: "lightsail-containers" as const,
    components: {
      compute: {
        service: "lightsail-containers",
        why: "Flat-rate $7/mo HTTPS container with zero ALB/NAT cost traps.",
        alternatives: [
          {
            service: "ecs-fargate",
            monthlyCostUsd: 30,
            whyNot: "Requires $16.43/mo ALB base fee for a small solo app.",
          },
        ],
        monthlyCostUsd: 7,
        config: { power: "nano", scale: 1 },
      },
      database: {
        service: "rds-postgres",
        why: "Managed PostgreSQL 17 with automated daily backups and zero code changes.",
        alternatives: [],
        monthlyCostUsd: 14,
        config: { instanceClass: "db.t4g.micro", multiAz: false },
      },
      network: {
        service: "vpc-public-strict-sg",
        why: "Avoids $32.85/mo NAT Gateway charge while keeping RDS in private subnets.",
        alternatives: [],
        monthlyCostUsd: 0,
        config: { natGateway: false },
      },
    },
    ...overrides,
  };
}

describe("034 AWS target schema (T3403)", () => {
  it("accepts a valid AWS managed target with default-on guardrails and observability", () => {
    const parsed = AwsTargetSchema.parse(baseAwsTarget());
    expect(parsed.provider).toBe("aws");
    expect(parsed.guardrails).toEqual({
      privateDatabase: true,
      encryptionAtRest: true,
      automatedBackups: true,
      s3BlockPublicAccess: true,
      leastPrivilegeIam: true,
      logRetention: true,
      noPrivateCa: true,
    });
    expect(parsed.observability.logsRetentionDays).toBe(30);
    expect(parsed.observability.alarms).toBe(true);
    expect(isAwsTarget(parsed)).toBe(true);
    expect(isManagedCloudTarget(parsed)).toBe(true);
    expect(isManagedCloudProvider("aws")).toBe(true);
    expect(DeployProviderSchema.options).toContain("aws");
  });

  it("refuses disabling any guardrail silently, and accepts it with an explicit recorded exception", () => {
    const silent = AwsTargetSchema.safeParse(
      baseAwsTarget({
        guardrails: { privateDatabase: false },
      }),
    );
    expect(silent.success).toBe(false);
    if (!silent.success) {
      expect(silent.error.issues[0]?.message).toContain("cannot be disabled silently");
    }

    const recorded = AwsTargetSchema.safeParse(
      baseAwsTarget({
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

  it("refuses Fargate for databases, invalid CloudWatch log retention, and conflicting pins", () => {
    const fargateDb = AwsTargetSchema.safeParse(
      baseAwsTarget({
        components: {
          database: {
            service: "ecs-fargate-postgres",
            why: "wrong",
            monthlyCostUsd: 15,
          },
        },
      }),
    );
    expect(fargateDb.success).toBe(false);
    if (!fargateDb.success) {
      expect(fargateDb.error.issues[0]?.message).toContain("refuses Fargate for databases");
    }

    const badRetention = AwsTargetSchema.safeParse(
      baseAwsTarget({
        observability: { logsRetentionDays: 999 },
      }),
    );
    expect(badRetention.success).toBe(false);

    const badNatPin = AwsTargetSchema.safeParse(
      baseAwsTarget({
        pins: { noNat: true },
        components: {
          network: {
            service: "vpc-nat",
            why: "NAT enabled",
            monthlyCostUsd: 33,
            config: { natGateway: true },
          },
        },
      }),
    );
    expect(badNatPin.success).toBe(false);
    if (!badNatPin.success) {
      expect(badNatPin.error.issues[0]?.message).toContain("conflicts with pins.noNat");
    }
  });
});
