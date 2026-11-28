/**
 * Standalone Zod schema for `GcpTarget` inside `@opscrew/provider-gcp` so the published npm
 * bundle has ZERO runtime imports of `@opscrew/core`, `@opscrew/contracts`, or
 * `@opscrew/plan-schema` (ADR 0040 D3).
 */
import { z } from "zod";

const GcpRegionLocalSchema = z.string().regex(/^[a-z]+-[a-z]+\d+$/, {
  message: "must be a GCP region code such as us-central1 or europe-west1",
});

const GcpProjectIdLocalSchema = z.string().regex(/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/, {
  message: "must be a valid GCP project ID",
});

const GcpVpcIdLocalSchema = z
  .string()
  .regex(/^projects\/[a-z][a-z0-9-]{4,28}[a-z0-9]\/global\/networks\/[a-z][a-z0-9-]{0,62}$/, {
    message: "must be a GCP VPC network path: projects/<project-id>/global/networks/<network-name>",
  });

const GuardrailNames = [
  "privateDatabase",
  "encryptionAtRest",
  "automatedBackups",
  "privateStorage",
  "leastPrivilegeIam",
  "noStaticSaKeys",
  "noLegacyVpcConnector",
  "noLegacyRedis",
  "noGlobalAlbOnLean",
] as const;

const LEGACY_REDIS_RE = /^(?:memorystore-redis|google_redis_instance|redis-legacy)$/i;
const LEGACY_VPC_CONN_RE = /vpc[-_ ]?access[-_ ]?connector|serverless[-_ ]?vpc[-_ ]?connector/i;
const GLOBAL_ALB_RE = /global[-_ ]?alb|cloud[-_ ]?cdn|external[-_ ]?alb/i;

export const StandaloneGcpTargetSchema = z
  .strictObject({
    provider: z.literal("gcp"),
    mode: z.literal("gcp-managed"),
    region: GcpRegionLocalSchema,
    preset: z.enum(["lean", "balanced", "production-ha"]),
    compute: z.enum(["cloud-run", "compute-engine"]),
    components: z.record(
      z.string().min(1),
      z.strictObject({
        service: z.string().min(1),
        why: z.string().min(1),
        alternatives: z
          .array(
            z.strictObject({
              service: z.string().min(1),
              monthlyCostUsd: z.number().nonnegative(),
              whyNot: z.string().min(1),
            }),
          )
          .default(() => []),
        monthlyCostUsd: z.number().nonnegative(),
        config: z
          .record(z.string(), z.union([z.string(), z.number(), z.boolean()]))
          .default(() => ({})),
      }),
    ),
    pins: z
      .strictObject({
        region: GcpRegionLocalSchema.optional(),
        projectId: GcpProjectIdLocalSchema.optional(),
        budgetCapUsd: z.number().positive().optional(),
        noNat: z.boolean().optional(),
        noGlobalAlb: z.boolean().optional(),
        existingVpcId: GcpVpcIdLocalSchema.optional(),
        existingDb: z.string().min(1).optional(),
        keepCloudflareDns: z.boolean().optional(),
      })
      .default(() => ({})),
    guardrails: z
      .strictObject({
        privateDatabase: z.boolean().default(true),
        encryptionAtRest: z.boolean().default(true),
        automatedBackups: z.boolean().default(true),
        privateStorage: z.boolean().default(true),
        leastPrivilegeIam: z.boolean().default(true),
        noStaticSaKeys: z.boolean().default(true),
        noLegacyVpcConnector: z.boolean().default(true),
        noLegacyRedis: z.boolean().default(true),
        noGlobalAlbOnLean: z.boolean().default(true),
      })
      .default(() => ({
        privateDatabase: true,
        encryptionAtRest: true,
        automatedBackups: true,
        privateStorage: true,
        leastPrivilegeIam: true,
        noStaticSaKeys: true,
        noLegacyVpcConnector: true,
        noLegacyRedis: true,
        noGlobalAlbOnLean: true,
      })),
    exceptions: z
      .array(
        z.strictObject({
          guardrail: z.enum(GuardrailNames),
          reason: z.string().min(8),
        }),
      )
      .default(() => []),
    observability: z
      .strictObject({
        logsRetentionDays: z.number().int().min(1).max(3650).default(30),
        cloudTrace: z.boolean().default(false),
        alerts: z.boolean().default(true),
      })
      .default(() => ({
        logsRetentionDays: 30,
        cloudTrace: false,
        alerts: true,
      })),
  })
  .superRefine((target, ctx) => {
    const issue = (path: (string | number)[], message: string) =>
      ctx.addIssue({ code: "custom", path, message });
    const exceptionSet = new Set(target.exceptions.map((e) => e.guardrail));
    for (const name of GuardrailNames) {
      if (target.guardrails[name] === false && !exceptionSet.has(name)) {
        issue(
          ["guardrails", name],
          `cannot be disabled silently: add an entry for "${name}" with a reason under target.exceptions`,
        );
      }
    }
    const cache = target.components.cache;
    if (
      target.guardrails.noLegacyRedis !== false &&
      cache !== undefined &&
      LEGACY_REDIS_RE.test(cache.service)
    ) {
      issue(
        ["components", "cache", "service"],
        "refuses legacy Memorystore for Redis (google_redis_instance): use Memorystore for Valkey (`memorystore-valkey`) instead",
      );
    }
    const network = target.components.network;
    if (
      target.guardrails.noLegacyVpcConnector !== false &&
      network !== undefined &&
      LEGACY_VPC_CONN_RE.test(network.service)
    ) {
      issue(
        ["components", "network", "service"],
        "refuses legacy Serverless VPC Access Connector: use Cloud Run Direct VPC Egress instead",
      );
    }
    const edge = target.components.edge;
    if (edge !== undefined && GLOBAL_ALB_RE.test(edge.service)) {
      if (target.compute === "compute-engine") {
        issue(
          ["components", "edge", "service"],
          'Global External ALB serverless NEG only targets compute "cloud-run"',
        );
      } else if (target.pins.noGlobalAlb === true) {
        issue(["components", "edge", "service"], "conflicts with pins.noGlobalAlb");
      } else if (target.preset === "lean" && target.guardrails.noGlobalAlbOnLean !== false) {
        issue(
          ["components", "edge", "service"],
          'refuses Global External ALB (~$18/mo base) on the "lean" preset',
        );
      }
    }
    if (target.pins.region !== undefined && target.pins.region !== target.region) {
      issue(["region"], `must match pins.region ("${target.pins.region}")`);
    }
    if (target.pins.noNat === true && target.components.network?.config.cloudNat === true) {
      issue(["components", "network", "config", "cloudNat"], "conflicts with pins.noNat");
    }
  });
