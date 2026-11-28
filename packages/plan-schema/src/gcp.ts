/**
 * Google Cloud (GCP) managed-services target schema for `opscrew/plan.yaml` (Feature 039, ADR 0040).
 *
 * Records per component: the concrete GCP service choice, plain-English `why`, rejected
 * `alternatives`, itemized `monthlyCostUsd`, user `pins`, default-on `guardrails`, and explicit
 * recorded `exceptions` (never silent).
 */
import { z } from "zod";

/** GCP architecture presets balancing cost, operational simplicity, and high availability. */
export const GcpPresetSchema = z.enum(["lean", "balanced", "production-ha"]);
export type GcpPreset = z.infer<typeof GcpPresetSchema>;

/** GCP compute primitives weighed per use case (GKE out of scope for v1 per roadmap). */
export const GcpComputeKindSchema = z.enum(["cloud-run", "compute-engine"]);
export type GcpComputeKind = z.infer<typeof GcpComputeKindSchema>;

/** GCP region code (e.g., `us-central1`, `europe-west1`, `europe-north1`, `asia-southeast1`). */
export const GcpRegionSchema = z.string().regex(/^[a-z]+-[a-z]+\d+$/, {
  message: "must be a GCP region code such as us-central1, europe-west1, or asia-southeast1",
});

/** GCP project ID (6-30 lowercase letters, digits, hyphens; starts with letter). */
export const GcpProjectIdSchema = z.string().regex(/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/, {
  message: "must be a valid GCP project ID (6-30 lowercase letters, digits, or hyphens)",
});

/** GCP VPC network self-link or resource path (`projects/<id>/global/networks/<name>`). */
export const GcpVpcIdSchema = z
  .string()
  .regex(/^projects\/[a-z][a-z0-9-]{4,28}[a-z0-9]\/global\/networks\/[a-z][a-z0-9-]{0,62}$/, {
    message: "must be a GCP VPC network path: projects/<project-id>/global/networks/<network-name>",
  });

export const GcpComponentAlternativeSchema = z.strictObject({
  service: z.string().min(1),
  monthlyCostUsd: z.number().nonnegative(),
  whyNot: z.string().min(1),
});
export type GcpComponentAlternative = z.infer<typeof GcpComponentAlternativeSchema>;

export const GcpComponentDecisionSchema = z.strictObject({
  /** Concrete GCP service (e.g., `cloud-run`, `cloud-sql-postgres`, `memorystore-valkey`, `gcs`). */
  service: z.string().min(1),
  /** Plain-English explanation of why OpsCrew selected this service for the app. */
  why: z.string().min(1),
  /** Alternatives considered and why they were not chosen. */
  alternatives: z.array(GcpComponentAlternativeSchema).default(() => []),
  /** Estimated monthly cost in USD (`us-central1` baseline adjusted for region). */
  monthlyCostUsd: z.number().nonnegative(),
  /** Component-specific typed overrides (e.g., tier, regionalHa, minInstances, cloudNat). */
  config: z.record(z.string(), z.union([z.string(), z.number(), z.boolean()])).default(() => ({})),
});
export type GcpComponentDecision = z.infer<typeof GcpComponentDecisionSchema>;

export const GcpPinsSchema = z.strictObject({
  region: GcpRegionSchema.optional(),
  projectId: GcpProjectIdSchema.optional(),
  budgetCapUsd: z.number().positive().optional(),
  noNat: z.boolean().optional(),
  noGlobalAlb: z.boolean().optional(),
  existingVpcId: GcpVpcIdSchema.optional(),
  existingDb: z.string().min(1).optional(),
  keepCloudflareDns: z.boolean().optional(),
});
export type GcpPins = z.infer<typeof GcpPinsSchema>;

/** Guardrails enabled by default on every GCP deployment (ADR 0040 D6, Feature 039). */
export const GcpGuardrailNameSchema = z.enum([
  "privateDatabase",
  "encryptionAtRest",
  "automatedBackups",
  "privateStorage",
  "leastPrivilegeIam",
  "noStaticSaKeys",
  "noLegacyVpcConnector",
  "noLegacyRedis",
  "noGlobalAlbOnLean",
]);
export type GcpGuardrailName = z.infer<typeof GcpGuardrailNameSchema>;

export const GcpGuardrailsSchema = z.strictObject({
  privateDatabase: z.boolean().default(true),
  encryptionAtRest: z.boolean().default(true),
  automatedBackups: z.boolean().default(true),
  privateStorage: z.boolean().default(true),
  leastPrivilegeIam: z.boolean().default(true),
  noStaticSaKeys: z.boolean().default(true),
  noLegacyVpcConnector: z.boolean().default(true),
  noLegacyRedis: z.boolean().default(true),
  noGlobalAlbOnLean: z.boolean().default(true),
});
export type GcpGuardrails = z.infer<typeof GcpGuardrailsSchema>;

export const GcpGuardrailExceptionSchema = z.strictObject({
  guardrail: GcpGuardrailNameSchema,
  reason: z.string().min(8, {
    message: "must explain in plain English why this guardrail is relaxed",
  }),
});
export type GcpGuardrailException = z.infer<typeof GcpGuardrailExceptionSchema>;

/** GCP observability layers (Cloud Logging retention 1..3650 days, default 30). */
export const GcpObservabilitySchema = z.strictObject({
  logsRetentionDays: z
    .number()
    .int()
    .min(1, { message: "Cloud Logging retention must be between 1 and 3650 days" })
    .max(3650, { message: "Cloud Logging retention must be between 1 and 3650 days" })
    .default(30),
  cloudTrace: z.boolean().default(false),
  alerts: z.boolean().default(true),
});
export type GcpObservability = z.infer<typeof GcpObservabilitySchema>;

const LEGACY_REDIS_RE = /^(?:memorystore-redis|google_redis_instance|redis-legacy)$/i;
const LEGACY_VPC_CONN_RE = /vpc[-_ ]?access[-_ ]?connector|serverless[-_ ]?vpc[-_ ]?connector/i;
const GLOBAL_ALB_RE = /global[-_ ]?alb|cloud[-_ ]?cdn|external[-_ ]?alb/i;

/** GCP managed-services target (`plan.target` when `provider: "gcp"`). */
export const GcpTargetSchema = z
  .strictObject({
    provider: z.literal("gcp"),
    mode: z.literal("gcp-managed"),
    region: GcpRegionSchema,
    preset: GcpPresetSchema,
    compute: GcpComputeKindSchema,
    components: z.record(z.string().min(1), GcpComponentDecisionSchema),
    pins: GcpPinsSchema.default(() => ({})),
    guardrails: GcpGuardrailsSchema.default(() => ({
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
    exceptions: z.array(GcpGuardrailExceptionSchema).default(() => []),
    observability: GcpObservabilitySchema.default(() => ({
      logsRetentionDays: 30,
      cloudTrace: false,
      alerts: true,
    })),
  })
  .superRefine((target, ctx) => {
    const issue = (path: (string | number)[], message: string) =>
      ctx.addIssue({ code: "custom", path, message });

    const exceptionSet = new Set(target.exceptions.map((e) => e.guardrail));
    for (const name of GcpGuardrailNameSchema.options) {
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
        "refuses legacy Serverless VPC Access Connector (~$14-18/mo idle VMs): use Cloud Run Direct VPC Egress instead",
      );
    }

    const edge = target.components.edge;
    if (edge !== undefined && GLOBAL_ALB_RE.test(edge.service)) {
      if (target.pins.noGlobalAlb === true) {
        issue(
          ["components", "edge", "service"],
          "conflicts with pins.noGlobalAlb: remove pins.noGlobalAlb or keep built-in *.run.app / Cloudflare edge",
        );
      } else if (target.preset === "lean" && target.guardrails.noGlobalAlbOnLean !== false) {
        issue(
          ["components", "edge", "service"],
          'refuses Global External ALB (~$18/mo base) on the "lean" preset: use free *.run.app or record an exception for "noGlobalAlbOnLean"',
        );
      }
    }

    if (target.pins.region !== undefined && target.pins.region !== target.region) {
      issue(
        ["region"],
        `must match pins.region ("${target.pins.region}"): update pins.region or target.region`,
      );
    }

    if (target.pins.noNat === true && target.components.network?.config.cloudNat === true) {
      issue(
        ["components", "network", "config", "cloudNat"],
        "conflicts with pins.noNat: remove pins.noNat or disable cloudNat to avoid Cloud NAT gateway & per-GiB charges",
      );
    }
  });

export type GcpTarget = z.output<typeof GcpTargetSchema>;
