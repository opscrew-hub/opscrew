/**
 * AWS managed-services target schema for `opscrew/plan.yaml` (Feature 034, ADR 0040).
 *
 * Records per component: the concrete AWS service choice, plain-English `why`, rejected
 * `alternatives`, itemized `monthlyCostUsd`, user `pins`, default-on `guardrails`, and explicit
 * recorded `exceptions` (never silent).
 */
import { z } from "zod";

/** AWS architecture presets balancing cost, operational simplicity, and high availability. */
export const AwsPresetSchema = z.enum(["lean", "balanced", "production-ha"]);
export type AwsPreset = z.infer<typeof AwsPresetSchema>;

/** AWS compute primitives weighed per use case (App Runner excluded for new designs: closed 2026-04-30). */
export const AwsComputeKindSchema = z.enum([
  "ec2-compose",
  "lightsail-containers",
  "ecs-fargate",
  "ecs-ec2",
  "lambda-web",
  "lambda-event",
]);
export type AwsComputeKind = z.infer<typeof AwsComputeKindSchema>;

/** Valid CloudWatch Logs retention values in days (explicit retention required — never Never Expire). */
export const AWS_LOG_RETENTION_DAYS = [
  1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288,
  3653,
] as const;

/** A rejected alternative recorded alongside a chosen AWS component. */
export const AwsComponentAlternativeSchema = z.strictObject({
  service: z.string().min(1),
  monthlyCostUsd: z.number().nonnegative(),
  whyNot: z.string().min(1),
});
export type AwsComponentAlternative = z.infer<typeof AwsComponentAlternativeSchema>;

/** One managed-service decision in `target.components`. */
export const AwsComponentDecisionSchema = z.strictObject({
  /** Concrete AWS service (e.g., `ecs-fargate`, `rds-postgres`, `elasticache-valkey`, `s3-cloudfront`). */
  service: z.string().min(1),
  /** Plain-English explanation of why OpsCrew selected this service for the app. */
  why: z.string().min(1),
  /** Alternatives considered and why they were not chosen. */
  alternatives: z.array(AwsComponentAlternativeSchema).default(() => []),
  /** Estimated monthly cost in USD (us-east-1 baseline adjusted for region). */
  monthlyCostUsd: z.number().nonnegative(),
  /** Component-specific typed overrides (e.g., instanceClass, multiAz, minAcu, natGateway). */
  config: z.record(z.string(), z.union([z.string(), z.number(), z.boolean()])).default(() => ({})),
});
export type AwsComponentDecision = z.infer<typeof AwsComponentDecisionSchema>;

/** User pins that constrain AWS architecture and pricing decisions. */
export const AwsPinsSchema = z.strictObject({
  region: z
    .string()
    .regex(/^[a-z]{2}-[a-z-]+-\d$/, {
      message: "must be an AWS region code such as us-east-1 or eu-central-1",
    })
    .optional(),
  budgetCapUsd: z.number().positive().optional(),
  noNat: z.boolean().optional(),
  existingVpcId: z
    .string()
    .regex(/^vpc-[0-9a-f]{8,17}$/, { message: "must be a VPC id such as vpc-0123456789abcdef0" })
    .optional(),
  existingDb: z.string().min(1).optional(),
  keepCloudflareDns: z.boolean().optional(),
});
export type AwsPins = z.infer<typeof AwsPinsSchema>;

/** Guardrails enabled by default on every AWS deployment (ADR 0040 D6). */
export const AwsGuardrailNameSchema = z.enum([
  "privateDatabase",
  "encryptionAtRest",
  "automatedBackups",
  "s3BlockPublicAccess",
  "leastPrivilegeIam",
  "logRetention",
  "noPrivateCa",
]);
export type AwsGuardrailName = z.infer<typeof AwsGuardrailNameSchema>;

export const AwsGuardrailsSchema = z.strictObject({
  privateDatabase: z.boolean().default(true),
  encryptionAtRest: z.boolean().default(true),
  automatedBackups: z.boolean().default(true),
  s3BlockPublicAccess: z.boolean().default(true),
  leastPrivilegeIam: z.boolean().default(true),
  logRetention: z.boolean().default(true),
  noPrivateCa: z.boolean().default(true),
});
export type AwsGuardrails = z.infer<typeof AwsGuardrailsSchema>;

/** Explicit recorded exception whenever a default AWS guardrail is relaxed. */
export const AwsGuardrailExceptionSchema = z.strictObject({
  guardrail: AwsGuardrailNameSchema,
  reason: z.string().min(8, {
    message: "must explain in plain English why this guardrail is relaxed",
  }),
});
export type AwsGuardrailException = z.infer<typeof AwsGuardrailExceptionSchema>;

/** AWS observability layers (roadmap 034: CloudWatch default, Managed Grafana / OpenSearch / X-Ray opt-in). */
export const AwsObservabilitySchema = z.strictObject({
  logsRetentionDays: z
    .number()
    .int()
    .refine((d) => (AWS_LOG_RETENTION_DAYS as readonly number[]).includes(d), {
      message: "must be a valid CloudWatch Logs retention period in days (e.g., 14, 30, 90)",
    })
    .default(30),
  containerInsights: z.boolean().default(false),
  alarms: z.boolean().default(true),
  managedGrafana: z.boolean().default(false),
  openSearch: z.boolean().default(false),
  tracing: z.enum(["none", "xray", "application-signals"]).default("none"),
  otelCollector: z.boolean().default(false),
});
export type AwsObservability = z.infer<typeof AwsObservabilitySchema>;

/** AWS managed-services target (`plan.target` when `provider: "aws"`). */
export const AwsTargetSchema = z
  .strictObject({
    provider: z.literal("aws"),
    mode: z.literal("aws-managed"),
    /** AWS region code, e.g. `us-east-1`, `eu-central-1`. */
    region: z.string().regex(/^[a-z]{2}-[a-z-]+-\d$/, {
      message: "must be an AWS region code such as us-east-1 or eu-central-1",
    }),
    /** Architecture preset (`lean`, `balanced`, `production-ha`). */
    preset: AwsPresetSchema,
    /** Primary compute choice selected for the app's workload. */
    compute: AwsComputeKindSchema,
    /**
     * Per-component managed-service decisions (`compute`, `database`, `cache`, `storage`, `edge`,
     * `secrets`, `email`, `queues`, `cron`, `network`, `observability`).
     */
    components: z.record(z.string().min(1), AwsComponentDecisionSchema),
    /** User constraints pinned across design reruns. */
    pins: AwsPinsSchema.default(() => ({})),
    /** Security and cost guardrails, all on by default. */
    guardrails: AwsGuardrailsSchema.default(() => ({
      privateDatabase: true,
      encryptionAtRest: true,
      automatedBackups: true,
      s3BlockPublicAccess: true,
      leastPrivilegeIam: true,
      logRetention: true,
      noPrivateCa: true,
    })),
    /** Explicit exceptions required whenever any guardrail in `guardrails` is set to `false`. */
    exceptions: z.array(AwsGuardrailExceptionSchema).default(() => []),
    /** Observability layers and retention settings. */
    observability: AwsObservabilitySchema.default(() => ({
      logsRetentionDays: 30,
      containerInsights: false,
      alarms: true,
      managedGrafana: false,
      openSearch: false,
      tracing: "none" as const,
      otelCollector: false,
    })),
  })
  .superRefine((target, ctx) => {
    const issue = (path: (string | number)[], message: string) =>
      ctx.addIssue({ code: "custom", path, message });

    // Every relaxed guardrail must have an explicit recorded exception with a reason.
    const exceptionSet = new Set(target.exceptions.map((e) => e.guardrail));
    for (const name of AwsGuardrailNameSchema.options) {
      if (target.guardrails[name] === false && !exceptionSet.has(name)) {
        issue(
          ["guardrails", name],
          `cannot be disabled silently: add an entry for "${name}" with a reason under target.exceptions`,
        );
      }
    }

    // Fargate is never used for databases (roadmap 034 / ADR 0040 D8).
    const dbComponent = target.components.database;
    if (dbComponent !== undefined && /fargate/i.test(dbComponent.service)) {
      issue(
        ["components", "database", "service"],
        "refuses Fargate for databases: use RDS, Aurora Serverless v2, a compatible managed database, or EC2 + EBS instead",
      );
    }

    // Pin consistency: if pins.region is set, target.region must match it.
    if (target.pins.region !== undefined && target.pins.region !== target.region) {
      issue(
        ["region"],
        `must match pins.region ("${target.pins.region}"): update pins.region or target.region`,
      );
    }

    // Pin consistency: if pins.noNat is true, network component must not enable natGateway.
    if (target.pins.noNat === true && target.components.network?.config.natGateway === true) {
      issue(
        ["components", "network", "config", "natGateway"],
        "conflicts with pins.noNat: remove pins.noNat or disable natGateway to avoid NAT Gateway charges",
      );
    }
  });

export type AwsTarget = z.output<typeof AwsTargetSchema>;
