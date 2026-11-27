/**
 * Microsoft Azure managed-services target schema for `opscrew/plan.yaml` (Feature 038, ADR 0040).
 *
 * Records per component: the concrete Azure service choice, plain-English `why`, rejected
 * `alternatives`, itemized `monthlyCostUsd`, user `pins`, default-on `guardrails`, and explicit
 * recorded `exceptions` (never silent).
 */
import { z } from "zod";

/** Azure architecture presets balancing cost, operational simplicity, and high availability. */
export const AzurePresetSchema = z.enum(["lean", "balanced", "production-ha"]);
export type AzurePreset = z.infer<typeof AzurePresetSchema>;

/** Azure compute primitives weighed per use case. */
export const AzureComputeKindSchema = z.enum(["container-apps", "app-service", "vm-compose"]);
export type AzureComputeKind = z.infer<typeof AzureComputeKindSchema>;

/** Azure region code (e.g., `westeurope`, `eastus2`, `swedencentral`). */
export const AzureRegionSchema = z.string().regex(/^[a-z][a-z0-9]{2,31}$/, {
  message: "must be an Azure region code such as westeurope, eastus2, or swedencentral",
});

/** Azure Virtual Network ARM resource ID. */
export const AzureVnetIdSchema = z
  .string()
  .regex(
    /^\/subscriptions\/[0-9a-fA-F-]+\/resourceGroups\/[^/]+\/providers\/Microsoft\.Network\/virtualNetworks\/[^/]+$/,
    {
      message:
        "must be an Azure Virtual Network resource ID (/subscriptions/.../resourceGroups/.../providers/Microsoft.Network/virtualNetworks/...)",
    },
  );

/** A rejected alternative recorded alongside a chosen Azure component. */
export const AzureComponentAlternativeSchema = z.strictObject({
  service: z.string().min(1),
  monthlyCostUsd: z.number().nonnegative(),
  whyNot: z.string().min(1),
});
export type AzureComponentAlternative = z.infer<typeof AzureComponentAlternativeSchema>;

/** One managed-service decision in `target.components`. */
export const AzureComponentDecisionSchema = z.strictObject({
  /** Concrete Azure service (e.g., `container-apps`, `flexible-postgres`, `managed-redis`, `blob-storage`). */
  service: z.string().min(1),
  /** Plain-English explanation of why OpsCrew selected this service for the app. */
  why: z.string().min(1),
  /** Alternatives considered and why they were not chosen. */
  alternatives: z.array(AzureComponentAlternativeSchema).default(() => []),
  /** Estimated monthly cost in USD (eastus2 baseline adjusted for region). */
  monthlyCostUsd: z.number().nonnegative(),
  /** Component-specific typed overrides (e.g., sku, zoneRedundant, natGateway, minReplicas). */
  config: z.record(z.string(), z.union([z.string(), z.number(), z.boolean()])).default(() => ({})),
});
export type AzureComponentDecision = z.infer<typeof AzureComponentDecisionSchema>;

/** User pins that constrain Azure architecture and pricing decisions. */
export const AzurePinsSchema = z.strictObject({
  region: AzureRegionSchema.optional(),
  budgetCapUsd: z.number().positive().optional(),
  noNat: z.boolean().optional(),
  noFrontDoor: z.boolean().optional(),
  existingVnetId: AzureVnetIdSchema.optional(),
  existingDb: z.string().min(1).optional(),
  keepCloudflareDns: z.boolean().optional(),
});
export type AzurePins = z.infer<typeof AzurePinsSchema>;

/** Guardrails enabled by default on every Azure deployment (ADR 0040 D6, Feature 038). */
export const AzureGuardrailNameSchema = z.enum([
  "privateDatabase",
  "encryptionAtRest",
  "automatedBackups",
  "privateStorage",
  "leastPrivilegeRbac",
  "logRetention",
  "noFrontDoorOnLean",
  "noRetiringRedis",
]);
export type AzureGuardrailName = z.infer<typeof AzureGuardrailNameSchema>;

export const AzureGuardrailsSchema = z.strictObject({
  privateDatabase: z.boolean().default(true),
  encryptionAtRest: z.boolean().default(true),
  automatedBackups: z.boolean().default(true),
  privateStorage: z.boolean().default(true),
  leastPrivilegeRbac: z.boolean().default(true),
  logRetention: z.boolean().default(true),
  noFrontDoorOnLean: z.boolean().default(true),
  noRetiringRedis: z.boolean().default(true),
});
export type AzureGuardrails = z.infer<typeof AzureGuardrailsSchema>;

/** Explicit recorded exception whenever a default Azure guardrail is relaxed. */
export const AzureGuardrailExceptionSchema = z.strictObject({
  guardrail: AzureGuardrailNameSchema,
  reason: z.string().min(8, {
    message: "must explain in plain English why this guardrail is relaxed",
  }),
});
export type AzureGuardrailException = z.infer<typeof AzureGuardrailExceptionSchema>;

/** Azure observability layers (Log Analytics default 30-day retention, App Insights & Grafana opt-in). */
export const AzureObservabilitySchema = z.strictObject({
  logsRetentionDays: z
    .number()
    .int()
    .min(30, { message: "Azure Log Analytics retention must be between 30 and 730 days" })
    .max(730, { message: "Azure Log Analytics retention must be between 30 and 730 days" })
    .default(30),
  applicationInsights: z.boolean().default(false),
  alerts: z.boolean().default(true),
  managedGrafana: z.boolean().default(false),
});
export type AzureObservability = z.infer<typeof AzureObservabilitySchema>;

/** Retiring Azure Cache for Redis service patterns (retiring 2028; use Azure Managed Redis). */
const RETIRING_REDIS_RE = /^(?:azure-cache-for-redis|azurerm_redis_cache|redis-cache)$/i;

/** Azure Front Door service pattern. */
const FRONT_DOOR_RE = /front[-_ ]?door/i;

/** Azure managed-services target (`plan.target` when `provider: "azure"`). */
export const AzureTargetSchema = z
  .strictObject({
    provider: z.literal("azure"),
    mode: z.literal("azure-managed"),
    /** Azure region code, e.g. `westeurope`, `eastus2`, `swedencentral`. */
    region: AzureRegionSchema,
    /** Architecture preset (`lean`, `balanced`, `production-ha`). */
    preset: AzurePresetSchema,
    /** Primary compute choice selected for the app's workload. */
    compute: AzureComputeKindSchema,
    /**
     * Per-component managed-service decisions (`compute`, `database`, `cache`, `storage`, `edge`,
     * `secrets`, `queues`, `network`, `observability`).
     */
    components: z.record(z.string().min(1), AzureComponentDecisionSchema),
    /** User constraints pinned across design reruns. */
    pins: AzurePinsSchema.default(() => ({})),
    /** Security and cost guardrails, all on by default. */
    guardrails: AzureGuardrailsSchema.default(() => ({
      privateDatabase: true,
      encryptionAtRest: true,
      automatedBackups: true,
      privateStorage: true,
      leastPrivilegeRbac: true,
      logRetention: true,
      noFrontDoorOnLean: true,
      noRetiringRedis: true,
    })),
    /** Explicit exceptions required whenever any guardrail in `guardrails` is set to `false`. */
    exceptions: z.array(AzureGuardrailExceptionSchema).default(() => []),
    /** Observability layers and retention settings. */
    observability: AzureObservabilitySchema.default(() => ({
      logsRetentionDays: 30,
      applicationInsights: false,
      alerts: true,
      managedGrafana: false,
    })),
  })
  .superRefine((target, ctx) => {
    const issue = (path: (string | number)[], message: string) =>
      ctx.addIssue({ code: "custom", path, message });

    // Every relaxed guardrail must have an explicit recorded exception with a reason.
    const exceptionSet = new Set(target.exceptions.map((e) => e.guardrail));
    for (const name of AzureGuardrailNameSchema.options) {
      if (target.guardrails[name] === false && !exceptionSet.has(name)) {
        issue(
          ["guardrails", name],
          `cannot be disabled silently: add an entry for "${name}" with a reason under target.exceptions`,
        );
      }
    }

    // Refuse retiring Azure Cache for Redis unless explicitly excepted.
    const cacheComponent = target.components.cache;
    if (
      target.guardrails.noRetiringRedis !== false &&
      cacheComponent !== undefined &&
      RETIRING_REDIS_RE.test(cacheComponent.service)
    ) {
      issue(
        ["components", "cache", "service"],
        "refuses retiring Azure Cache for Redis (azurerm_redis_cache): use Azure Managed Redis (`managed-redis`) instead",
      );
    }

    // Refuse $35/mo Azure Front Door on lean preset unless explicitly excepted, or when pinned off.
    const edgeComponent = target.components.edge;
    if (edgeComponent !== undefined && FRONT_DOOR_RE.test(edgeComponent.service)) {
      if (target.pins.noFrontDoor === true) {
        issue(
          ["components", "edge", "service"],
          "conflicts with pins.noFrontDoor: remove pins.noFrontDoor or keep Cloudflare/built-in TLS edge",
        );
      } else if (target.preset === "lean" && target.guardrails.noFrontDoorOnLean !== false) {
        issue(
          ["components", "edge", "service"],
          'refuses Azure Front Door ($35/mo base) on the "lean" preset: use Cloudflare or built-in Container Apps TLS, or record an exception for "noFrontDoorOnLean"',
        );
      }
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
        "conflicts with pins.noNat: remove pins.noNat or disable natGateway to avoid ~$37/mo Azure NAT Gateway charges",
      );
    }
  });

export type AzureTarget = z.output<typeof AzureTargetSchema>;
