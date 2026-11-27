/**
 * Local standalone Zod validation for `AzureTarget` inside `@opscrew/provider-azure`
 * so the published npm bundle has ZERO runtime dependency on `@opscrew/plan-schema` or
 * `@opscrew/core` (ADR 0040 D3, Opus 5.5 Blocker B4).
 */
import { z } from "zod";

const AzureRegionLocalSchema = z.string().regex(/^[a-z][a-z0-9]{2,31}$/, {
  message: "must be an Azure region code such as westeurope, eastus2, or swedencentral",
});

const AzureVnetIdLocalSchema = z
  .string()
  .regex(
    /^\/subscriptions\/[0-9a-fA-F-]+\/resourceGroups\/[^/]+\/providers\/Microsoft\.Network\/virtualNetworks\/[^/]+$/,
    {
      message: "must be an Azure Virtual Network resource ID",
    },
  );

const GuardrailNames = [
  "privateDatabase",
  "encryptionAtRest",
  "automatedBackups",
  "privateStorage",
  "leastPrivilegeRbac",
  "logRetention",
  "noFrontDoorOnLean",
  "noRetiringRedis",
] as const;

const RETIRING_REDIS_RE = /^(?:azure-cache-for-redis|azurerm_redis_cache|redis-cache)$/i;
const FRONT_DOOR_RE = /front[-_ ]?door/i;

export const StandaloneAzureTargetSchema = z
  .strictObject({
    provider: z.literal("azure"),
    mode: z.literal("azure-managed"),
    region: AzureRegionLocalSchema,
    preset: z.enum(["lean", "balanced", "production-ha"]),
    compute: z.enum(["container-apps", "app-service", "vm-compose"]),
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
        region: AzureRegionLocalSchema.optional(),
        budgetCapUsd: z.number().positive().optional(),
        noNat: z.boolean().optional(),
        noFrontDoor: z.boolean().optional(),
        existingVnetId: AzureVnetIdLocalSchema.optional(),
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
        leastPrivilegeRbac: z.boolean().default(true),
        logRetention: z.boolean().default(true),
        noFrontDoorOnLean: z.boolean().default(true),
        noRetiringRedis: z.boolean().default(true),
      })
      .default(() => ({
        privateDatabase: true,
        encryptionAtRest: true,
        automatedBackups: true,
        privateStorage: true,
        leastPrivilegeRbac: true,
        logRetention: true,
        noFrontDoorOnLean: true,
        noRetiringRedis: true,
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
        logsRetentionDays: z.number().int().min(30).max(730).default(30),
        applicationInsights: z.boolean().default(false),
        alerts: z.boolean().default(true),
        managedGrafana: z.boolean().default(false),
      })
      .default(() => ({
        logsRetentionDays: 30,
        applicationInsights: false,
        alerts: true,
        managedGrafana: false,
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
      target.guardrails.noRetiringRedis !== false &&
      cache !== undefined &&
      RETIRING_REDIS_RE.test(cache.service)
    ) {
      issue(
        ["components", "cache", "service"],
        "refuses retiring Azure Cache for Redis (azurerm_redis_cache): use Azure Managed Redis (`managed-redis`) instead",
      );
    }
    const edge = target.components.edge;
    if (edge !== undefined && FRONT_DOOR_RE.test(edge.service)) {
      if (target.pins.noFrontDoor === true) {
        issue(["components", "edge", "service"], "conflicts with pins.noFrontDoor");
      } else if (target.preset === "lean" && target.guardrails.noFrontDoorOnLean !== false) {
        issue(
          ["components", "edge", "service"],
          'refuses Azure Front Door ($35/mo base) on the "lean" preset',
        );
      }
    }
    if (target.pins.region !== undefined && target.pins.region !== target.region) {
      issue(["region"], `must match pins.region ("${target.pins.region}")`);
    }
    if (target.pins.noNat === true && target.components.network?.config.natGateway === true) {
      issue(["components", "network", "config", "natGateway"], "conflicts with pins.noNat");
    }
  });
