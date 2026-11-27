/**
 * Provisioning and connector sync for non-Cloudflare edge/DNS providers and `shared-header`
 * origin-verification tokens (ADR 0038 D6, Bunny.net / Gcore).
 *
 * Every provider call goes through `@opscrew/edge-providers` (`edgeProvider(id)`): no code here
 * branches on a specific edge provider id (ADR 0029).
 *
 * Security invariants:
 * - The 32-byte hex secret lives in local `generated_values.json` (0600), GitHub Actions deploy
 *   secret `OPSCREW_EDGE_ORIGIN_TOKEN`, and the server's `/srv/edge/tls/<app>/origin-token.<ext>`
 *   (0600) — NEVER in Terraform state or git.
 * - Every remote origin-header mutation requires a plan-hash-bound approval (`requestApproval` +
 *   `assertApprovedPlan`) before applying (constitution I).
 */
import { randomBytes as nodeRandomBytes } from "node:crypto";
import { mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import type { EdgeOriginHeaderPlan, FetchLike } from "@opscrew/contracts";
import { OpsCrewError, readTextIfExists, writeFileAtomic } from "@opscrew/core";
import { edgeProvider } from "@opscrew/edge-providers";
import { thirdPartyEdgeId, usesSharedOriginHeader } from "@opscrew/iac-templates";
import { activeEdgeProvider, type DeployPlan } from "@opscrew/plan-schema";
import { z } from "zod";
import type { PhaseDeps } from "../context";
import {
  type EdgeOriginTokenSchema,
  GeneratedValuesSchema,
  generatedValuesFile,
} from "../shared/app-secrets";
import { requestApproval } from "../shared/approvals";
import type { ProvisionServices } from "./types";

/** Credential name used by `opscrew rotate` for the shared edge origin-verification token. */
export const EDGE_ORIGIN_TOKEN_CREDENTIAL = "edge-origin-token";

export type EdgeOriginTokenValue = z.infer<typeof EdgeOriginTokenSchema>;

/** Resolved credentials and optional DNS zone id / zone name / CIDR ranges for a non-Cloudflare edge/DNS provider. */
export interface ThirdPartyEdgeSetup {
  id: string;
  envVar: string;
  apiKey: string;
  dnsZoneId?: number;
  /** Learned DNS zone name (for example `example.com`) when `dns.zone` was omitted in plan.yaml. */
  dnsZoneName?: string;
  /**
   * Separate DNS provider credentials when `dns.provider` and `dns.edge` are two distinct
   * non-Cloudflare providers (for example `dns.provider: bunny` with `dns.edge: fastly`).
   */
  dnsProvider?: {
    id: string;
    envVar: string;
    apiKey: string;
  };
  edgeRanges?: string[];
}

const RawGeneratedObjectSchema = z.looseObject({});

/** Generates a 32-byte lower-case hex token (64 hex characters). */
export function generateEdgeOriginToken(
  randomBytes: (n: number) => Buffer = nodeRandomBytes,
): string {
  return randomBytes(32).toString("hex");
}

/** Registers every token in `value` with `redactor`. */
function registerTokens(
  deps: Pick<PhaseDeps, "redactor">,
  value: EdgeOriginTokenValue | undefined,
): void {
  if (value === undefined) return;
  deps.redactor.addLiteral(value.current, "edge-origin-token");
  if (value.previous !== undefined) deps.redactor.addLiteral(value.previous, "edge-origin-token");
}

/** Reads `edgeOriginToken` from `generated_values.json` and registers it with the redactor. */
export async function readEdgeOriginToken(
  deps: Pick<PhaseDeps, "paths" | "redactor">,
): Promise<EdgeOriginTokenValue | undefined> {
  const text = await readTextIfExists(generatedValuesFile(deps));
  if (text === undefined) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return undefined;
  }
  const values = GeneratedValuesSchema.safeParse(parsed);
  if (!values.success || values.data.edgeOriginToken === undefined) return undefined;
  registerTokens(deps, values.data.edgeOriginToken);
  return values.data.edgeOriginToken;
}

/** Persists `edgeOriginToken` atomically into `generated_values.json` (mode 0600). */
export async function writeEdgeOriginToken(
  deps: Pick<PhaseDeps, "paths" | "redactor">,
  value: EdgeOriginTokenValue,
): Promise<void> {
  registerTokens(deps, value);
  const file = generatedValuesFile(deps);
  const existingText = await readTextIfExists(file);
  const current =
    existingText === undefined ? {} : RawGeneratedObjectSchema.parse(JSON.parse(existingText));
  await mkdir(dirname(file), { recursive: true, mode: 0o700 });
  await writeFileAtomic(
    file,
    `${JSON.stringify({ ...current, edgeOriginToken: value }, null, 2)}\n`,
    { mode: 0o600 },
  );
}

/** Returns the existing `edgeOriginToken` or generates and persists a new 32-byte hex secret once. */
export async function ensureEdgeOriginToken(
  deps: Pick<PhaseDeps, "paths" | "redactor">,
  randomBytes: (n: number) => Buffer = nodeRandomBytes,
): Promise<EdgeOriginTokenValue> {
  const kept = await readEdgeOriginToken(deps);
  if (kept !== undefined) return kept;
  const created: EdgeOriginTokenValue = { current: generateEdgeOriginToken(randomBytes) };
  await writeEdgeOriginToken(deps, created);
  return created;
}

/** Formats `edgeOriginToken` for the `OPSCREW_EDGE_ORIGIN_TOKEN` deploy secret (1 or 2 lines). */
export function formatEdgeOriginTokenSecret(value: EdgeOriginTokenValue): string {
  return value.previous === undefined ? value.current : `${value.current}\n${value.previous}`;
}

/**
 * Reads and redacts the API key for a non-Cloudflare edge/DNS provider `id` from `deps.env`.
 * @throws OpsCrewError `CREDENTIALS_MISSING` when unset.
 */
export function requireThirdPartyEdgeKey(
  deps: Pick<PhaseDeps, "env" | "redactor">,
  id: string,
): { envVar: string; apiKey: string } {
  const edge = edgeProvider(id);
  const envVar = edge.credentials.envVars[0];
  if (envVar === undefined) {
    throw new OpsCrewError("INTERNAL", `Edge provider "${id}" defines no credential variable.`);
  }
  const apiKey = deps.env[envVar]?.trim() ?? "";
  if (apiKey.length === 0) {
    throw new OpsCrewError(
      "CREDENTIALS_MISSING",
      `No ${edge.displayName} API key found: set ${envVar}.`,
      {
        hint: `Create an API key at ${edge.credentials.createUrl}, export ${envVar}, and try again.`,
      },
    );
  }
  deps.redactor.addLiteral(apiKey, `${id}-api-key`);
  return { envVar, apiKey };
}

/**
 * Checks credentials and (when a non-Cloudflare provider manages DNS) looks up the DNS zone id
 * and zone name via the edge registry. When `dns.provider` and `dns.edge` are two separate
 * non-Cloudflare providers (for example Bunny DNS + Fastly edge), verifies BOTH providers'
 * credentials and looks up the DNS zone on `dns.provider`. Returns `undefined` when the plan uses
 * Cloudflare or no third-party edge/DNS provider.
 */
export async function setupThirdPartyEdge(
  deps: Pick<PhaseDeps, "env" | "redactor">,
  plan: DeployPlan,
  services: Pick<ProvisionServices, "edgeFetch"> = {},
): Promise<ThirdPartyEdgeSetup | undefined> {
  const id = thirdPartyEdgeId(plan);
  if (id === undefined) return undefined;
  const edge = edgeProvider(id);
  const { envVar, apiKey } = requireThirdPartyEdgeKey(deps, id);
  const connector = edge.connector;
  if (connector !== undefined) {
    const check = await connector.verifyCredentials({
      apiKey,
      ...(services.edgeFetch === undefined ? {} : { fetch: services.edgeFetch }),
      redactor: deps.redactor,
    });
    if (!check.ok) {
      throw new OpsCrewError("CREDENTIALS_INVALID", check.message, {
        hint: `Check ${envVar} at ${edge.credentials.createUrl}, then try again.`,
      });
    }
  }

  const dnsId =
    plan.dns.provider !== "cloudflare" && plan.dns.provider !== "none"
      ? plan.dns.provider
      : undefined;
  let dnsProvider: ThirdPartyEdgeSetup["dnsProvider"];
  let dnsZoneId: number | undefined;
  let dnsZoneName: string | undefined;
  if (dnsId !== undefined && dnsId !== id) {
    const dnsEdge = edgeProvider(dnsId);
    const dnsCreds = requireThirdPartyEdgeKey(deps, dnsId);
    dnsProvider = { id: dnsId, envVar: dnsCreds.envVar, apiKey: dnsCreds.apiKey };
    const dnsConnector = dnsEdge.connector;
    if (dnsConnector !== undefined) {
      const dnsCheck = await dnsConnector.verifyCredentials({
        apiKey: dnsCreds.apiKey,
        ...(services.edgeFetch === undefined ? {} : { fetch: services.edgeFetch }),
        redactor: deps.redactor,
      });
      if (!dnsCheck.ok) {
        throw new OpsCrewError("CREDENTIALS_INVALID", dnsCheck.message, {
          hint: `Check ${dnsCreds.envVar} at ${dnsEdge.credentials.createUrl}, then try again.`,
        });
      }
      if (dnsConnector.lookupDnsZone !== undefined && plan.dns.domain !== undefined) {
        const zone = await dnsConnector.lookupDnsZone({
          apiKey: dnsCreds.apiKey,
          domain: plan.dns.domain,
          ...(services.edgeFetch === undefined ? {} : { fetch: services.edgeFetch }),
          redactor: deps.redactor,
        });
        if (zone === undefined) {
          throw new OpsCrewError(
            "PHASE_PRECONDITION",
            `${dnsEdge.displayName} has no DNS zone matching "${plan.dns.domain}".`,
            {
              hint: `Add the DNS zone for "${plan.dns.domain}" in ${dnsEdge.displayName}, then run \`opscrew provision\` again.`,
            },
          );
        }
        dnsZoneId = zone.id;
        dnsZoneName = zone.domain;
      }
    }
  } else if (
    dnsId === id &&
    connector?.lookupDnsZone !== undefined &&
    plan.dns.domain !== undefined
  ) {
    const zone = await connector.lookupDnsZone({
      apiKey,
      domain: plan.dns.domain,
      ...(services.edgeFetch === undefined ? {} : { fetch: services.edgeFetch }),
      redactor: deps.redactor,
    });
    if (zone === undefined) {
      throw new OpsCrewError(
        "PHASE_PRECONDITION",
        `${edge.displayName} has no DNS zone matching "${plan.dns.domain}".`,
        {
          hint: `Add the DNS zone for "${plan.dns.domain}" in ${edge.displayName}, then run \`opscrew provision\` again.`,
        },
      );
    }
    dnsZoneId = zone.id;
    dnsZoneName = zone.domain;
  }

  let edgeRanges: string[] | undefined;
  if (
    edge.capabilities.originIpFiltering === "compact-cidrs" &&
    connector?.getIpRanges !== undefined
  ) {
    const ranges = await connector.getIpRanges({
      ...(services.edgeFetch === undefined ? {} : { fetch: services.edgeFetch }),
      redactor: deps.redactor,
    });
    edgeRanges = [...ranges.ipv4, ...ranges.ipv6];
  }
  return {
    id,
    envVar,
    apiKey,
    ...(dnsZoneId === undefined ? {} : { dnsZoneId }),
    ...(dnsZoneName === undefined ? {} : { dnsZoneName }),
    ...(dnsProvider === undefined ? {} : { dnsProvider }),
    ...(edgeRanges === undefined ? {} : { edgeRanges }),
  };
}

/**
 * Plans, approves by SHA-256 hash, and applies the active `shared-header` edge provider's
 * origin-verification header via its registry connector (never via Terraform).
 */
export async function syncEdgeOriginHeader(
  deps: Pick<PhaseDeps, "approvals" | "reporter" | "redactor">,
  plan: DeployPlan,
  input: {
    resourceId: string;
    token: string;
    apiKey: string;
    command: string;
    planOnly?: boolean;
    fetch?: FetchLike;
  },
): Promise<{ plan: EdgeOriginHeaderPlan; applied: boolean }> {
  if (!usesSharedOriginHeader(plan)) {
    throw new OpsCrewError(
      "INVALID_INPUT",
      "This plan does not use a shared-header edge provider. Nothing was changed.",
    );
  }
  const edgeId = activeEdgeProvider(plan);
  if (edgeId === undefined) {
    throw new OpsCrewError(
      "INVALID_INPUT",
      "This plan has no active edge provider. Nothing was changed.",
    );
  }
  const edge = edgeProvider(edgeId);
  const headerName = edge.capabilities.originAuthHeader;
  const connector = edge.connector;
  if (
    headerName === undefined ||
    connector?.planOriginHeader === undefined ||
    connector.applyOriginHeader === undefined
  ) {
    throw new OpsCrewError(
      "INTERNAL",
      `Edge provider "${edgeId}" does not define a shared-header connector.`,
    );
  }
  deps.redactor.addLiteral(input.token, "edge-origin-token");
  deps.redactor.addLiteral(input.apiKey, `${edgeId}-api-key`);
  const planned = await connector.planOriginHeader({
    apiKey: input.apiKey,
    resourceId: input.resourceId,
    headerName,
    token: input.token,
    ...(input.fetch === undefined ? {} : { fetch: input.fetch }),
    redactor: deps.redactor,
  });
  if (planned.action === "noop") {
    return { plan: planned, applied: false };
  }
  if (input.planOnly === true) {
    deps.reporter.info(
      `${planned.summary}\nPlan hash: ${planned.hash}\nIn a script, approve it with --approve ${planned.hash}.`,
    );
    return { plan: planned, applied: false };
  }
  await requestApproval(deps, {
    kind: "iac-apply",
    title: `Configure ${headerName} on ${edge.displayName} (${input.resourceId})`,
    details: `${planned.summary}\nPlan hash: ${planned.hash}`,
    hash: planned.hash,
    refused: {
      plan: `${edge.displayName} origin-header update`,
      unchanged: `Nothing was changed on ${edge.displayName}.`,
      again: input.command,
    },
  });
  await deps.approvals.assertApprovedPlan(planned.hash);
  const result = await connector.applyOriginHeader({
    apiKey: input.apiKey,
    plan: planned,
    token: input.token,
    approvedHash: planned.hash,
    ...(input.fetch === undefined ? {} : { fetch: input.fetch }),
    redactor: deps.redactor,
  });
  return { plan: planned, applied: result.applied };
}
