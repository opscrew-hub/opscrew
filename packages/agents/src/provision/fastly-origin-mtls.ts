/**
 * Provisioning sync for `mtls-client-cert` edge providers (`pull.pem`, ADR 0038 D6, Fastly).
 * Dispatches exclusively through `@opscrew/edge-providers` (`edgeProvider(id).connector`) using
 * `activeEdgeProvider(plan)` so `@opscrew/agents` never hardcodes a provider id (ADR 0029).
 */
import type { EdgeOriginMtlsPlan, FetchLike } from "@opscrew/contracts";
import { OpsCrewError } from "@opscrew/core";
import { edgeProvider } from "@opscrew/edge-providers";
import { usesOriginMtls } from "@opscrew/iac-templates";
import { activeEdgeProvider, type DeployPlan } from "@opscrew/plan-schema";
import type { PhaseDeps } from "../context";
import { requestApproval } from "../shared/approvals";

/**
 * Plans, approves by SHA-256 hash, and applies the active `mtls-client-cert` edge provider's
 * backend mTLS client certificate/key and optional pinned origin CA certificate via its registry
 * connector (never via Terraform state).
 */
export async function syncOriginMtls(
  deps: Pick<PhaseDeps, "approvals" | "reporter" | "redactor">,
  plan: DeployPlan,
  input: {
    apiKey: string;
    serviceId: string;
    backendName: string;
    clientCertPem: string;
    clientKeyPem: string;
    originCaCertPem?: string;
    originAddress?: string;
    command: string;
    planOnly?: boolean;
    fetch?: FetchLike;
  },
): Promise<{ plan: EdgeOriginMtlsPlan; applied: boolean; activatedVersion?: number }> {
  if (!usesOriginMtls(plan)) {
    throw new OpsCrewError(
      "INVALID_INPUT",
      "This plan does not use an origin mTLS edge provider. Nothing was changed.",
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
  const connector = edge.connector;
  if (connector?.planOriginMtls === undefined || connector.applyOriginMtls === undefined) {
    throw new OpsCrewError(
      "INTERNAL",
      `Edge provider "${edgeId}" does not define an origin mTLS connector.`,
    );
  }
  deps.redactor.addLiteral(input.apiKey, `${edgeId}-api-key`);
  deps.redactor.addLiteral(input.clientKeyPem, "origin-mtls-key");
  const planned = await connector.planOriginMtls({
    apiKey: input.apiKey,
    serviceId: input.serviceId,
    backendName: input.backendName,
    clientCertPem: input.clientCertPem,
    clientKeyPem: input.clientKeyPem,
    ...(input.originCaCertPem === undefined ? {} : { originCaCertPem: input.originCaCertPem }),
    ...(input.originAddress === undefined ? {} : { originAddress: input.originAddress }),
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
    title: `Configure origin mTLS on ${edge.displayName} service ${input.serviceId}`,
    details: `${planned.summary}\nPlan hash: ${planned.hash}`,
    hash: planned.hash,
    refused: {
      plan: `${edge.displayName} origin mTLS update`,
      unchanged: `Nothing was changed on ${edge.displayName}. Until this origin mTLS update is approved, ${edge.displayName} will return HTTP 503 because the origin requires pull.pem and the edge has not yet pinned the origin CA.`,
      again: input.command,
    },
  });
  await deps.approvals.assertApprovedPlan(planned.hash);
  const result = await connector.applyOriginMtls({
    apiKey: input.apiKey,
    plan: planned,
    clientCertPem: input.clientCertPem,
    clientKeyPem: input.clientKeyPem,
    ...(input.originCaCertPem === undefined ? {} : { originCaCertPem: input.originCaCertPem }),
    ...(input.originAddress === undefined ? {} : { originAddress: input.originAddress }),
    approvedHash: planned.hash,
    ...(input.fetch === undefined ? {} : { fetch: input.fetch }),
    redactor: deps.redactor,
  });
  return {
    plan: planned,
    applied: result.applied,
    ...(result.activatedVersion === undefined ? {} : { activatedVersion: result.activatedVersion }),
  };
}
