/**
 * Plan-hash-bound Fastly backend mTLS configuration (ADR 0038 D6).
 *
 * Why this is NOT in Terraform: `fastly_service_vcl.backend.ssl_client_key` would persist the
 * private client key inside Terraform state. Instead, OpsCrew keeps the per-app P-256 client key
 * in local `generated_values.json` (0600), puts only the public client certificate in `pull.pem`
 * on the server proxy, and configures `ssl_client_cert`, `ssl_client_key`, `ssl_ca_cert`, and
 * backend `address` on the Fastly backend through Fastly's API (clone active version -> update
 * backend -> activate) after an approval bound to the plan's SHA-256 hash.
 */
import { canonicalJson, OpsCrewError, sha256Hex } from "@opscrew/core";
import type { FastlyClient } from "./client";

export type FastlyMtlsAction = "configure" | "update" | "noop";

export interface FastlyOriginMtlsPlan {
  action: FastlyMtlsAction;
  serviceId: string;
  activeVersion: number;
  backendName: string;
  /** Short SHA-256 fingerprint of the public client certificate PEM (never the private key). */
  certFingerprint: string;
  /** Short SHA-256 fingerprint of the pinned origin CA certificate PEM, when configured. */
  caCertFingerprint?: string;
  /** Desired origin server address when reconciling backend address alongside mTLS. */
  originAddress?: string;
  /** Plain-English summary shown before approval (contains no private key). */
  summary: string;
  /** SHA-256 hash binding approval to this exact service, version, backend, and cert fingerprints. */
  hash: string;
}

function normalizePem(pem: string): string {
  return pem.replace(/\r\n/g, "\n").trim();
}

function assertClientKeyPair(certPem: string, keyPem: string, originCaCertPem?: string): void {
  if (!certPem.includes("BEGIN CERTIFICATE")) {
    throw new OpsCrewError(
      "INVALID_INPUT",
      "The origin mTLS client certificate must be a PEM-encoded X.509 certificate.",
    );
  }
  if (!keyPem.includes("PRIVATE KEY")) {
    throw new OpsCrewError(
      "INVALID_INPUT",
      "The origin mTLS client private key must be a PEM-encoded private key.",
    );
  }
  if (originCaCertPem !== undefined && !originCaCertPem.includes("BEGIN CERTIFICATE")) {
    throw new OpsCrewError(
      "INVALID_INPUT",
      "The origin CA certificate must be a PEM-encoded X.509 certificate.",
    );
  }
}

/**
 * Inspects the active Fastly VCL service version's backend and plans configuring or updating its
 * mTLS client certificate (`pull.pem`), optional pinned origin CA (`ssl_ca_cert`), and optional
 * origin backend address without exposing the private key in the plan or hash.
 */
export async function planFastlyOriginMtls(
  client: Pick<FastlyClient, "getActiveVersion" | "getBackend">,
  input: {
    serviceId: string;
    backendName: string;
    clientCertPem: string;
    clientKeyPem: string;
    originCaCertPem?: string;
    originAddress?: string;
  },
): Promise<FastlyOriginMtlsPlan> {
  assertClientKeyPair(input.clientCertPem, input.clientKeyPem, input.originCaCertPem);
  const activeVersion = await client.getActiveVersion(input.serviceId);
  const backend = await client.getBackend(input.serviceId, activeVersion, input.backendName);
  const desiredCert = normalizePem(input.clientCertPem);
  const existingCert = backend.ssl_client_cert ? normalizePem(backend.ssl_client_cert) : undefined;
  const desiredCaCert =
    input.originCaCertPem === undefined ? undefined : normalizePem(input.originCaCertPem);
  const existingCaCert = backend.ssl_ca_cert ? normalizePem(backend.ssl_ca_cert) : undefined;
  const desiredAddress = input.originAddress?.trim() || undefined;
  const existingAddress = backend.address.trim();
  const certFingerprint = sha256Hex(desiredCert).slice(0, 12);
  const caCertFingerprint =
    desiredCaCert === undefined ? undefined : sha256Hex(desiredCaCert).slice(0, 12);
  const clientMatches = existingCert === desiredCert;
  const caMatches = desiredCaCert === undefined || existingCaCert === desiredCaCert;
  const addressMatches = desiredAddress === undefined || existingAddress === desiredAddress;
  const action: FastlyMtlsAction =
    clientMatches && caMatches && addressMatches
      ? "noop"
      : existingCert === undefined && existingCaCert === undefined
        ? "configure"
        : "update";
  const caSuffix = caCertFingerprint === undefined ? "" : ` and origin CA ${caCertFingerprint}`;
  const addressSuffix = addressMatches ? "" : " and update origin backend address";
  const summary =
    action === "noop"
      ? `Fastly service ${input.serviceId} (v${activeVersion}) backend "${input.backendName}" already uses client certificate ${certFingerprint}${caSuffix}.`
      : action === "configure"
        ? `Clone Fastly service ${input.serviceId} v${activeVersion}, configure mTLS client certificate ${certFingerprint}${caSuffix}${addressSuffix} on backend "${input.backendName}", and activate.`
        : `Clone Fastly service ${input.serviceId} v${activeVersion}, update mTLS client certificate to ${certFingerprint}${caSuffix}${addressSuffix} on backend "${input.backendName}", and activate.`;
  const hash = sha256Hex(
    canonicalJson({
      op: "fastly-origin-mtls",
      serviceId: input.serviceId,
      activeVersion,
      backendName: input.backendName,
      action,
      certFingerprint,
      ...(caCertFingerprint === undefined ? {} : { caCertFingerprint }),
      ...(desiredAddress === undefined ? {} : { originAddress: desiredAddress }),
    }),
  );
  return {
    action,
    serviceId: input.serviceId,
    activeVersion,
    backendName: input.backendName,
    certFingerprint,
    ...(caCertFingerprint === undefined ? {} : { caCertFingerprint }),
    ...(desiredAddress === undefined ? {} : { originAddress: desiredAddress }),
    summary,
    hash,
  };
}

/**
 * Applies a previously planned Fastly backend mTLS update after verifying `approvedHash` matches
 * `plan.hash` (constitution I): clones active version, updates backend, and activates it.
 */
export async function applyFastlyOriginMtls(
  client: Pick<FastlyClient, "cloneVersion" | "updateBackendMtls" | "activateVersion">,
  plan: FastlyOriginMtlsPlan,
  input: {
    clientCertPem: string;
    clientKeyPem: string;
    originCaCertPem?: string;
    originAddress?: string;
    approvedHash: string;
  },
): Promise<{ applied: boolean; activatedVersion?: number }> {
  assertClientKeyPair(input.clientCertPem, input.clientKeyPem, input.originCaCertPem);
  if (input.approvedHash.toLowerCase() !== plan.hash.toLowerCase()) {
    throw new OpsCrewError(
      "APPROVAL_REFUSED",
      `Approval hash mismatch for Fastly service ${plan.serviceId} backend mTLS update. Nothing was changed.`,
      { hint: "Re-run the command to generate a fresh plan and approve its hash." },
    );
  }
  const actualFingerprint = sha256Hex(normalizePem(input.clientCertPem)).slice(0, 12);
  if (actualFingerprint !== plan.certFingerprint) {
    throw new OpsCrewError(
      "APPROVAL_REFUSED",
      "The origin mTLS client certificate changed after the Fastly plan was hashed. Nothing was changed.",
      { hint: "Re-run the command so the approval hash matches the current certificate." },
    );
  }
  const actualCaFingerprint =
    input.originCaCertPem === undefined
      ? undefined
      : sha256Hex(normalizePem(input.originCaCertPem)).slice(0, 12);
  if (actualCaFingerprint !== plan.caCertFingerprint) {
    throw new OpsCrewError(
      "APPROVAL_REFUSED",
      "The origin CA certificate changed after the Fastly plan was hashed. Nothing was changed.",
      {
        hint: "Re-run the command so the approval hash matches the current origin CA certificate.",
      },
    );
  }
  const actualAddress = input.originAddress?.trim() || undefined;
  if (actualAddress !== plan.originAddress) {
    throw new OpsCrewError(
      "APPROVAL_REFUSED",
      "The origin backend address changed after the Fastly plan was hashed. Nothing was changed.",
      { hint: "Re-run the command so the approval hash matches the current origin address." },
    );
  }
  if (plan.action === "noop") return { applied: false };
  const nextVersion = await client.cloneVersion(plan.serviceId, plan.activeVersion);
  await client.updateBackendMtls({
    serviceId: plan.serviceId,
    version: nextVersion,
    backendName: plan.backendName,
    clientCertPem: normalizePem(input.clientCertPem),
    clientKeyPem: normalizePem(input.clientKeyPem),
    ...(input.originCaCertPem === undefined
      ? {}
      : { originCaCertPem: normalizePem(input.originCaCertPem) }),
    ...(actualAddress === undefined ? {} : { originAddress: actualAddress }),
  });
  await client.activateVersion(plan.serviceId, nextVersion);
  return { applied: true, activatedVersion: nextVersion };
}
