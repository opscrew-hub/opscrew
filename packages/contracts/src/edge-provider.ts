/**
 * The contract for a DNS and edge proxy provider (ADR 0038): everything OpsCrew knows about one
 * provider that proxies web traffic at the edge (and optionally hosts DNS), in one definition a
 * provider package exports. Only plain data, regular expressions, and functions cross it — never
 * a zod schema or a class instance (matching ADR 0029 D2). OpsCrew validates every definition it
 * loads (`@opscrew/edge-providers`) and everything it reads from one.
 */
import type { CredentialCheck } from "./connector";
import type { FetchLike } from "./io";
import type { ProviderRequirement } from "./provider";

/** The contract version this OpsCrew reads; a definition of another version is refused. */
export const EDGE_PROVIDER_CONTRACT_VERSION = 1;

/**
 * How the edge authenticates itself to the app's origin server (ADR 0038, D6):
 * - `cloudflare-aop`: Cloudflare Origin CA + per-hostname mTLS Authenticated Origin Pulls (`pull.pem`).
 * - `mtls-client-cert`: Per-app P-256 client certificate (`pull.pem`) presented by the edge backend (Fastly).
 * - `shared-header`: Per-app 32-byte hex secret header set via a connector call (never in Terraform
 *   state), verified by the server's reverse proxy before `kamal-proxy` and before trusting the
 *   visitor-IP header (Bunny.net, Gcore).
 */
export type EdgeOriginAuth = "cloudflare-aop" | "mtls-client-cert" | "shared-header";

/**
 * How the server's firewall handles the edge's published IP addresses (ADR 0038, D6):
 * - `compact-cidrs`: The provider publishes a compact CIDR list (~20 ranges) that fits cloud
 *   firewalls and the server's own web filter (Cloudflare, Fastly).
 * - `dynamic-ips`: The provider publishes a large or frequently changing list of edge IPs that
 *   exceeds cloud firewall CIDR limits; the firewall leaves ports 80/443 open and `originAuth`
 *   (`shared-header`) is the gate (Bunny.net, Gcore).
 */
export type EdgeOriginIpFiltering = "compact-cidrs" | "dynamic-ips";

/** Capabilities of an edge proxy provider. */
export interface EdgeProviderCapabilities {
  /** How the edge authenticates upstream requests to the origin server. */
  originAuth: EdgeOriginAuth;
  /**
   * HTTP header name carrying the shared origin-verification token when `originAuth` is
   * `"shared-header"` (for example `X-OpsCrew-Origin-Token`). Defined once here; omitted otherwise.
   */
  originAuthHeader?: string;
  /** Whether the edge's published IP list fits cloud firewalls (`compact-cidrs`) or not (`dynamic-ips`). */
  originIpFiltering: EdgeOriginIpFiltering;
  /**
   * HTTP request header carrying the real visitor's IP address on requests from this edge
   * (for example `CF-Connecting-IP`, `X-Real-IP`, `X-Forwarded-For`, `Fastly-Client-IP`).
   */
  realIpHeader: string;
}

/** How an edge/DNS provider's API credentials are supplied. */
export interface EdgeProviderCredentials {
  /** The environment variables, in order (for example `["BUNNYNET_API_KEY"]`). */
  envVars: readonly string[];
  /** Where the user creates API tokens or keys. */
  createUrl: string;
}

/** Vendored Terraform module shipped by an edge provider package. */
export interface EdgeProviderTerraformModule {
  /** Folder name placed under `opscrew/infra/modules/<name>`. */
  name: string;
  /** Relative file path -> file content (`main.tf`, `variables.tf`, `outputs.tf`, `versions.tf`). */
  files: Readonly<Record<string, string>>;
}

/** Variable declaration contributed by an edge provider to the root Terraform module. */
export interface EdgeVariableSpec {
  name: string;
  type: string;
  description: string;
  default?: string;
}

/** Inputs passed from the root Terraform renderer to an edge provider's root contribution. */
export interface EdgeRootInput {
  /** Module name in `main.tf` (defaults to `"edge"`; `"dns"` when paired under a separate edge). */
  moduleName?: "dns" | "edge";
  appName: string;
  environmentName?: string;
  domain: string;
  zone?: string;
  www: boolean;
  proxied: boolean;
  manageDns: boolean;
  wafCustomRules: boolean;
  ipv4Expr: string;
  ipv6Expr: string;
  hasDomainVar: boolean;
  /** Provider-specific DNS zone id looked up by the connector before rendering. */
  dnsZoneId?: number;
  /**
   * When `moduleName` is `"dns"` and a separate edge provider sits in front (`dns.edge`),
   * Terraform expressions referencing `module.edge` for DNS routing and ACME TLS validation
   * records so DNS points at the edge instead of the origin server's IP.
   */
  edgeDns?: {
    cnameTargetExpr: string;
    ipv4TargetsExpr?: string;
    ipv6TargetsExpr?: string;
    tlsValidationRecordsExpr?: string;
  };
  /**
   * True when a separate `module "dns"` creates ACME DNS validation records that this edge
   * provider's TLS subscription validation resource must wait for (`depends_on = [module.dns]`).
   */
  dependsOnDnsModule?: boolean;
}

/** Root Terraform module fragments contributed by an edge provider. */
export interface EdgeRootContribution {
  /** Module block lines for `main.tf`. */
  mainLines: string[];
  /** Root variable declarations for `variables.tf`. */
  variables: EdgeVariableSpec[];
  /** Output block lines for `outputs.tf`. */
  outputLines: string[];
  /** Non-secret entries for `terraform.tfvars.json`. */
  tfvars: Record<string, unknown>;
}

/** Root Terraform integration implemented by a non-Cloudflare edge/DNS provider. */
export interface EdgeProviderTerraformRoot {
  /** Terraform output name carrying the edge resource id for connector post-apply sync. */
  resourceIdOutput: string;
  /** Terraform output name carrying the backend name for `mtls-client-cert` post-apply sync. */
  backendNameOutput?: string;
  /**
   * Terraform module outputs exposed by an edge provider when paired with a separate DNS host
   * (`dns.provider !== dns.edge`), so `module "dns"` routes traffic to the edge and provisions
   * any ACME DNS validation records instead of pointing at the origin IP.
   */
  edgeDnsOutputs?: {
    cnameTarget: string;
    ipv4Targets?: string;
    ipv6Targets?: string;
    tlsValidationRecords?: string;
  };
  render(input: EdgeRootInput): EdgeRootContribution;
}

/** Terraform / OpenTofu facts for an edge/DNS provider. */
export interface EdgeProviderTerraform {
  provider: ProviderRequirement;
  /** Comment placed above the provider block (for example `Token from the CLOUDFLARE_API_TOKEN environment variable.`). */
  credentialsComment: string;
  /** Terraform resource type of a DNS record when the provider hosts DNS. */
  dnsRecordResourceType?: string;
  /** Vendored edge/DNS Terraform module shipped by this provider package. */
  module?: EdgeProviderTerraformModule;
  /** Root Terraform contribution (`main.tf`, `variables.tf`, `outputs.tf`, `tfvars`). */
  root?: EdgeProviderTerraformRoot;
}

/** Planned Terraform resource shape inspected by an edge provider's SecOps plan policy. */
export interface EdgePlanResource {
  type: string;
  address: string;
  values: Readonly<Record<string, unknown>>;
}

/** SecOps plan policy result emitted by an edge provider. */
export interface EdgePlanPolicyResult {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low";
  passed: boolean;
  detail: string;
  resource?: string;
}

/** Plan-hash-bound origin-header change planned by a `shared-header` edge provider connector. */
export interface EdgeOriginHeaderPlan {
  action: "create" | "update" | "noop";
  resourceId: string;
  headerName: string;
  existingId?: string;
  /** Short SHA-256 fingerprint of the desired token (never the plaintext secret). */
  tokenFingerprint: string;
  /** Plain-English summary shown before approval (contains no secret). */
  summary: string;
  /** SHA-256 hash binding approval to this exact resource, header, action, and token fingerprint. */
  hash: string;
}

/** Plan-hash-bound origin mTLS change planned by an `mtls-client-cert` edge provider connector. */
export interface EdgeOriginMtlsPlan {
  action: "configure" | "update" | "noop";
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

/** Redactor hook passed to edge provider connectors so secrets never leak into errors or logs. */
export interface EdgeRedactorLike {
  addLiteral(value: string, label: string): void;
  redact(text: string): string;
}

/** Typed API connector hooks for an edge/DNS provider (never called from Terraform). */
export interface EdgeProviderConnector {
  verifyCredentials(input: {
    apiKey: string;
    fetch?: FetchLike;
    redactor?: EdgeRedactorLike;
  }): Promise<CredentialCheck>;
  getIpRanges?(input: {
    fetch?: FetchLike;
    redactor?: EdgeRedactorLike;
  }): Promise<{ ipv4: string[]; ipv6: string[] }>;
  lookupDnsZone?(input: {
    apiKey: string;
    domain: string;
    fetch?: FetchLike;
    redactor?: EdgeRedactorLike;
  }): Promise<{ id: number; domain: string } | undefined>;
  planOriginHeader?(input: {
    apiKey: string;
    resourceId: string;
    headerName: string;
    token: string;
    fetch?: FetchLike;
    redactor?: EdgeRedactorLike;
  }): Promise<EdgeOriginHeaderPlan>;
  applyOriginHeader?(input: {
    apiKey: string;
    plan: EdgeOriginHeaderPlan;
    token: string;
    approvedHash: string;
    fetch?: FetchLike;
    redactor?: EdgeRedactorLike;
  }): Promise<{ applied: boolean }>;
  planOriginMtls?(input: {
    apiKey: string;
    serviceId: string;
    backendName: string;
    clientCertPem: string;
    clientKeyPem: string;
    /** Optional PEM CA certificate pinned as `ssl_ca_cert` so the edge trusts OpsCrew's origin cert. */
    originCaCertPem?: string;
    /** Optional origin server address reconciled alongside mTLS (because Terraform ignores backend drift). */
    originAddress?: string;
    fetch?: FetchLike;
    redactor?: EdgeRedactorLike;
  }): Promise<EdgeOriginMtlsPlan>;
  applyOriginMtls?(input: {
    apiKey: string;
    plan: EdgeOriginMtlsPlan;
    clientCertPem: string;
    clientKeyPem: string;
    /** Optional PEM CA certificate pinned as `ssl_ca_cert` so the edge trusts OpsCrew's origin cert. */
    originCaCertPem?: string;
    /** Optional origin server address reconciled alongside mTLS. */
    originAddress?: string;
    approvedHash: string;
    fetch?: FetchLike;
    redactor?: EdgeRedactorLike;
  }): Promise<{ applied: boolean; activatedVersion?: number }>;
}

/** Plain-English wording per OpsCrew surface. */
export interface EdgeProviderTexts {
  secops: {
    /** Label used in TLS/edge scan reports (for example `Cloudflare's edge`). */
    edgeLabel: string;
    /** Remediation hint for edge TLS findings. */
    edgeTlsHint: string;
  };
}

/** Everything OpsCrew reads about a single DNS and/or edge proxy provider (ADR 0038). */
export interface EdgeProviderDefinition {
  contractVersion: typeof EDGE_PROVIDER_CONTRACT_VERSION;
  id: string;
  displayName: string;
  capabilities: EdgeProviderCapabilities;
  credentials: EdgeProviderCredentials;
  terraform: EdgeProviderTerraform;
  secops?: {
    checkPlan(resources: readonly EdgePlanResource[]): EdgePlanPolicyResult[];
  };
  connector?: EdgeProviderConnector;
  texts: EdgeProviderTexts;
}
