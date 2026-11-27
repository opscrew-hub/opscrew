import { edgeProvider } from "@opscrew/edge-providers";
import { activeEdgeProvider, type DeployPlan } from "@opscrew/plan-schema";

/** True when the plan's DNS is a domain on Cloudflare. */
export function usesCloudflare(plan: DeployPlan): boolean {
  return plan.dns.provider === "cloudflare" && plan.dns.domain !== undefined;
}

/**
 * The non-Cloudflare edge/DNS provider id used by `plan`'s Terraform root (`dns.edge` if set,
 * otherwise `dns.provider` when it is not `"cloudflare"` or `"none"` and a domain is set).
 */
export function thirdPartyEdgeId(plan: DeployPlan): string | undefined {
  if (plan.dns.domain === undefined) return undefined;
  if (plan.dns.edge !== undefined) return plan.dns.edge;
  if (plan.dns.provider !== "cloudflare" && plan.dns.provider !== "none") return plan.dns.provider;
  return undefined;
}

/**
 * True when web traffic may reach the server only through Cloudflare: a proxied Cloudflare domain
 * (with no separate `dns.edge`), or a preview environment's proxied wildcard, with
 * `security.httpAllowedFrom: edge`.
 */
export function webOnlyFromCloudflare(plan: DeployPlan): boolean {
  return activeEdgeProvider(plan) === "cloudflare" && plan.security.httpAllowedFrom === "edge";
}

/**
 * True when the active edge provider publishes compact CIDRs that fit cloud firewalls
 * (`originIpFiltering: "compact-cidrs"` with `security.httpAllowedFrom: edge`). False for
 * `dynamic-ips` providers such as Bunny.net, where the firewall leaves ports 80/443 open and the
 * shared header is the gate.
 */
export function usesCompactEdgeCidrs(plan: DeployPlan): boolean {
  const edgeId = activeEdgeProvider(plan);
  if (edgeId === undefined || plan.security.httpAllowedFrom !== "edge") return false;
  return edgeProvider(edgeId).capabilities.originIpFiltering === "compact-cidrs";
}

/**
 * True when the active edge provider uses compact CIDRs and proxies traffic to the server
 * (regardless of `security.httpAllowedFrom`, so proxied Cloudflare apps with `httpAllowedFrom: any`
 * still trust Cloudflare's real-IP header).
 */
export function trustsCompactEdgeRealIp(plan: DeployPlan): boolean {
  const edgeId = activeEdgeProvider(plan);
  if (edgeId === undefined) return false;
  return edgeProvider(edgeId).capabilities.originIpFiltering === "compact-cidrs";
}

/**
 * True when the active edge provider authenticates origin requests with a shared secret header
 * (`originAuth: "shared-header"`), verified by the server's reverse proxy before `kamal-proxy`.
 */
export function usesSharedOriginHeader(plan: DeployPlan): boolean {
  const edgeId = activeEdgeProvider(plan);
  if (edgeId === undefined || plan.security.httpAllowedFrom !== "edge") return false;
  return edgeProvider(edgeId).capabilities.originAuth === "shared-header";
}

/**
 * True when the active edge provider authenticates origin requests with a per-app mTLS client
 * certificate (`originAuth: "mtls-client-cert"`, for example Fastly), reusing `pull.pem` and
 * `OPSCREW_ORIGIN_TLS` on the server proxy.
 */
export function usesOriginMtls(plan: DeployPlan): boolean {
  const edgeId = activeEdgeProvider(plan);
  if (edgeId === undefined || plan.security.httpAllowedFrom !== "edge") return false;
  return edgeProvider(edgeId).capabilities.originAuth === "mtls-client-cert";
}
