/**
 * Deterministic fail-closed Google Cloud (GCP) static policy checks on OpenTofu/Terraform plan JSON
 * (Feature 039, T3904, ADR 0040 D11).
 *
 * Every sensitive attribute in `after_unknown` fails closed:
 * 1. `gcp-wif-strict-condition`: `google_iam_workload_identity_pool_provider` requires GitHub OIDC
 *    issuer AND non-empty wildcard-free `attribute_condition` pinning `assertion.repository` and
 *    `assertion.environment` / `assertion.ref`.
 * 2. `gcp-no-sa-keys`: blocks `google_service_account_key`.
 * 3. `gcp-iam-least-privilege`: blocks `roles/owner`, `roles/editor`, `roles/iam.securityAdmin`,
 *    `roles/resourcemanager.projectIamAdmin` (fail-closed on unknown role).
 * 4. `gcp-cloudsql-private`: `google_sql_database_instance` requires `ipv4_enabled = false` unless
 *    explicitly excepted (fail-closed on unknown).
 * 5. `gcp-no-legacy-vpc-connector`: blocks legacy `google_vpc_access_connector`.
 * 6. `gcp-no-legacy-redis`: blocks legacy `google_redis_instance` in favor of `google_memorystore_instance`.
 * 7. `gcp-gcs-private-uniform`: `google_storage_bucket` requires `uniform_bucket_level_access = true`
 *    and `public_access_prevention = "enforced"` (fail-closed on unknown).
 * 8. `gcp-no-secret-in-state`: blocks `google_secret_manager_secret_version`.
 * 9. `gcp-firewall-no-open-sensitive-ports`: blocks `google_compute_firewall` exposing ports
 *    22/3306/5432/6379/27017 to `0.0.0.0/0` or `::/0`.
 */
import type { PlannedResourceJson, PolicyResult, Severity } from "@opscrew/contracts";
import { isRecord } from "@opscrew/core";
import type { DeployPlan } from "@opscrew/plan-schema";
import { plannedResources } from "./plan";

const DANGEROUS_GCP_ROLES = new Set([
  "roles/owner",
  "roles/editor",
  "roles/iam.securityadmin",
  "roles/resourcemanager.projectiamadmin",
]);
const OPEN_CIDRS = new Set(["0.0.0.0/0", "::/0"]);
const SENSITIVE_PORTS = new Set([22, 3306, 5432, 6379, 27017]);

function policy(
  policyId: string,
  title: string,
  severity: Severity,
  passed: boolean,
  message: string,
  resource?: string,
): PolicyResult {
  return { policyId, title, severity, passed, message, ...(resource ? { resource } : {}) };
}

function stringList(value: unknown): string[] {
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.filter((v): v is string => typeof v === "string");
  return [];
}

function portHitsSensitive(spec: string): number | undefined {
  const trimmed = spec.trim();
  if (trimmed === "*") return 5432;
  const range = /^(\d+)-(\d+)$/.exec(trimmed);
  if (range !== null) {
    const start = Number(range[1]);
    const end = Number(range[2]);
    for (const p of SENSITIVE_PORTS) {
      if (start <= p && p <= end) return p;
    }
    return undefined;
  }
  const num = Number(trimmed);
  return SENSITIVE_PORTS.has(num) ? num : undefined;
}

function checkWifAndIam(resources: readonly PlannedResourceJson[]): PolicyResult[] {
  const out: PolicyResult[] = [];
  for (const r of resources) {
    if (r.type === "google_iam_workload_identity_pool_provider") {
      const unknownCond = r.unknown?.attribute_condition === true;
      const cond =
        typeof r.values.attribute_condition === "string" ? r.values.attribute_condition : "";
      const oidcArr = Array.isArray(r.values.oidc) ? r.values.oidc : [];
      const oidc = isRecord(oidcArr[0])
        ? oidcArr[0]
        : isRecord(r.values.oidc)
          ? r.values.oidc
          : undefined;
      const issuer = typeof oidc?.issuer_uri === "string" ? oidc.issuer_uri : "";

      let violation: string | undefined;
      if (unknownCond) {
        violation = `${r.address} has unknown attribute_condition at plan time (fail-closed).`;
      } else if (issuer !== "https://token.actions.githubusercontent.com") {
        violation = `${r.address} OIDC issuer_uri must be "https://token.actions.githubusercontent.com" (got ${String(issuer)}).`;
      } else if (
        cond.trim().length === 0 ||
        !cond.includes("assertion.repository") ||
        (!cond.includes("assertion.environment") && !cond.includes("assertion.ref")) ||
        cond.includes("*")
      ) {
        violation = `${r.address} attribute_condition must strictly pin assertion.repository and assertion.environment/ref without wildcards (got ${JSON.stringify(cond)}).`;
      }
      out.push(
        policy(
          "gcp-wif-strict-condition",
          "GCP Workload Identity Provider enforces strict GitHub repository + environment CEL condition",
          "critical",
          violation === undefined,
          violation ?? `${r.address} pins GitHub issuer_uri and strict CEL attribute_condition.`,
          r.address,
        ),
      );
    }

    if (r.type === "google_service_account_key") {
      out.push(
        policy(
          "gcp-no-sa-keys",
          "No static GCP Service Account JSON keys created",
          "critical",
          false,
          `${r.address} creates a static Service Account JSON key; use keyless Workload Identity Federation instead.`,
          r.address,
        ),
      );
    }

    if (r.type === "google_project_iam_member" || r.type === "google_project_iam_binding") {
      const unknownRole = r.unknown?.role === true;
      const role = typeof r.values.role === "string" ? r.values.role.trim() : "";
      const dangerous = DANGEROUS_GCP_ROLES.has(role.toLowerCase());
      out.push(
        policy(
          "gcp-iam-least-privilege",
          "GCP project IAM follows least privilege",
          "critical",
          !unknownRole && !dangerous,
          unknownRole
            ? `${r.address} has unknown IAM role at plan time (fail-closed).`
            : dangerous
              ? `${r.address} grants overly broad role "${role}"; use a least-privilege service role.`
              : `${r.address} grants scoped role "${role}".`,
          r.address,
        ),
      );
    }
  }
  return out;
}

function checkDataAndNetwork(
  resources: readonly PlannedResourceJson[],
  deployPlan: DeployPlan,
): PolicyResult[] {
  const out: PolicyResult[] = [];
  const allowPublicDb =
    deployPlan.target.provider === "gcp" && deployPlan.target.guardrails.privateDatabase === false;
  const allowPublicStorage =
    deployPlan.target.provider === "gcp" && deployPlan.target.guardrails.privateStorage === false;
  const allowLegacyVpc =
    deployPlan.target.provider === "gcp" &&
    deployPlan.target.guardrails.noLegacyVpcConnector === false;
  const allowLegacyRedis =
    deployPlan.target.provider === "gcp" && deployPlan.target.guardrails.noLegacyRedis === false;

  for (const r of resources) {
    if (r.type === "google_sql_database_instance") {
      const settingsArr = Array.isArray(r.values.settings) ? r.values.settings : [];
      const settings = isRecord(settingsArr[0]) ? settingsArr[0] : undefined;
      const ipArr = Array.isArray(settings?.ip_configuration) ? settings.ip_configuration : [];
      const ipCfg = isRecord(ipArr[0]) ? ipArr[0] : undefined;
      const unknownSettings = r.unknown?.settings === true;
      const isPrivate = !unknownSettings && ipCfg?.ipv4_enabled === false;
      out.push(
        policy(
          "gcp-cloudsql-private",
          "Cloud SQL disables public IPv4 access",
          "critical",
          isPrivate || allowPublicDb,
          isPrivate
            ? `${r.address} sets ip_configuration.ipv4_enabled = false.`
            : allowPublicDb
              ? `${r.address} allows public IPv4 under a recorded guardrail exception.`
              : `${r.address} enables or leaves unknown Cloud SQL public IPv4 without a recorded guardrail exception.`,
          r.address,
        ),
      );
    }

    if (r.type === "google_vpc_access_connector") {
      out.push(
        policy(
          "gcp-no-legacy-vpc-connector",
          "Uses Cloud Run Direct VPC Egress instead of legacy Serverless VPC Access Connector",
          "high",
          allowLegacyVpc,
          allowLegacyVpc
            ? `${r.address} uses legacy Serverless VPC Connector under a recorded guardrail exception.`
            : `${r.address} provisions legacy 2x VM Serverless VPC Access Connector; use Direct VPC Egress instead.`,
          r.address,
        ),
      );
    }

    if (r.type === "google_redis_instance") {
      out.push(
        policy(
          "gcp-no-legacy-redis",
          "Uses Memorystore for Valkey instead of legacy Memorystore for Redis",
          "high",
          allowLegacyRedis,
          allowLegacyRedis
            ? `${r.address} uses legacy google_redis_instance under a recorded guardrail exception.`
            : `${r.address} uses legacy google_redis_instance; use google_memorystore_instance (Valkey) instead.`,
          r.address,
        ),
      );
    }

    if (r.type === "google_storage_bucket") {
      const unknownBucket =
        r.unknown?.uniform_bucket_level_access === true ||
        r.unknown?.public_access_prevention === true;
      const uniform = r.values.uniform_bucket_level_access === true;
      const pap = r.values.public_access_prevention === "enforced";
      const ok = !unknownBucket && uniform && (pap || allowPublicStorage);
      out.push(
        policy(
          "gcp-gcs-private-uniform",
          "GCS bucket enforces uniform bucket-level access and public access prevention",
          "high",
          ok,
          ok
            ? `${r.address} enables uniform_bucket_level_access and public_access_prevention = enforced.`
            : `${r.address} violates uniform/private GCS policy (uniform=${String(r.values.uniform_bucket_level_access)}, public_access_prevention=${String(r.values.public_access_prevention)}).`,
          r.address,
        ),
      );
    }

    if (r.type === "google_secret_manager_secret_version") {
      out.push(
        policy(
          "gcp-no-secret-in-state",
          "No plaintext Secret Manager values stored in Terraform state",
          "critical",
          false,
          `${r.address} writes a Secret Manager version via Terraform, persisting plaintext in .tfstate; populate secret values out-of-band via OpsCrew's GCP connector.`,
          r.address,
        ),
      );
    }

    if (r.type === "google_compute_firewall") {
      const direction = String(r.values.direction ?? "INGRESS").toUpperCase();
      if (direction !== "INGRESS") continue;
      const sources = stringList(r.values.source_ranges);
      if (!sources.some((s) => OPEN_CIDRS.has(s))) continue;
      const allows = Array.isArray(r.values.allow) ? r.values.allow : [];
      for (const rule of allows) {
        if (!isRecord(rule)) continue;
        const ports = stringList(rule.ports);
        const specs = ports.length === 0 ? ["*"] : ports;
        for (const spec of specs) {
          const hit = portHitsSensitive(spec);
          if (hit !== undefined) {
            out.push(
              policy(
                "gcp-firewall-no-open-sensitive-ports",
                "GCP VPC firewall does not expose database/cache/SSH ports to the internet",
                "critical",
                false,
                `${r.address} exposes port ${hit} (spec ${spec}) to ${sources.filter((s) => OPEN_CIDRS.has(s)).join(", ")}.`,
                r.address,
              ),
            );
            break;
          }
        }
      }
    }
  }
  return out;
}

export function evaluateGcpPlanPolicies(planJson: unknown, deployPlan: DeployPlan): PolicyResult[] {
  const resources = plannedResources(planJson);
  return [...checkWifAndIam(resources), ...checkDataAndNetwork(resources, deployPlan)];
}
