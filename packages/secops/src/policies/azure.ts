/**
 * Deterministic Microsoft Azure static policy checks on OpenTofu/Terraform plan JSON
 * (Feature 038, T3804, ADR 0040 D11).
 *
 * Fail-closed checks run BEFORE any apply approval (every sensitive attribute in `after_unknown`
 * fails closed):
 * 1. GitHub OIDC Federated Identity Credential (`azurerm_federated_identity_credential`): exact
 *    `issuer`, `audience = ["api://AzureADTokenExchange"]`, and strict wildcard-free `subject`
 *    pinned to `repo:<owner>/<repo>:environment:<env>` or `ref:refs/heads/<branch>` (rejects
 *    `pull_request` and wildcards).
 * 2. Least-privilege RBAC (`azurerm_role_assignment`): blocks `Owner`, `User Access Administrator`,
 *    `Role Based Access Control Administrator` (by name OR built-in role GUID) and blocks
 *    subscription-wide `Contributor`; fails closed when role or scope is unknown.
 * 3. Blocks retiring Azure Cache for Redis (`azurerm_redis_cache`) in favor of `azurerm_managed_redis`.
 * 4. Private Flexible Server (`public_network_access_enabled = false`, fail-closed on unknown).
 * 5. Private TLS 1.2+/1.3 Storage (`allow_nested_items_to_be_public = false`,
 *    `public_network_access = "Disabled"`, `min_tls_version` in `TLS1_2`/`TLS1_3`,
 *    `https_traffic_only_enabled = true`, fail-closed on unknown).
 * 6. Zero plaintext secrets in `.tfstate`: blocks `azurerm_key_vault_secret`.
 * 7. Blocking `high` check for Log Analytics `retention_in_days` in `30..730`.
 * 8. NSG rules (`azurerm_network_security_group` / `azurerm_network_security_rule`) cannot expose
 *    SSH/DB/cache ports (22, 3306, 5432, 6379, 27017) to open sources (case-insensitive).
 */
import type { PlannedResourceJson, PolicyResult, Severity } from "@opscrew/contracts";
import { isRecord } from "@opscrew/core";
import type { DeployPlan } from "@opscrew/plan-schema";
import { plannedResources } from "./plan";

const DANGEROUS_ROLES = new Set([
  "owner",
  "user access administrator",
  "role based access control administrator",
]);

/** Built-in Azure RBAC role definition GUIDs for Owner, UAA, and RBAC Administrator. */
const DANGEROUS_ROLE_GUIDS = [
  "8e3af657-a8ff-443c-a75c-2fe8c4bcb635", // Owner
  "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9", // User Access Administrator
  "f58310d9-a9f6-439a-9e8d-f62e7b41a168", // Role Based Access Control Administrator
];

const CONTRIBUTOR_GUID = "b24988ac-6180-42a0-ab88-20f7382dd24c";
const OPEN_SOURCES_LOWER = new Set(["*", "internet", "any", "0.0.0.0/0", "::/0"]);
const SENSITIVE_PORTS = new Set([22, 3306, 5432, 6379, 27017]);
const STRICT_OIDC_SUB_RE =
  /^repo:[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+:(?:environment:[^\s*]+|ref:refs\/heads\/[^\s*]+)$/;

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

function portSpecHitsSensitive(spec: string): number | undefined {
  const trimmed = spec.trim();
  if (trimmed === "*") return 5432;
  const rangeMatch = /^(\d+)-(\d+)$/.exec(trimmed);
  if (rangeMatch !== null) {
    const start = Number(rangeMatch[1]);
    const end = Number(rangeMatch[2]);
    for (const p of SENSITIVE_PORTS) {
      if (start <= p && p <= end) return p;
    }
    return undefined;
  }
  const single = Number(trimmed);
  return SENSITIVE_PORTS.has(single) ? single : undefined;
}

function checkOidcCredentials(resources: readonly PlannedResourceJson[]): PolicyResult[] {
  const out: PolicyResult[] = [];
  for (const r of resources) {
    if (r.type !== "azurerm_federated_identity_credential") continue;
    const unknown =
      r.unknown?.subject === true || r.unknown?.issuer === true || r.unknown?.audience === true;
    const issuer = r.values.issuer;
    const subject = r.values.subject;
    const audience = stringList(r.values.audience);

    let violation: string | undefined;
    if (unknown) {
      violation =
        "Federated identity credential has unknown issuer/subject/audience at plan time (fail-closed).";
    } else if (issuer !== "https://token.actions.githubusercontent.com") {
      violation = `Federated identity issuer must be "https://token.actions.githubusercontent.com" (got ${String(issuer)}).`;
    } else if (!audience.includes("api://AzureADTokenExchange") || audience.length !== 1) {
      violation = `Federated identity audience must be exactly ["api://AzureADTokenExchange"] (got ${JSON.stringify(audience)}).`;
    } else if (typeof subject !== "string" || !STRICT_OIDC_SUB_RE.test(subject)) {
      violation = `Federated identity subject must pin one GitHub repo and environment/branch without wildcards or pull_request claims (got ${String(subject)}).`;
    }

    out.push(
      policy(
        "azure-oidc-strict-sub",
        "Azure GitHub OIDC federated credential pins issuer, audience, and exact subject",
        "critical",
        violation === undefined,
        violation ??
          `${r.address} pins issuer, api://AzureADTokenExchange, and exact wildcard-free subject.`,
        r.address,
      ),
    );
  }
  return out;
}

function checkRbac(resources: readonly PlannedResourceJson[]): PolicyResult[] {
  const out: PolicyResult[] = [];
  for (const r of resources) {
    if (r.type !== "azurerm_role_assignment") continue;
    const unknownRole =
      r.unknown?.role_definition_name === true || r.unknown?.role_definition_id === true;
    const unknownScope = r.unknown?.scope === true;
    const roleName =
      typeof r.values.role_definition_name === "string" ? r.values.role_definition_name.trim() : "";
    const roleId =
      typeof r.values.role_definition_id === "string"
        ? r.values.role_definition_id.toLowerCase()
        : "";
    const scope = typeof r.values.scope === "string" ? r.values.scope : "";
    const isSubscriptionScope = /^\/subscriptions\/[^/]+\/?$/i.test(scope);
    const matchesDangerousGuid = DANGEROUS_ROLE_GUIDS.some((g) => roleId.includes(g));
    const isContributor =
      roleName.toLowerCase() === "contributor" || roleId.includes(CONTRIBUTOR_GUID);

    let violation: string | undefined;
    if (unknownRole) {
      violation = `${r.address} has an unknown role_definition_name or role_definition_id at plan time (fail-closed).`;
    } else if (DANGEROUS_ROLES.has(roleName.toLowerCase()) || matchesDangerousGuid) {
      violation = `${r.address} assigns overly broad role "${roleName || roleId}"; use a least-privilege resource-group role.`;
    } else if (isContributor && (isSubscriptionScope || unknownScope)) {
      violation = `${r.address} assigns Contributor at subscription or unknown scope; scope role assignments to the app's resource group.`;
    }

    out.push(
      policy(
        "azure-rbac-least-privilege",
        "Azure RBAC assignment follows least privilege",
        "critical",
        violation === undefined,
        violation ?? `${r.address} assigns scoped role "${roleName || roleId || "custom"}".`,
        r.address,
      ),
    );
  }
  return out;
}

function checkDatabasesAndCache(
  resources: readonly PlannedResourceJson[],
  deployPlan: DeployPlan,
): PolicyResult[] {
  const out: PolicyResult[] = [];
  const allowPublicDb =
    deployPlan.target.provider === "azure" &&
    deployPlan.target.guardrails.privateDatabase === false;
  const allowRetiringRedis =
    deployPlan.target.provider === "azure" &&
    deployPlan.target.guardrails.noRetiringRedis === false;

  for (const r of resources) {
    if (
      r.type === "azurerm_postgresql_flexible_server" ||
      r.type === "azurerm_mysql_flexible_server"
    ) {
      const isUnknown = r.unknown?.public_network_access_enabled === true;
      const isPrivate = !isUnknown && r.values.public_network_access_enabled === false;
      out.push(
        policy(
          "azure-db-private",
          "Azure Flexible Server disables public network access",
          "critical",
          isPrivate || allowPublicDb,
          isPrivate
            ? `${r.address} sets public_network_access_enabled = false.`
            : allowPublicDb
              ? `${r.address} allows public access under a recorded guardrail exception.`
              : isUnknown
                ? `${r.address} has unknown public_network_access_enabled at plan time (fail-closed).`
                : `${r.address} sets public_network_access_enabled = ${String(r.values.public_network_access_enabled)} without a recorded guardrail exception.`,
          r.address,
        ),
      );
    }

    if (r.type === "azurerm_redis_cache") {
      out.push(
        policy(
          "azure-no-retiring-redis",
          "Uses Azure Managed Redis instead of retiring Azure Cache for Redis",
          "high",
          allowRetiringRedis,
          allowRetiringRedis
            ? `${r.address} uses retiring azurerm_redis_cache under a recorded guardrail exception.`
            : `${r.address} uses retiring azurerm_redis_cache; migrate to azurerm_managed_redis.`,
          r.address,
        ),
      );
    }
  }
  return out;
}

function checkStorageSecretsAndLogs(
  resources: readonly PlannedResourceJson[],
  deployPlan: DeployPlan,
): PolicyResult[] {
  const out: PolicyResult[] = [];
  const allowPublicStorage =
    deployPlan.target.provider === "azure" && deployPlan.target.guardrails.privateStorage === false;

  for (const r of resources) {
    if (r.type === "azurerm_storage_account") {
      const unknownPrivacy =
        r.unknown?.allow_nested_items_to_be_public === true ||
        r.unknown?.public_network_access === true ||
        r.unknown?.min_tls_version === true;
      const publicItems = r.values.allow_nested_items_to_be_public !== false;
      const publicNet =
        r.values.public_network_access === "Enabled" ||
        r.values.public_network_access_enabled === true;
      const minTls = r.values.min_tls_version;
      const tlsOk = minTls === "TLS1_2" || minTls === "TLS1_3";
      const httpsOnly = r.values.https_traffic_only_enabled !== false;
      const ok =
        !unknownPrivacy &&
        (!publicItems || allowPublicStorage) &&
        (!publicNet || allowPublicStorage) &&
        tlsOk &&
        httpsOnly;
      out.push(
        policy(
          "azure-storage-private-tls",
          "Azure Storage Account disables public blob access and enforces TLS 1.2+",
          "high",
          ok,
          ok
            ? `${r.address} enforces TLS 1.2+, HTTPS-only, and private blob access.`
            : unknownPrivacy
              ? `${r.address} has unknown privacy or TLS settings at plan time (fail-closed).`
              : `${r.address} violates private/TLS 1.2+ storage policy (allow_nested_items_to_be_public=${String(r.values.allow_nested_items_to_be_public)}, public_network_access=${String(r.values.public_network_access ?? r.values.public_network_access_enabled)}, min_tls_version=${String(minTls)}, https_traffic_only_enabled=${String(httpsOnly)}).`,
          r.address,
        ),
      );
    }

    if (r.type === "azurerm_key_vault_secret") {
      out.push(
        policy(
          "azure-no-secret-in-state",
          "No plaintext Key Vault secret values stored in Terraform state",
          "critical",
          false,
          `${r.address} writes a Key Vault secret via Terraform, persisting plaintext in .tfstate; populate secrets out-of-band via OpsCrew's Azure connector.`,
          r.address,
        ),
      );
    }

    if (r.type === "azurerm_log_analytics_workspace") {
      const days = typeof r.values.retention_in_days === "number" ? r.values.retention_in_days : 0;
      out.push(
        policy(
          "azure-log-retention",
          "Azure Log Analytics Workspace sets explicit retention_in_days (30-730)",
          "high",
          days >= 30 && days <= 730,
          days >= 30 && days <= 730
            ? `${r.address} sets retention_in_days = ${days}.`
            : `${r.address} must set retention_in_days between 30 and 730 (got ${String(r.values.retention_in_days)}).`,
          r.address,
        ),
      );
    }
  }
  return out;
}

function checkNetworkSecurityGroups(resources: readonly PlannedResourceJson[]): PolicyResult[] {
  const out: PolicyResult[] = [];
  const inspectRule = (address: string, rule: Record<string, unknown>) => {
    if (String(rule.direction ?? "").toLowerCase() !== "inbound") return;
    if (String(rule.access ?? "").toLowerCase() !== "allow") return;
    const sources = [
      ...stringList(rule.source_address_prefix),
      ...stringList(rule.source_address_prefixes),
    ];
    const openMatches = sources.filter((s) => OPEN_SOURCES_LOWER.has(s.trim().toLowerCase()));
    if (openMatches.length === 0) return;
    const ports = [
      ...stringList(rule.destination_port_range),
      ...stringList(rule.destination_port_ranges),
    ];
    for (const spec of ports) {
      const exposed = portSpecHitsSensitive(spec);
      if (exposed !== undefined) {
        out.push(
          policy(
            "azure-nsg-no-open-sensitive-ports",
            "Azure NSG does not expose database/cache/SSH ports to the internet",
            "critical",
            false,
            `${address} rule "${String(rule.name ?? "unnamed")}" exposes port ${exposed} (range ${spec}) to ${openMatches.join(", ")}.`,
            address,
          ),
        );
        return;
      }
    }
  };

  for (const r of resources) {
    if (r.type === "azurerm_network_security_group" && Array.isArray(r.values.security_rule)) {
      for (const rule of r.values.security_rule) {
        if (isRecord(rule)) inspectRule(r.address, rule);
      }
    }
    if (r.type === "azurerm_network_security_rule") {
      inspectRule(r.address, r.values);
    }
  }
  return out;
}

/** Evaluates all deterministic Azure SecOps policies against Terraform/OpenTofu plan JSON. */
export function evaluateAzurePlanPolicies(
  planJson: unknown,
  deployPlan: DeployPlan,
): PolicyResult[] {
  const resources = plannedResources(planJson);
  return [
    ...checkOidcCredentials(resources),
    ...checkRbac(resources),
    ...checkDatabasesAndCache(resources, deployPlan),
    ...checkStorageSecretsAndLogs(resources, deployPlan),
    ...checkNetworkSecurityGroups(resources),
  ];
}
