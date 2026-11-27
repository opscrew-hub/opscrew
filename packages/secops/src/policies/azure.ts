/**
 * Deterministic Microsoft Azure static policy checks on OpenTofu/Terraform plan JSON
 * (Feature 038, T3804, ADR 0040 D11).
 *
 * Fail-closed checks run BEFORE any apply approval:
 * 1. GitHub OIDC Federated Identity Credential (`azurerm_federated_identity_credential`): exact
 *    `issuer`, `audience = ["api://AzureADTokenExchange"]`, and wildcard-free `repo:` `subject`
 *    (fails closed if `subject` or `issuer` is unknown in `after_unknown`).
 * 2. Least-privilege RBAC (`azurerm_role_assignment`): blocks `Owner` / `User Access Administrator`
 *    and blocks subscription-wide `Contributor` (fails closed when role/scope is unknown).
 * 3. Blocks retiring Azure Cache for Redis (`azurerm_redis_cache`) in favor of `azurerm_managed_redis`.
 * 4. Private Flexible Server (`public_network_access_enabled = false`) unless explicitly excepted.
 * 5. Private TLS 1.2+ Storage (`allow_nested_items_to_be_public = false`, `min_tls_version = "TLS1_2"`,
 *    `https_traffic_only_enabled = true`) unless explicitly excepted.
 * 6. Zero plaintext secrets in `.tfstate`: blocks `azurerm_key_vault_secret`.
 * 7. Blocking `high` check for Log Analytics `retention_in_days` >= 30.
 * 8. NSG rules (`azurerm_network_security_group` / `azurerm_network_security_rule`) cannot expose
 *    SSH/DB/cache ports (22, 3306, 5432, 6379, 27017) to `Internet`, `*`, `0.0.0.0/0`, or `::/0`.
 */
import type { PlannedResourceJson, PolicyResult, Severity } from "@opscrew/contracts";
import { isRecord } from "@opscrew/core";
import type { DeployPlan } from "@opscrew/plan-schema";
import { plannedResources } from "./plan";

const DANGEROUS_ROLES = new Set(["Owner", "User Access Administrator"]);
const OPEN_SOURCES = new Set(["*", "Internet", "Any", "0.0.0.0/0", "::/0"]);
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
    } else if (
      typeof subject !== "string" ||
      !subject.startsWith("repo:") ||
      subject.includes("*")
    ) {
      violation = `Federated identity subject must pin one GitHub repo/environment without wildcards (got ${String(subject)}).`;
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
    const unknownRole = r.unknown?.role_definition_name === true;
    const role =
      typeof r.values.role_definition_name === "string" ? r.values.role_definition_name : "";
    const scope = typeof r.values.scope === "string" ? r.values.scope : "";
    const isSubscriptionScope = /^\/subscriptions\/[^/]+\/?$/.test(scope);

    let violation: string | undefined;
    if (unknownRole) {
      violation = `${r.address} has an unknown role_definition_name at plan time (fail-closed).`;
    } else if (DANGEROUS_ROLES.has(role)) {
      violation = `${r.address} assigns overly broad role "${role}"; use a least-privilege resource-group role.`;
    } else if (role === "Contributor" && isSubscriptionScope) {
      violation = `${r.address} assigns subscription-wide Contributor; scope role assignments to the app's resource group.`;
    }

    out.push(
      policy(
        "azure-rbac-least-privilege",
        "Azure RBAC assignment follows least privilege",
        "critical",
        violation === undefined,
        violation ?? `${r.address} assigns scoped role "${role || "custom"}".`,
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
      const isPublic = r.values.public_network_access_enabled === true;
      out.push(
        policy(
          "azure-db-private",
          "Azure Flexible Server disables public network access",
          "critical",
          !isPublic || allowPublicDb,
          !isPublic
            ? `${r.address} sets public_network_access_enabled = false.`
            : allowPublicDb
              ? `${r.address} allows public access under a recorded guardrail exception.`
              : `${r.address} sets public_network_access_enabled = true without a recorded guardrail exception.`,
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
      const publicItems = r.values.allow_nested_items_to_be_public === true;
      const publicNet =
        r.values.public_network_access === "Enabled" ||
        r.values.public_network_access_enabled === true;
      const minTls = r.values.min_tls_version;
      const httpsOnly = r.values.https_traffic_only_enabled !== false;
      const ok =
        (!publicItems || allowPublicStorage) &&
        (!publicNet || allowPublicStorage) &&
        minTls === "TLS1_2" &&
        httpsOnly;
      out.push(
        policy(
          "azure-storage-private-tls",
          "Azure Storage Account disables public blob access and enforces TLS 1.2+",
          "high",
          ok,
          ok
            ? `${r.address} enforces TLS 1.2+, HTTPS-only, and private blob access.`
            : `${r.address} violates private/TLS 1.2+ storage policy (allow_nested_items_to_be_public=${String(publicItems)}, public_network_access=${String(r.values.public_network_access ?? r.values.public_network_access_enabled)}, min_tls_version=${String(minTls)}, https_traffic_only_enabled=${String(httpsOnly)}).`,
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
    if (!sources.some((s) => OPEN_SOURCES.has(s))) return;
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
            `${address} rule "${String(rule.name ?? "unnamed")}" exposes port ${exposed} (range ${spec}) to ${sources.filter((s) => OPEN_SOURCES.has(s)).join(", ")}.`,
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
