import type { DeployPlan } from "@opscrew/plan-schema";
import { describe, expect, it } from "vitest";
import { evaluatePlanPolicies } from "./plan";

function azurePlan(guardrails: Record<string, boolean> = {}): DeployPlan {
  return {
    schemaVersion: 1,
    createdAt: "2026-11-27T00:00:00.000Z",
    updatedAt: "2026-11-27T00:00:00.000Z",
    app: { name: "acme", port: 3000, healthPath: "/health", env: [] },
    target: {
      provider: "azure",
      mode: "azure-managed",
      region: "westeurope",
      preset: "lean",
      compute: "container-apps",
      components: {
        compute: {
          service: "container-apps",
          why: "consumption",
          alternatives: [],
          monthlyCostUsd: 8,
          config: {},
        },
      },
      pins: {},
      guardrails: {
        privateDatabase: true,
        encryptionAtRest: true,
        automatedBackups: true,
        privateStorage: true,
        leastPrivilegeRbac: true,
        logRetention: true,
        noFrontDoorOnLean: true,
        noRetiringRedis: true,
        ...guardrails,
      },
      exceptions: [],
      observability: {
        logsRetentionDays: 30,
        applicationInsights: false,
        alerts: true,
        managedGrafana: false,
      },
    },
    processes: { workers: [], cron: [] },
    services: [],
    externalServices: [],
    cost: {
      monthly: { amount: 25, currency: "USD" },
      breakdown: [],
      pricesIncludeVat: false,
      source: "static",
      asOf: "2026-11-27T00:00:00.000Z",
    },
    codeChanges: [],
    infra: { engine: "tofu", dir: "opscrew/infra" },
    dns: { provider: "none", proxied: false, www: false },
    cicd: {
      provider: "github-actions",
      workflowPath: ".github/workflows/opscrew-deploy.yml",
      registry: "ghcr",
      branch: "main",
      deployTags: { enabled: false, release: false },
    },
    supplyChain: { sign: false },
  } as unknown as DeployPlan;
}

function makePlanJson(
  resources: Array<{
    address: string;
    type: string;
    values: Record<string, unknown>;
    afterUnknown?: Record<string, unknown>;
  }>,
) {
  return {
    planned_values: {
      root_module: {
        resources: resources.map((r) => ({
          address: r.address,
          type: r.type,
          name: r.address.split(".").pop() ?? "app",
          mode: "managed",
          values: r.values,
        })),
      },
    },
    resource_changes: resources
      .filter((r) => r.afterUnknown !== undefined)
      .map((r) => ({
        address: r.address,
        type: r.type,
        change: { actions: ["create"], after_unknown: r.afterUnknown },
      })),
  };
}

describe("038 Azure SecOps plan policies (T3804)", () => {
  it("passes a clean least-privilege Azure plan", () => {
    const planJson = makePlanJson([
      {
        address: "azurerm_federated_identity_credential.github",
        type: "azurerm_federated_identity_credential",
        values: {
          issuer: "https://token.actions.githubusercontent.com",
          audience: ["api://AzureADTokenExchange"],
          subject: "repo:acme/web:environment:prod",
        },
      },
      {
        address: "azurerm_role_assignment.deploy_rg",
        type: "azurerm_role_assignment",
        values: {
          scope: "/subscriptions/sub-1/resourceGroups/rg-opscrew-acme-prod",
          role_definition_name: "Container Apps Contributor",
        },
      },
      {
        address: "azurerm_postgresql_flexible_server.app",
        type: "azurerm_postgresql_flexible_server",
        values: { public_network_access_enabled: false },
      },
      {
        address: "azurerm_storage_account.app",
        type: "azurerm_storage_account",
        values: {
          allow_nested_items_to_be_public: false,
          min_tls_version: "TLS1_2",
          https_traffic_only_enabled: true,
        },
      },
      {
        address: "azurerm_log_analytics_workspace.app",
        type: "azurerm_log_analytics_workspace",
        values: { retention_in_days: 30 },
      },
      {
        address: "azurerm_network_security_group.app",
        type: "azurerm_network_security_group",
        values: {
          security_rule: [
            {
              name: "AllowHttps",
              direction: "Inbound",
              access: "Allow",
              source_address_prefix: "Internet",
              destination_port_range: "443",
            },
          ],
        },
      },
    ]);

    const results = evaluatePlanPolicies(planJson, azurePlan());
    expect(results.length).toBeGreaterThanOrEqual(5);
    expect(results.every((r) => r.passed)).toBe(true);
  });

  it("blocks wildcard/unknown OIDC, Owner/sub-Contributor RBAC, retiring Redis, public DB, Key Vault secret in state, missing log retention, and open NSG DB ports", () => {
    const planJson = makePlanJson([
      {
        address: "azurerm_federated_identity_credential.bad_sub",
        type: "azurerm_federated_identity_credential",
        values: {
          issuer: "https://token.actions.githubusercontent.com",
          audience: ["api://AzureADTokenExchange"],
          subject: "repo:acme/*:environment:prod",
        },
      },
      {
        address: "azurerm_federated_identity_credential.unknown_sub",
        type: "azurerm_federated_identity_credential",
        values: {
          issuer: "https://token.actions.githubusercontent.com",
          audience: ["api://AzureADTokenExchange"],
        },
        afterUnknown: { subject: true },
      },
      {
        address: "azurerm_role_assignment.too_broad",
        type: "azurerm_role_assignment",
        values: {
          scope: "/subscriptions/sub-1",
          role_definition_name: "Contributor",
        },
      },
      {
        address: "azurerm_redis_cache.legacy",
        type: "azurerm_redis_cache",
        values: { name: "old-redis" },
      },
      {
        address: "azurerm_postgresql_flexible_server.pub",
        type: "azurerm_postgresql_flexible_server",
        values: { public_network_access_enabled: true },
      },
      {
        address: "azurerm_key_vault_secret.leak",
        type: "azurerm_key_vault_secret",
        values: { name: "DB_PASS", value: "plaintext" },
      },
      {
        address: "azurerm_log_analytics_workspace.no_ret",
        type: "azurerm_log_analytics_workspace",
        values: {},
      },
      {
        address: "azurerm_federated_identity_credential.pr_sub",
        type: "azurerm_federated_identity_credential",
        values: {
          issuer: "https://token.actions.githubusercontent.com",
          audience: ["api://AzureADTokenExchange"],
          subject: "repo:acme/web:pull_request",
        },
      },
      {
        address: "azurerm_role_assignment.owner_guid",
        type: "azurerm_role_assignment",
        values: {
          scope: "/subscriptions/sub-1/resourceGroups/rg-app",
          role_definition_id:
            "/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
        },
      },
      {
        address: "azurerm_postgresql_flexible_server.unknown_pub",
        type: "azurerm_postgresql_flexible_server",
        values: {},
        afterUnknown: { public_network_access_enabled: true },
      },
      {
        address: "azurerm_network_security_group.open_db",
        type: "azurerm_network_security_group",
        values: {
          security_rule: [
            {
              name: "BadPg",
              direction: "Inbound",
              access: "Allow",
              source_address_prefix: "Internet",
              destination_port_range: "5432",
            },
          ],
        },
      },
    ]);

    const results = evaluatePlanPolicies(planJson, azurePlan());
    const failedIds = results.filter((r) => !r.passed).map((r) => r.policyId);
    expect(failedIds).toContain("azure-oidc-strict-sub");
    expect(failedIds).toContain("azure-rbac-least-privilege");
    expect(failedIds).toContain("azure-no-retiring-redis");
    expect(failedIds).toContain("azure-db-private");
    expect(failedIds).toContain("azure-no-secret-in-state");
    expect(failedIds).toContain("azure-log-retention");
    expect(failedIds).toContain("azure-nsg-no-open-sensitive-ports");
    expect(results.filter((r) => !r.passed && r.policyId === "azure-oidc-strict-sub")).toHaveLength(
      3,
    );
    expect(
      results.filter((r) => !r.passed && r.policyId === "azure-rbac-least-privilege"),
    ).toHaveLength(2);
    expect(results.filter((r) => !r.passed && r.policyId === "azure-db-private")).toHaveLength(2);
  });
});
