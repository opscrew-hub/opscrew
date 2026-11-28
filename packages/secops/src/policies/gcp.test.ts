import type { DeployPlan } from "@opscrew/plan-schema";
import { describe, expect, it } from "vitest";
import { evaluatePlanPolicies } from "./plan";

function gcpPlan(): DeployPlan {
  return {
    schemaVersion: 1,
    createdAt: "2026-11-27T00:00:00.000Z",
    updatedAt: "2026-11-27T00:00:00.000Z",
    app: { name: "acme", port: 3000, healthPath: "/health", env: [] },
    target: {
      provider: "gcp",
      mode: "gcp-managed",
      region: "us-central1",
      preset: "lean",
      compute: "cloud-run",
      components: {
        compute: {
          service: "cloud-run",
          why: "scale-to-zero",
          alternatives: [],
          monthlyCostUsd: 5,
          config: {},
        },
      },
      pins: {},
      guardrails: {
        privateDatabase: true,
        encryptionAtRest: true,
        automatedBackups: true,
        privateStorage: true,
        leastPrivilegeIam: true,
        noStaticSaKeys: true,
        noLegacyVpcConnector: true,
        noLegacyRedis: true,
        noGlobalAlbOnLean: true,
      },
      exceptions: [],
      observability: { logsRetentionDays: 30, cloudTrace: false, alerts: true },
    },
    processes: { workers: [], cron: [] },
    services: [],
    externalServices: [],
    cost: {
      monthly: { amount: 18, currency: "USD" },
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

describe("039 GCP SecOps plan policies (T3904)", () => {
  it("passes a clean least-privilege GCP plan", () => {
    const planJson = makePlanJson([
      {
        address: "google_iam_workload_identity_pool_provider.github",
        type: "google_iam_workload_identity_pool_provider",
        values: {
          oidc: [{ issuer_uri: "https://token.actions.githubusercontent.com" }],
          attribute_condition:
            "assertion.repository == 'acme/web' && assertion.environment == 'prod'",
        },
      },
      {
        address: "google_project_iam_member.deploy_role",
        type: "google_project_iam_member",
        values: { role: "roles/run.developer" },
      },
      {
        address: "google_sql_database_instance.app",
        type: "google_sql_database_instance",
        values: { settings: [{ ip_configuration: [{ ipv4_enabled: false }] }] },
      },
      {
        address: "google_storage_bucket.app",
        type: "google_storage_bucket",
        values: { uniform_bucket_level_access: true, public_access_prevention: "enforced" },
      },
      {
        address: "google_compute_firewall.allow_https",
        type: "google_compute_firewall",
        values: {
          direction: "INGRESS",
          source_ranges: ["0.0.0.0/0"],
          allow: [{ protocol: "tcp", ports: ["443"] }],
        },
      },
    ]);

    const results = evaluatePlanPolicies(planJson, gcpPlan());
    expect(results.length).toBeGreaterThanOrEqual(4);
    expect(results.every((r) => r.passed)).toBe(true);
  });

  it("blocks missing/unknown WIF condition, static SA keys, Owner role, public Cloud SQL, legacy VPC connector/Redis, public GCS, secret version in state, and open DB firewall", () => {
    const planJson = makePlanJson([
      {
        address: "google_iam_workload_identity_pool_provider.open",
        type: "google_iam_workload_identity_pool_provider",
        values: {
          oidc: [{ issuer_uri: "https://token.actions.githubusercontent.com" }],
          attribute_condition: "",
        },
      },
      {
        address: "google_iam_workload_identity_pool_provider.unknown",
        type: "google_iam_workload_identity_pool_provider",
        values: { oidc: [{ issuer_uri: "https://token.actions.githubusercontent.com" }] },
        afterUnknown: { attribute_condition: true },
      },
      {
        address: "google_service_account_key.leak",
        type: "google_service_account_key",
        values: {},
      },
      {
        address: "google_project_iam_member.owner",
        type: "google_project_iam_member",
        values: { role: "roles/owner" },
      },
      {
        address: "google_sql_database_instance.pub",
        type: "google_sql_database_instance",
        values: { settings: [{ ip_configuration: [{ ipv4_enabled: true }] }] },
      },
      {
        address: "google_vpc_access_connector.legacy",
        type: "google_vpc_access_connector",
        values: {},
      },
      {
        address: "google_redis_instance.legacy",
        type: "google_redis_instance",
        values: {},
      },
      {
        address: "google_storage_bucket.pub",
        type: "google_storage_bucket",
        values: { uniform_bucket_level_access: false, public_access_prevention: "inherited" },
      },
      {
        address: "google_secret_manager_secret_version.leak",
        type: "google_secret_manager_secret_version",
        values: { secret_data: "plaintext" },
      },
      {
        address: "google_compute_firewall.open_pg",
        type: "google_compute_firewall",
        values: {
          direction: "INGRESS",
          source_ranges: ["0.0.0.0/0"],
          allow: [{ protocol: "tcp", ports: ["5432"] }],
        },
      },
    ]);

    const results = evaluatePlanPolicies(planJson, gcpPlan());
    const failedIds = results.filter((r) => !r.passed).map((r) => r.policyId);
    expect(failedIds).toContain("gcp-wif-strict-condition");
    expect(failedIds).toContain("gcp-no-sa-keys");
    expect(failedIds).toContain("gcp-iam-least-privilege");
    expect(failedIds).toContain("gcp-cloudsql-private");
    expect(failedIds).toContain("gcp-no-legacy-vpc-connector");
    expect(failedIds).toContain("gcp-no-legacy-redis");
    expect(failedIds).toContain("gcp-gcs-private-uniform");
    expect(failedIds).toContain("gcp-no-secret-in-state");
    expect(failedIds).toContain("gcp-firewall-no-open-sensitive-ports");
    expect(
      results.filter((r) => !r.passed && r.policyId === "gcp-wif-strict-condition"),
    ).toHaveLength(2);
  });
});
