import type { FetchLike, ProviderRedactor } from "@opscrew/contracts";
import type { ProjectFacts, Requirements } from "@opscrew/plan-schema";
import { describe, expect, it } from "vitest";
import {
  AZURE_MANAGED_PROVIDER,
  applyAzureOverrides,
  azureDbServerName,
  azureGithubOidcSubject,
  createAzureConnector,
  designAzureTarget,
  hclString,
  renderAzureDeployWorkflow,
  renderAzureHcl,
} from "./index";

function sampleFacts(): ProjectFacts {
  return {
    schemaVersion: 1,
    name: "acme-web",
    language: "typescript",
    packageManager: "pnpm",
    appKind: "fullstack",
    platformExport: "none",
    port: 3000,
    healthEndpoint: "/health",
    services: [
      { kind: "postgres", confidence: "high", evidence: ["pg"] },
      { kind: "redis", confidence: "high", evidence: ["ioredis"] },
      { kind: "s3", confidence: "high", evidence: ["@aws-sdk/client-s3"] },
    ],
    envVars: [],
    hasDockerfile: true,
    hasDockerignore: true,
    warnings: [],
  } as unknown as ProjectFacts;
}

function sampleRequirements(overrides: Partial<Requirements> = {}): Requirements {
  return {
    schemaVersion: 1,
    expectedMonthlyUsers: "1k-10k",
    budgetMonthly: { amount: 40, currency: "USD" },
    provider: "azure",
    region: "eu-central",
    uptime: "standard",
    dataCriticality: "important",
    domain: "app.example.com",
    dnsProvider: "cloudflare",
    ...overrides,
  } as unknown as Requirements;
}

const passThroughRedactor: ProviderRedactor = {
  addLiteral: () => undefined,
  redact: (text) => text.replace(/SUPER_SECRET_TOKEN/g, "[REDACTED]"),
  redactDeep: <T>(value: T): T => value,
};

describe("@opscrew/provider-azure (Wave 2: T3802, T3803, T3805)", () => {
  it("designs lean, balanced, and production-ha presets with zero NAT/FrontDoor traps on lean and Azure Managed Redis", () => {
    const lean = designAzureTarget({
      facts: sampleFacts(),
      requirements: sampleRequirements(),
      preset: "lean",
    });
    expect(lean.target.region).toBe("westeurope");
    expect(lean.target.compute).toBe("container-apps");
    expect(lean.target.components.network?.config.natGateway).toBe(false);
    expect(lean.target.components.cache?.service).toBe("managed-redis");
    expect(lean.target.components.edge?.service).toBe("cloudflare-edge");
    expect(lean.target.observability.logsRetentionDays).toBe(30);

    const ha = designAzureTarget({
      facts: sampleFacts(),
      requirements: sampleRequirements({
        dnsProvider: "none",
        budgetMonthly: { amount: 500, currency: "USD" },
      }),
      preset: "production-ha",
    });
    expect(ha.target.components.database?.config.zoneRedundant).toBe(true);
    expect(ha.target.components.edge?.service).toBe("azure-front-door");
    expect(ha.target.observability.logsRetentionDays).toBe(90);
    expect(ha.totalMonthlyUsd).toBeGreaterThan(lean.totalMonthlyUsd);
  });

  it("applies --set overrides, syncs compute, reprices, and enforces guardrails", () => {
    const { target } = designAzureTarget({
      facts: sampleFacts(),
      requirements: sampleRequirements(),
      preset: "lean",
    });
    const res = applyAzureOverrides(target, [
      "compute=app-service",
      "observability.logsRetentionDays=60",
    ]);
    expect(res.target.compute).toBe("app-service");
    expect(res.target.components.compute?.service).toBe("app-service");
    expect(res.target.observability.logsRetentionDays).toBe(60);
    expect(res.deltaMonthlyUsd).not.toBe(0);

    expect(() => applyAzureOverrides(target, ["cache.service=azure-cache-for-redis"])).toThrow(
      /retiring Azure Cache for Redis/,
    );

    expect(() => applyAzureOverrides(target, ["guardrails.privateDatabase=false"])).toThrow(
      /cannot be disabled silently/,
    );
  });

  it("escapes HCL strings cleanly (preserving $${}) and renders valid HCL across all 3 compute kinds & existingVnetId", () => {
    const sampleExpr = ['a "b" $', "{foo} %{bar}\nc"].join("");
    const expectedExpr = ['"a \\"b\\" $$', '{foo} %%{bar}\\nc"'].join("");
    expect(hclString(sampleExpr)).toBe(expectedExpr);
    expect(azureGithubOidcSubject({ owner: "acme", repo: "web", environmentName: "prod" })).toBe(
      "repo:acme/web:environment:prod",
    );

    const { target } = designAzureTarget({
      facts: sampleFacts(),
      requirements: sampleRequirements(),
      preset: "lean",
      pins: {
        existingVnetId:
          "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-core",
      },
    });
    const files = renderAzureHcl({
      appName: "acme-web",
      environment: "prod",
      target,
      domain: "app.example.com",
      dnsProvider: "cloudflare",
      github: { owner: "acme", repo: "web", environmentName: "prod" },
    });
    const byPath = new Map(files.map((f) => [f.path, f.content]));
    expect(byPath.get("network.tf")).toContain('data "azurerm_virtual_network" "existing"');
    expect(byPath.get("iam.tf")).toMatch(/subject\s+=\s+"repo:acme\/web:environment:prod"/);
    expect(byPath.get("iam.tf")).toMatch(/audience\s+=\s+\["api:\/\/AzureADTokenExchange"\]/);
    expect(byPath.get("cache.tf")).toContain('resource "azurerm_managed_redis" "app"');
    expect(byPath.get("cache.tf")).not.toContain('resource "azurerm_redis_cache"');
    expect(byPath.get("secrets.tf")).toContain('resource "azurerm_key_vault" "app"');
    expect(byPath.get("secrets.tf")).not.toContain('resource "azurerm_key_vault_secret"');
    expect(byPath.get("outputs.tf")).toContain("asuid.app.example.com");

    // App Service & VM Compose compute renderers
    const appSvc = applyAzureOverrides(target, ["compute=app-service"]).target;
    const appSvcFiles = new Map(
      renderAzureHcl({
        appName: "acme-web",
        environment: "prod",
        target: appSvc,
        github: { owner: "acme", repo: "web", environmentName: "prod" },
      }).map((f) => [f.path, f.content]),
    );
    expect(appSvcFiles.get("compute.tf")).toContain('resource "azurerm_linux_web_app" "app"');

    const vmTarget = applyAzureOverrides(target, ["compute=vm-compose"]).target;
    const vmFiles = new Map(
      renderAzureHcl({
        appName: "acme-web",
        environment: "prod",
        target: vmTarget,
        github: { owner: "acme", repo: "web", environmentName: "prod" },
      }).map((f) => [f.path, f.content]),
    );
    expect(vmFiles.get("compute.tf")).toContain('resource "azurerm_linux_virtual_machine" "app"');

    const wf = renderAzureDeployWorkflow({
      appName: "acme-web",
      environment: "prod",
      workflowPath: ".github/workflows/opscrew-deploy.yml",
      target,
      branch: "main",
    });
    expect(wf.content).toContain("id-token: write");
    expect(wf.content).toContain('environment: "prod"');
    expect(wf.content).toContain("uses: azure/login@v2");
    expect(wf.content).not.toContain("AZURE_CLIENT_SECRET");
  });

  it("verifies credentials, reads status/logs, writes Key Vault secrets out-of-band, lists backups newest-first, and completes honest PITR restore drills", async () => {
    let pollCount = 0;
    let deleted = false;
    const calls: string[] = [];

    const fakeFetch: FetchLike = async (input, init) => {
      const url = typeof input === "string" ? input : String(input);
      const method = init?.method ?? "GET";
      calls.push(`${method} ${url}`);

      if (url.includes("/subscriptions/sub-123?api-version=")) {
        return new Response(JSON.stringify({ subscriptionId: "sub-123", displayName: "Dev Sub" }), {
          status: 200,
        });
      }
      if (url.includes("/containerApps/opscrew-acme-prod")) {
        return new Response(
          JSON.stringify({
            properties: {
              runningStatus: "Running",
              configuration: { ingress: { fqdn: "acme.azurecontainerapps.io" } },
            },
          }),
          { status: 200 },
        );
      }
      if (url.includes("api.loganalytics.io/v1/workspaces/ws-1/query")) {
        return new Response(
          JSON.stringify({
            tables: [
              {
                rows: [["2026-11-27T12:00:00Z", "app", "Started with SUPER_SECRET_TOKEN"]],
              },
            ],
          }),
          { status: 200 },
        );
      }
      if (url.includes("kv-acme-prod.vault.azure.net/secrets/DATABASE-URL")) {
        return new Response(JSON.stringify({ id: "secret-v1" }), { status: 200 });
      }
      if (url.includes("/backups?api-version=")) {
        return new Response(
          JSON.stringify({
            value: [
              {
                name: "bkp-old",
                properties: { completedTime: "2026-11-26T00:00:00Z", backupType: "Automatic" },
              },
              {
                name: "bkp-new",
                properties: { completedTime: "2026-11-27T00:00:00Z", backupType: "OnDemand" },
              },
            ],
          }),
          { status: 200 },
        );
      }
      if (url.includes("/flexibleServers/opscrew-acme-prod-db-drill")) {
        if (method === "PUT") {
          const parsedBody = JSON.parse(String(init?.body ?? "{}")) as {
            properties?: { network?: { publicNetworkAccess?: string } };
          };
          expect(parsedBody.properties?.network?.publicNetworkAccess).toBe("Disabled");
          return new Response(JSON.stringify({ properties: { state: "Creating" } }), {
            status: 202,
          });
        }
        if (method === "DELETE") {
          deleted = true;
          return new Response("", { status: 202 });
        }
        if (deleted) {
          return new Response("", { status: 404 });
        }
        pollCount += 1;
        return new Response(
          JSON.stringify({ properties: { state: pollCount >= 2 ? "Ready" : "Creating" } }),
          { status: 200 },
        );
      }
      return new Response("Not Found", { status: 404 });
    };

    const connector = createAzureConnector({
      fetch: fakeFetch,
      env: {
        AZURE_SUBSCRIPTION_ID: "sub-123",
        AZURE_ACCESS_TOKEN: "tok-arm-test",
        AZURE_KEY_VAULT_ACCESS_TOKEN: "tok-kv-test",
        AZURE_LOG_ANALYTICS_ACCESS_TOKEN: "tok-log-test",
        AZURE_KEY_VAULT_URL: "https://kv-acme-prod.vault.azure.net",
      },
      redactor: passThroughRedactor,
      sleep: async () => undefined,
    });

    const id = await connector.verifyCredentials();
    expect(id.ok).toBe(true);
    expect(id.accountId).toBe("sub-123");

    const status = await connector.readStatus({
      appName: "acme",
      environment: "prod",
      region: "westeurope",
      computeKind: "container-apps",
    });
    expect(status.healthy).toBe(true);
    expect(status.compute.endpoint).toBe("https://acme.azurecontainerapps.io");

    const logs = await connector.readLogs({ logGroup: "ws-1", region: "westeurope" });
    expect(logs[0]?.message).toContain("[REDACTED]");
    expect(logs[0]?.message).not.toContain("SUPER_SECRET_TOKEN");

    const secrets = await connector.writeSecrets({
      region: "westeurope",
      secrets: [{ store: "key-vault", name: "DATABASE_URL", value: "postgres://..." }],
    });
    expect(secrets.written).toEqual(["DATABASE-URL"]);

    const snaps = await connector.listSnapshots({
      region: "westeurope",
      identifierPrefix: azureDbServerName("acme", "prod"),
    });
    expect(snaps.map((s) => s.id)).toEqual(["bkp-new", "bkp-old"]);

    const badDrill = await connector.runRestoreDrill({
      region: "westeurope",
      snapshotId: "not-a-timestamp",
      service: "flexible-postgres",
      drillInstanceId: "opscrew-acme-prod-db-drill",
    });
    expect(badDrill.verified).toBe(false);
    expect(badDrill.cleanedUp).toBe(false);

    await expect(
      connector.writeSecrets({
        region: "westeurope",
        secrets: [
          { store: "key-vault", name: "FOO_BAR", value: "1" },
          { store: "key-vault", name: "FOO-BAR", value: "2" },
        ],
      }),
    ).rejects.toThrow(/collision/);

    const drill = await connector.runRestoreDrill({
      region: "westeurope",
      snapshotId: "2026-11-27T00:00:00Z",
      service: "flexible-postgres",
      drillInstanceId: "opscrew-acme-prod-db-drill",
    });
    expect(drill.verified).toBe(true);
    expect(drill.cleanedUp).toBe(true);
    expect(AZURE_MANAGED_PROVIDER.id).toBe("azure");
  });
});
