import type { FetchLike, ProviderRedactor } from "@opscrew/contracts";
import type { ProjectFacts, Requirements } from "@opscrew/plan-schema";
import { describe, expect, it } from "vitest";
import {
  applyGcpOverrides,
  createGcpConnector,
  designGcpTarget,
  GCP_MANAGED_PROVIDER,
  gcpDbInstanceName,
  gcpWifAttributeCondition,
  hclString,
  renderGcpDeployWorkflow,
  renderGcpHcl,
} from "./index";

function sampleFacts(): ProjectFacts {
  return {
    schemaVersion: 1,
    name: "acme-gcp",
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
    provider: "gcp",
    region: "us-east",
    uptime: "standard",
    dataCriticality: "important",
    domain: "app.example.com",
    dnsProvider: "cloudflare",
    ...overrides,
  } as unknown as Requirements;
}

const redactor: ProviderRedactor = {
  addLiteral: () => undefined,
  redact: (text) => text.replace(/TOP_SECRET_VALUE/g, "[REDACTED]"),
  redactDeep: <T>(v: T): T => v,
};

describe("@opscrew/provider-gcp (Wave 2: T3902, T3903, T3905)", () => {
  it("designs lean, balanced, and production-ha presets with Direct VPC Egress and Memorystore for Valkey", () => {
    const lean = designGcpTarget({
      facts: sampleFacts(),
      requirements: sampleRequirements(),
      preset: "lean",
    });
    expect(lean.target.region).toBe("us-central1");
    expect(lean.target.compute).toBe("cloud-run");
    expect(lean.target.components.network?.service).toBe("direct-vpc-egress");
    expect(lean.target.components.network?.config.cloudNat).toBe(false);
    expect(lean.target.components.cache?.service).toBe("memorystore-valkey");
    expect(lean.target.components.edge?.service).toBe("cloud-run-default-tls");

    const ha = designGcpTarget({
      facts: sampleFacts(),
      requirements: sampleRequirements({ budgetMonthly: { amount: 400, currency: "USD" } }),
      preset: "production-ha",
    });
    expect(ha.target.components.database?.config.regionalHa).toBe(true);
    expect(ha.target.components.edge?.service).toBe("global-alb-cloud-cdn");
    expect(ha.totalMonthlyUsd).toBeGreaterThan(lean.totalMonthlyUsd);
  });

  it("applies --set overrides, reprices, and enforces GCP guardrails", () => {
    const { target } = designGcpTarget({
      facts: sampleFacts(),
      requirements: sampleRequirements(),
      preset: "lean",
    });
    const res = applyGcpOverrides(target, [
      "compute=compute-engine",
      "observability.logsRetentionDays=90",
    ]);
    expect(res.target.compute).toBe("compute-engine");
    expect(res.target.components.compute?.service).toBe("compute-engine");
    expect(res.target.observability.logsRetentionDays).toBe(90);

    expect(() => applyGcpOverrides(target, ["cache.service=memorystore-redis"])).toThrow(
      /legacy Memorystore for Redis/,
    );
    expect(() => applyGcpOverrides(target, ["guardrails.privateDatabase=false"])).toThrow(
      /cannot be disabled silently/,
    );
  });

  it("escapes HCL cleanly and renders valid HCL across Cloud Run, Compute Engine, existingVpcId, and Global ALB", () => {
    const expr = ['a "b" $', "{foo} %{bar}\nc"].join("");
    const expected = ['"a \\"b\\" $$', '{foo} %%{bar}\\nc"'].join("");
    expect(hclString(expr)).toBe(expected);
    expect(gcpWifAttributeCondition({ owner: "acme", repo: "web", environmentName: "prod" })).toBe(
      "assertion.repository == 'acme/web' && assertion.environment == 'prod'",
    );

    const { target } = designGcpTarget({
      facts: sampleFacts(),
      requirements: sampleRequirements(),
      preset: "production-ha",
      pins: {
        projectId: "acme-prod-1234",
        existingVpcId: "projects/acme-prod-1234/global/networks/shared-vpc",
      },
    });
    const files = new Map(
      renderGcpHcl({
        appName: "acme-gcp",
        environment: "prod",
        target,
        domain: "app.example.com",
        dnsProvider: "cloudflare",
        github: { owner: "acme", repo: "web", environmentName: "prod" },
      }).map((f) => [f.path, f.content]),
    );
    expect(files.get("network.tf")).toContain('data "google_compute_network" "existing"');
    expect(files.get("iam.tf")).toContain(
      "assertion.repository == 'acme/web' && assertion.environment == 'prod'",
    );
    expect(files.get("iam.tf")).not.toContain('resource "google_service_account_key"');
    expect(files.get("cache.tf")).toContain('resource "google_memorystore_instance" "app"');
    expect(files.get("cache.tf")).not.toContain('resource "google_redis_instance"');
    expect(files.get("secrets.tf")).not.toContain(
      'resource "google_secret_manager_secret_version"',
    );
    expect(files.get("edge.tf")).toContain(
      'resource "google_certificate_manager_dns_authorization" "app"',
    );
    expect(files.get("outputs.tf")).toContain("acme_validation_records");

    const wf = renderGcpDeployWorkflow({
      appName: "acme-gcp",
      environment: "prod",
      workflowPath: ".github/workflows/opscrew-deploy.yml",
      target,
      branch: "main",
    });
    expect(wf.content).toContain("id-token: write");
    expect(wf.content).toContain("uses: google-github-actions/auth@v2");
    expect(wf.content).toContain('environment: "prod"');
  });

  it("verifies credentials, reads status/logs, writes Secret Manager versions out-of-band, lists backups newest-first, and runs honest restore drills", async () => {
    let polls = 0;
    let deleted = false;
    const fakeFetch: FetchLike = async (input, init) => {
      const url = typeof input === "string" ? input : String(input);
      const method = init?.method ?? "GET";
      if (url.includes("cloudresourcemanager.googleapis.com/v3/projects/acme-123")) {
        return new Response(JSON.stringify({ projectId: "acme-123", displayName: "Acme" }), {
          status: 200,
        });
      }
      if (url.includes("run.googleapis.com/v2/projects/acme-123/locations/us-central1/services/")) {
        return new Response(
          JSON.stringify({
            uri: "https://opscrew-acme-prod-abc.a.run.app",
            conditions: [{ type: "Ready", state: "CONDITION_SUCCEEDED" }],
          }),
          { status: 200 },
        );
      }
      if (url.includes("logging.googleapis.com/v2/entries:list")) {
        return new Response(
          JSON.stringify({
            entries: [
              {
                timestamp: "2026-11-27T12:00:00Z",
                logName: "run",
                textPayload: "Leak TOP_SECRET_VALUE",
              },
            ],
          }),
          { status: 200 },
        );
      }
      if (url.includes("secretmanager.googleapis.com") && url.endsWith(":addVersion")) {
        return new Response(
          JSON.stringify({ name: "projects/acme-123/secrets/DB_URL/versions/1" }),
          { status: 200 },
        );
      }
      if (url.includes("/backupRuns")) {
        return new Response(
          JSON.stringify({
            items: [
              { id: "100", windowStartTime: "2026-11-26T00:00:00Z", status: "SUCCESSFUL" },
              { id: "200", windowStartTime: "2026-11-27T00:00:00Z", status: "SUCCESSFUL" },
            ],
          }),
          { status: 200 },
        );
      }
      if (url.endsWith("/clone")) {
        return new Response(JSON.stringify({ name: "op-1", status: "RUNNING" }), { status: 200 });
      }
      if (url.includes("/instances/opscrew-acme-prod-db-drill")) {
        if (method === "DELETE") {
          deleted = true;
          return new Response(JSON.stringify({ status: "RUNNING" }), { status: 200 });
        }
        if (deleted) return new Response("", { status: 404 });
        polls += 1;
        return new Response(JSON.stringify({ state: polls >= 2 ? "RUNNABLE" : "PENDING_CREATE" }), {
          status: 200,
        });
      }
      return new Response("Not Found", { status: 404 });
    };

    const connector = createGcpConnector({
      fetch: fakeFetch,
      env: { GOOGLE_CLOUD_PROJECT: "acme-123", GOOGLE_OAUTH_ACCESS_TOKEN: "ya29.test" },
      redactor,
      sleep: async () => undefined,
    });

    const id = await connector.verifyCredentials();
    expect(id.ok).toBe(true);
    expect(id.accountId).toBe("acme-123");

    const status = await connector.readStatus({
      appName: "acme",
      environment: "prod",
      region: "us-central1",
      computeKind: "cloud-run",
    });
    expect(status.healthy).toBe(true);
    expect(status.compute.endpoint).toContain("run.app");

    const logs = await connector.readLogs({ logGroup: "opscrew-acme-prod", region: "us-central1" });
    expect(logs[0]?.message).toContain("[REDACTED]");
    expect(logs[0]?.message).not.toContain("TOP_SECRET_VALUE");

    const sec = await connector.writeSecrets({
      region: "us-central1",
      secrets: [{ store: "secret-manager", name: "DB_URL", value: "postgres://..." }],
    });
    expect(sec.written).toEqual(["DB_URL"]);

    const snaps = await connector.listSnapshots({
      region: "us-central1",
      identifierPrefix: gcpDbInstanceName("acme", "prod"),
    });
    expect(snaps.map((s) => s.id)).toEqual(["200", "100"]);

    const drill = await connector.runRestoreDrill({
      region: "us-central1",
      snapshotId: "2026-11-27T00:00:00Z",
      service: "cloud-sql-postgres",
      drillInstanceId: "opscrew-acme-prod-db-drill",
    });
    expect(drill.verified).toBe(true);
    expect(drill.cleanedUp).toBe(true);
    expect(GCP_MANAGED_PROVIDER.id).toBe("gcp");
  });
});
