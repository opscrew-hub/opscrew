import { mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type {
  IacApplyResult,
  IacEngine,
  ManagedCloudConnector,
  ManagedCloudProviderDefinition,
  ManagedCloudSecretWrite,
  PlanSummary,
} from "@opscrew/contracts";
import {
  ApprovalGate,
  CostLedger,
  MemoryApprovalStore,
  MemoryAuditLog,
  OpsCrewError,
  Redactor,
  resolveProjectPaths,
} from "@opscrew/core";
import {
  type Architecture,
  type DeployPlan,
  type ProjectFacts,
  type Requirements,
  writeArtifact,
} from "@opscrew/plan-schema";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { PhaseDeps } from "../context";
import {
  planGcpRetarget,
  runGcpAdvise,
  runGcpDesign,
  runGcpDestroy,
  runGcpDrift,
  runGcpLogs,
  runGcpProvision,
  runGcpRestoreDrill,
  runGcpRotateSecrets,
  runGcpSnapshotList,
  runGcpSnapshotTake,
  runGcpStatus,
  runGcpVerify,
} from "./index";

const PLAN_HASH = "e".repeat(64);
const DESTROY_HASH = "f".repeat(64);

const tempDirs: string[] = [];

afterEach(async () => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir !== undefined) await rm(dir, { recursive: true, force: true });
  }
});

function sampleFacts(): ProjectFacts {
  return {
    name: "shop-api",
    languages: ["typescript"],
    packageManager: "pnpm",
    frameworks: [{ name: "nextjs", path: "." }],
    appKind: "fullstack",
    platformExport: { platform: "none", evidence: [] },
    build: {},
    port: 3000,
    runtimeVersions: { node: "22" },
    envVars: [
      {
        name: "APP_SECRET",
        files: ["src/auth.ts"],
        clientExposed: false,
        secretLikely: true,
      },
      {
        name: "DATABASE_URL",
        files: ["src/db.ts"],
        clientExposed: false,
        secretLikely: true,
        urlScheme: "postgres",
      },
    ],
    services: [
      { kind: "postgres", evidence: ["DATABASE_URL"], variable: "DATABASE_URL" },
      { kind: "redis", evidence: ["REDIS_URL"], variable: "REDIS_URL" },
    ],
    docker: {},
    healthEndpoint: "/api/health",
    monorepo: false,
    appDir: ".",
    git: { owner: "acme", repo: "shop", defaultBranch: "main" },
  };
}

function sampleArchitecture(): Architecture {
  return {
    schemaVersion: 1,
    generatedAt: "2026-11-28T00:00:00.000Z",
    generator: { tool: "opscrew", version: "0.2.12" },
    facts: sampleFacts(),
    summary: "Next.js fullstack app with Postgres and Redis.",
    risks: [],
    aiEnriched: false,
  };
}

function sampleRequirements(): Requirements {
  return {
    schemaVersion: 1,
    answeredAt: "2026-11-28T00:00:00.000Z",
    expectedMonthlyUsers: "1k-10k",
    budgetMonthly: { amount: 80, currency: "USD" },
    provider: "gcp",
    region: "eu-central",
    uptime: "standard",
    dataCriticality: "important",
    keepExternalServices: {},
    domain: "shop.example.com",
    dnsProvider: "cloudflare",
  };
}

async function createTestDeps(options?: {
  approve?: boolean;
  confirmText?: string;
  fetch?: PhaseDeps["fetch"];
}): Promise<{ deps: PhaseDeps; audit: MemoryAuditLog; root: string }> {
  const root = await mkdtemp(path.join(os.tmpdir(), "opscrew-gcp-agent-"));
  tempDirs.push(root);
  const paths = resolveProjectPaths(root, { homedir: path.join(root, ".home") });
  const audit = new MemoryAuditLog();
  const approvals = new ApprovalGate({
    handler: {
      request: async () => ({
        approved: options?.approve ?? true,
        approver: "tester",
        decidedAt: "2026-11-28T00:00:00.000Z",
        ...(options?.confirmText === undefined ? {} : { confirmation: options.confirmText }),
      }),
    },
    store: new MemoryApprovalStore(),
    audit,
  });
  const deps: PhaseDeps = {
    paths,
    reporter: {
      info: vi.fn(),
      step: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
      success: vi.fn(),
    },
    approvals,
    audit,
    state: {} as PhaseDeps["state"],
    costs: new CostLedger(path.join(root, ".opscrew", "costs.jsonl")),
    runner: {
      run: vi.fn(async () => ({ exitCode: 0, stdout: "", stderr: "", durationMs: 1 })),
    },
    fetch:
      options?.fetch ??
      (vi.fn(async () => new Response("ok", { status: 200 })) as unknown as PhaseDeps["fetch"]),
    env: {},
    clock: { now: () => new Date("2026-11-28T00:00:00.000Z") },
    redactor: new Redactor(),
    interactive: false,
    version: "0.2.12",
  };
  await writeArtifact("architecture", paths.files.architecture, sampleArchitecture());
  await writeArtifact("requirements", paths.files.requirements, sampleRequirements());
  return { deps, audit, root };
}

function fakeConnector(overrides?: Partial<ManagedCloudConnector>): ManagedCloudConnector {
  return {
    verifyCredentials: vi.fn(async () => ({
      ok: true,
      accountId: "my-gcp-project-123",
      principalArn: "gcp:project:my-gcp-project-123",
    })),
    readStatus: vi.fn(async () => ({
      healthy: true,
      region: "europe-west1",
      accountId: "my-gcp-project-123",
      compute: {
        kind: "cloud-run",
        status: "Running",
        endpoint: "https://shop.example.com",
      },
      services: [{ name: "postgres", service: "cloud-sql-postgres", status: "RUNNABLE" }],
      alarms: [],
    })),
    readLogs: vi.fn(async () => [
      { timestamp: "2026-11-28T00:00:00.000Z", stream: "app", message: "ready on 3000" },
    ]),
    writeSecrets: vi.fn(async ({ secrets }: { secrets: readonly ManagedCloudSecretWrite[] }) => ({
      written: secrets.map((s) => s.name),
    })),
    listSnapshots: vi.fn(async () => [
      {
        id: "1732752000000",
        service: "cloud-sql-postgres",
        engine: "postgres",
        createdAt: "2026-11-27T23:00:00.000Z",
        status: "SUCCESSFUL",
      },
    ]),
    takeSnapshot: vi.fn(async ({ snapshotId, service }) => ({
      id: snapshotId,
      service,
      engine: "postgres",
      createdAt: "2026-11-28T00:00:00.000Z",
      status: "SUCCESSFUL",
    })),
    runRestoreDrill: vi.fn(async ({ snapshotId, service }) => ({
      snapshotId,
      service,
      verified: true,
      durationMs: 280,
      cleanedUp: true,
      detail:
        "Restored private throwaway Cloud SQL clone, verified RUNNABLE, and confirmed deleted.",
    })),
    ...overrides,
  };
}

function fakeEngine(options?: {
  planJson?: unknown;
  planHash?: string;
  hasDestroy?: boolean;
  deleteCount?: number;
  outputs?: Record<string, unknown>;
}): IacEngine & { applied: boolean; applyCalls: number } {
  const engine = {
    applied: false,
    applyCalls: 0,
    info: { name: "tofu" as const, version: "1.11.0", binary: "/usr/bin/tofu" },
    init: vi.fn(async () => undefined),
    validate: vi.fn(async () => ({ valid: true, diagnostics: [] })),
    plan: vi.fn(async (_dir, planFile, opts): Promise<PlanSummary> => {
      const destroy = opts?.destroy === true || options?.hasDestroy === true;
      const deleteCount = options?.deleteCount ?? (destroy ? 3 : 0);
      return {
        engine: { name: "tofu", version: "1.11.0", binary: "/usr/bin/tofu" },
        dir: _dir,
        planFile,
        planHash: options?.planHash ?? (destroy ? DESTROY_HASH : PLAN_HASH),
        createdAt: "2026-11-28T00:00:00.000Z",
        changes: [
          {
            address: "google_cloud_run_v2_service.app",
            type: "google_cloud_run_v2_service",
            name: "app",
            provider: "registry.opentofu.org/hashicorp/google",
            action: destroy ? "delete" : "create",
          },
        ],
        counts: { create: destroy ? 0 : 1, update: 0, delete: deleteCount, replace: 0 },
        hasDestroy: destroy,
        planJson: options?.planJson ?? {
          resource_changes: [
            {
              address: "google_logging_project_bucket_config.app",
              type: "google_logging_project_bucket_config",
              change: { actions: ["create"], after: { retention_days: 30 } },
            },
          ],
        },
      };
    }),
    apply: vi.fn(async (): Promise<IacApplyResult> => {
      engine.applied = true;
      engine.applyCalls += 1;
      return { ok: true, outputs: options?.outputs ?? {}, log: "Apply complete!" };
    }),
    output: vi.fn(async () => options?.outputs ?? {}),
    providerSchemas: vi.fn(async () => ({})),
    stateResources: vi.fn(async () => []),
    untaint: vi.fn(async () => undefined),
    stateRemove: vi.fn(async () => undefined),
    importResource: vi.fn(async () => undefined),
  };
  return engine;
}

describe("GCP core phase orchestration (Feature 039 T3906)", () => {
  it("fails closed by default when @opscrew/provider-gcp is not installed", async () => {
    const { deps } = await createTestDeps();
    await expect(runGcpDesign(deps, { optionId: "gcp-lean" })).rejects.toThrow(/not installed yet/);
  });

  it("designs GCP presets, applies --set overrides, and persists validated plan.yaml", async () => {
    const { deps } = await createTestDeps();
    const res = await runGcpDesign(deps, {
      optionId: "gcp-balanced",
      setFlags: ["compute=compute-engine"],
      allowWorkspaceFallback: true,
    });
    expect(res.options.map((o) => o.id)).toEqual(["gcp-lean", "gcp-balanced", "gcp-production-ha"]);
    expect(res.target.provider).toBe("gcp");
    expect(res.target.compute).toBe("compute-engine");
    expect(res.appliedOverrides).toHaveLength(1);
    const saved = await readFile(deps.paths.files.plan, "utf8");
    expect(saved).toContain("provider: gcp");
    expect(saved).toContain("compute-engine");
  });

  it("blocks GCP provision when SecOps detects legacy Serverless VPC Access Connector or public Cloud SQL", async () => {
    const { deps, audit } = await createTestDeps();
    const designed = await runGcpDesign(deps, {
      optionId: "gcp-lean",
      allowWorkspaceFallback: true,
    });
    const engine = fakeEngine({
      planJson: {
        planned_values: {
          root_module: {
            resources: [
              {
                address: "google_vpc_access_connector.legacy",
                mode: "managed",
                type: "google_vpc_access_connector",
                values: { name: "legacy-conn" },
              },
            ],
          },
        },
        resource_changes: [
          {
            address: "google_vpc_access_connector.legacy",
            type: "google_vpc_access_connector",
            change: { actions: ["create"], after: { name: "legacy-conn" } },
          },
        ],
      },
    });
    const connector = fakeConnector();

    await expect(
      runGcpProvision(deps, {
        plan: designed.plan,
        engine,
        githubRepo: "acme/shop",
        connector,
        allowWorkspaceFallback: true,
      }),
    ).rejects.toThrow(/Blocked GCP plan due to/);

    expect(engine.applied).toBe(false);
    expect(audit.entries.some((e) => e.kind === "iac" && e.decision === "refused")).toBe(true);
  });

  it("provisions with hash-bound approval, writes Secret Manager versions out-of-band, and wires Cloudflare ACME CNAME proxied=false", async () => {
    const { deps, audit, root } = await createTestDeps();
    const designed = await runGcpDesign(deps, {
      optionId: "gcp-lean",
      allowWorkspaceFallback: true,
    });
    const engine = fakeEngine({
      outputs: {
        acme_validation_records: [
          {
            name: "_acme-challenge.shop.example.com",
            value: "token.authorize.certificatemanager.goog.",
          },
        ],
      },
    });
    const connector = fakeConnector();
    const cfRecords: unknown[] = [];

    const result = await runGcpProvision(deps, {
      plan: designed.plan,
      engine,
      githubRepo: "acme/shop",
      connector,
      allowWorkspaceFallback: true,
      secrets: [{ store: "secret-manager", name: "APP_SECRET", value: "super-secret-gcp-xyz" }],
      cloudflare: {
        upsertDnsRecord: async (rec) => {
          cfRecords.push(rec);
        },
      },
    });

    expect(result.applied).toBe(true);
    expect(result.renderedFiles.some((f) => f.endsWith("versions.tf"))).toBe(true);
    expect(result.renderedFiles.some((f) => f.endsWith("iam.tf"))).toBe(true);
    expect(result.renderedFiles.some((f) => f.endsWith("opscrew-deploy.yml"))).toBe(true);
    expect(result.writtenSecretNames).toEqual(["APP_SECRET"]);
    expect(result.acmeRecordsWired).toEqual([
      {
        name: "_acme-challenge.shop.example.com",
        content: "token.authorize.certificatemanager.goog.",
        proxied: false,
      },
    ]);
    expect(cfRecords).toHaveLength(1);

    expect(JSON.stringify(audit.entries)).not.toContain("super-secret-gcp-xyz");
    const iamTf = await readFile(path.join(root, designed.plan.infra.dir, "iam.tf"), "utf8");
    expect(iamTf).toContain("assertion.repository == 'acme/shop'");
  });

  it("runs status, logs, verify, drift, snapshot list/take/drill, rotate, advise, retarget, and typed destroy", async () => {
    const { deps } = await createTestDeps({ approve: true, confirmText: "shop-api" });
    const designed = await runGcpDesign(deps, {
      optionId: "gcp-balanced",
      allowWorkspaceFallback: true,
    });
    const connector = fakeConnector();
    const engine = fakeEngine();

    const status = await runGcpStatus(deps, {
      plan: designed.plan,
      connector,
      allowWorkspaceFallback: true,
    });
    expect(status.status.healthy).toBe(true);

    const logs = await runGcpLogs(deps, {
      plan: designed.plan,
      connector,
      allowWorkspaceFallback: true,
    });
    expect(logs.lines[0]?.message).toBe("ready on 3000");

    const verify = await runGcpVerify(deps, {
      plan: designed.plan,
      connector,
      allowWorkspaceFallback: true,
    });
    expect(verify.ok).toBe(true);

    const drift = await runGcpDrift(deps, {
      plan: designed.plan,
      engine,
      githubRepo: "acme/shop",
      connector,
      allowWorkspaceFallback: true,
    });
    expect(drift.driftedFiles.length).toBeGreaterThan(0);

    const snaps = await runGcpSnapshotList(deps, {
      plan: designed.plan,
      connector,
      allowWorkspaceFallback: true,
    });
    expect(snaps).toHaveLength(1);

    const taken = await runGcpSnapshotTake(deps, {
      plan: designed.plan,
      connector,
      allowWorkspaceFallback: true,
    });
    expect(taken.id).toContain("opscrew-shop-api-prod-db");

    const drill = await runGcpRestoreDrill(deps, {
      plan: designed.plan,
      connector,
      snapshotId: "2026-11-28T00:00:00Z",
      allowWorkspaceFallback: true,
    });
    expect(drill.verified).toBe(true);
    expect(drill.cleanedUp).toBe(true);

    const rotated = await runGcpRotateSecrets(deps, {
      plan: designed.plan,
      connector,
      allowWorkspaceFallback: true,
      secrets: [{ store: "secret-manager", name: "JWT_SECRET", value: "new-secret-value" }],
    });
    expect(rotated.written).toEqual(["JWT_SECRET"]);

    const advice = await runGcpAdvise(deps, {
      plan: designed.plan,
      allowWorkspaceFallback: true,
    });
    expect(advice.length).toBeGreaterThan(0);

    const retarget = await planGcpRetarget(deps, {
      allowWorkspaceFallback: true,
      currentPlan: {
        ...designed.plan,
        target: {
          provider: "hetzner",
          mode: "vps-compose",
          location: "fsn1",
          serverType: "cx22",
          image: "ubuntu-24.04",
          backups: true,
          edge: "caddy",
        },
      } as unknown as DeployPlan,
      facts: sampleFacts(),
    });
    expect(retarget.target.compute).toBe("compute-engine");

    const destroyEngine = fakeEngine({ hasDestroy: true, deleteCount: 3 });
    const destroyed = await runGcpDestroy(deps, {
      plan: designed.plan,
      engine: destroyEngine,
      allowWorkspaceFallback: true,
    });
    expect(destroyed.destroyed).toBe(true);
    expect(destroyEngine.applied).toBe(true);

    const { deps: badDeps } = await createTestDeps({ approve: true, confirmText: "wrong" });
    const badEngine = fakeEngine({ hasDestroy: true, deleteCount: 3 });
    await expect(
      runGcpDestroy(badDeps, {
        plan: designed.plan,
        engine: badEngine,
        allowWorkspaceFallback: true,
      }),
    ).rejects.toThrow(OpsCrewError);
    expect(badEngine.applied).toBe(false);
  });

  it("rejects malformed GCP plugin missing required render/design hooks", async () => {
    const { deps } = await createTestDeps();
    const incompletePlugin: ManagedCloudProviderDefinition = {
      contractVersion: 1,
      id: "gcp",
      displayName: "Google Cloud",
      packageName: "@opscrew/provider-gcp",
      credentials: { envVars: [], secretPatterns: [], consoleUrl: "", instructions: "" },
      regions: [],
      presets: ["lean"],
      createConnector: () => fakeConnector(),
    };
    await expect(runGcpDesign(deps, { plugin: incompletePlugin })).rejects.toThrow(
      /missing required design\/render hooks/,
    );
  });
});
