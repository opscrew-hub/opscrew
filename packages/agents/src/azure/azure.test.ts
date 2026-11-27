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
  planAzureRetarget,
  runAzureAdvise,
  runAzureDesign,
  runAzureDestroy,
  runAzureDrift,
  runAzureLogs,
  runAzureProvision,
  runAzureRestoreDrill,
  runAzureRotateSecrets,
  runAzureSnapshotList,
  runAzureSnapshotTake,
  runAzureStatus,
  runAzureVerify,
} from "./index";

const PLAN_HASH = "c".repeat(64);
const DESTROY_HASH = "d".repeat(64);

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
    generatedAt: "2026-11-27T12:00:00.000Z",
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
    answeredAt: "2026-11-27T12:00:00.000Z",
    expectedMonthlyUsers: "1k-10k",
    budgetMonthly: { amount: 80, currency: "USD" },
    provider: "azure",
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
  const root = await mkdtemp(path.join(os.tmpdir(), "opscrew-azure-agent-"));
  tempDirs.push(root);
  const paths = resolveProjectPaths(root, { homedir: path.join(root, ".home") });
  const audit = new MemoryAuditLog();
  const approvals = new ApprovalGate({
    handler: {
      request: async () => ({
        approved: options?.approve ?? true,
        approver: "tester",
        decidedAt: "2026-11-27T12:00:00.000Z",
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
    clock: { now: () => new Date("2026-11-27T12:00:00.000Z") },
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
      accountId: "sub-0000-1111",
      principalArn: "azure:subscription:Dev",
    })),
    readStatus: vi.fn(async () => ({
      healthy: true,
      region: "westeurope",
      accountId: "sub-0000-1111",
      compute: {
        kind: "container-apps",
        status: "Running",
        endpoint: "https://shop.example.com",
      },
      services: [{ name: "postgres", service: "flexible-postgres", status: "Ready" }],
      alarms: [],
    })),
    readLogs: vi.fn(async () => [
      { timestamp: "2026-11-27T12:00:00.000Z", stream: "app", message: "ready on 3000" },
    ]),
    writeSecrets: vi.fn(async ({ secrets }: { secrets: readonly ManagedCloudSecretWrite[] }) => ({
      written: secrets.map((s) => s.name),
    })),
    listSnapshots: vi.fn(async () => [
      {
        id: "bkp-20261127",
        service: "flexible-postgres",
        engine: "postgres",
        createdAt: "2026-11-27T11:00:00.000Z",
        status: "Automatic",
      },
    ]),
    takeSnapshot: vi.fn(async ({ snapshotId, service }) => ({
      id: snapshotId,
      service,
      engine: "postgres",
      createdAt: "2026-11-27T12:00:00.000Z",
      status: "Completed",
    })),
    runRestoreDrill: vi.fn(async ({ snapshotId, service }) => ({
      snapshotId,
      service,
      verified: true,
      durationMs: 310,
      cleanedUp: true,
      detail: "Restored private throwaway Flexible Server, verified Ready, and confirmed deleted.",
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
        createdAt: "2026-11-27T12:00:00.000Z",
        changes: [
          {
            address: "azurerm_resource_group.app",
            type: "azurerm_resource_group",
            name: "app",
            provider: "registry.opentofu.org/hashicorp/azurerm",
            action: destroy ? "delete" : "create",
          },
        ],
        counts: { create: destroy ? 0 : 1, update: 0, delete: deleteCount, replace: 0 },
        hasDestroy: destroy,
        planJson: options?.planJson ?? {
          resource_changes: [
            {
              address: "azurerm_log_analytics_workspace.app",
              type: "azurerm_log_analytics_workspace",
              change: { actions: ["create"], after: { retention_in_days: 30 } },
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

describe("Azure core phase orchestration (Feature 038 T3806)", () => {
  it("fails closed by default when @opscrew/provider-azure is not installed", async () => {
    const { deps } = await createTestDeps();
    await expect(runAzureDesign(deps, { optionId: "azure-lean" })).rejects.toThrow(
      /not installed yet/,
    );
  });

  it("designs Azure presets, applies --set overrides, and persists validated plan.yaml", async () => {
    const { deps } = await createTestDeps();
    const res = await runAzureDesign(deps, {
      optionId: "azure-balanced",
      setFlags: ["compute=app-service"],
      allowWorkspaceFallback: true,
    });
    expect(res.options.map((o) => o.id)).toEqual([
      "azure-lean",
      "azure-balanced",
      "azure-production-ha",
    ]);
    expect(res.target.provider).toBe("azure");
    expect(res.target.compute).toBe("app-service");
    expect(res.appliedOverrides).toHaveLength(1);
    const saved = await readFile(deps.paths.files.plan, "utf8");
    expect(saved).toContain("provider: azure");
    expect(saved).toContain("app-service");
  });

  it("blocks Azure provision when SecOps detects retiring Redis or public DB", async () => {
    const { deps, audit } = await createTestDeps();
    const designed = await runAzureDesign(deps, {
      optionId: "azure-lean",
      allowWorkspaceFallback: true,
    });
    const engine = fakeEngine({
      planJson: {
        planned_values: {
          root_module: {
            resources: [
              {
                address: "azurerm_redis_cache.old",
                mode: "managed",
                type: "azurerm_redis_cache",
                values: { name: "old" },
              },
            ],
          },
        },
        resource_changes: [
          {
            address: "azurerm_redis_cache.old",
            type: "azurerm_redis_cache",
            change: { actions: ["create"], after: { name: "old" } },
          },
        ],
      },
    });
    const connector = fakeConnector();

    await expect(
      runAzureProvision(deps, {
        plan: designed.plan,
        engine,
        githubRepo: "acme/shop",
        connector,
        allowWorkspaceFallback: true,
      }),
    ).rejects.toThrow(/Blocked Azure plan due to/);

    expect(engine.applied).toBe(false);
    expect(audit.entries.some((e) => e.kind === "iac" && e.decision === "refused")).toBe(true);
  });

  it("provisions with hash-bound approval, writes Key Vault secrets out-of-band, and wires Cloudflare asuid TXT proxied=false", async () => {
    const { deps, audit, root } = await createTestDeps();
    const designed = await runAzureDesign(deps, {
      optionId: "azure-lean",
      allowWorkspaceFallback: true,
    });
    const engine = fakeEngine({
      outputs: {
        asuid_validation_records: [
          { name: "asuid.shop.example.com", value: "VERIFICATION-TOKEN-123" },
        ],
      },
    });
    const connector = fakeConnector();
    const cfRecords: unknown[] = [];

    const result = await runAzureProvision(deps, {
      plan: designed.plan,
      engine,
      githubRepo: "acme/shop",
      connector,
      allowWorkspaceFallback: true,
      secrets: [{ store: "key-vault", name: "APP-SECRET", value: "super-secret-azure-xyz" }],
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
    expect(result.writtenSecretNames).toEqual(["APP-SECRET"]);
    expect(result.asuidRecordsWired).toEqual([
      { name: "asuid.shop.example.com", content: "VERIFICATION-TOKEN-123", proxied: false },
    ]);
    expect(cfRecords).toHaveLength(1);

    expect(JSON.stringify(audit.entries)).not.toContain("super-secret-azure-xyz");
    const iamTf = await readFile(path.join(root, designed.plan.infra.dir, "iam.tf"), "utf8");
    expect(iamTf).toContain("repo:acme/shop:environment:prod");
  });

  it("runs status, logs, verify, drift, snapshot list/take/drill, rotate, advise, retarget, and typed destroy", async () => {
    const { deps } = await createTestDeps({ approve: true, confirmText: "shop-api" });
    const designed = await runAzureDesign(deps, {
      optionId: "azure-balanced",
      allowWorkspaceFallback: true,
    });
    const connector = fakeConnector();
    const engine = fakeEngine();

    const status = await runAzureStatus(deps, {
      plan: designed.plan,
      connector,
      allowWorkspaceFallback: true,
    });
    expect(status.status.healthy).toBe(true);

    const logs = await runAzureLogs(deps, {
      plan: designed.plan,
      connector,
      allowWorkspaceFallback: true,
    });
    expect(logs.lines[0]?.message).toBe("ready on 3000");

    const verify = await runAzureVerify(deps, {
      plan: designed.plan,
      connector,
      allowWorkspaceFallback: true,
    });
    expect(verify.ok).toBe(true);

    const drift = await runAzureDrift(deps, {
      plan: designed.plan,
      engine,
      githubRepo: "acme/shop",
      connector,
      allowWorkspaceFallback: true,
    });
    expect(drift.driftedFiles.length).toBeGreaterThan(0);

    const snaps = await runAzureSnapshotList(deps, {
      plan: designed.plan,
      connector,
      allowWorkspaceFallback: true,
    });
    expect(snaps).toHaveLength(1);

    const taken = await runAzureSnapshotTake(deps, {
      plan: designed.plan,
      connector,
      allowWorkspaceFallback: true,
    });
    expect(taken.id).toContain("opscrew-shop-api-prod-db");

    const drill = await runAzureRestoreDrill(deps, {
      plan: designed.plan,
      connector,
      snapshotId: "2026-11-27T11:00:00Z",
      allowWorkspaceFallback: true,
    });
    expect(drill.verified).toBe(true);
    expect(drill.cleanedUp).toBe(true);

    const rotated = await runAzureRotateSecrets(deps, {
      plan: designed.plan,
      connector,
      allowWorkspaceFallback: true,
      secrets: [{ store: "key-vault", name: "JWT-SECRET", value: "new-secret-value" }],
    });
    expect(rotated.written).toEqual(["JWT-SECRET"]);

    const advice = await runAzureAdvise(deps, {
      plan: designed.plan,
      allowWorkspaceFallback: true,
    });
    expect(advice.length).toBeGreaterThan(0);

    const retarget = await planAzureRetarget(deps, {
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
    expect(retarget.target.compute).toBe("vm-compose");

    const destroyEngine = fakeEngine({ hasDestroy: true, deleteCount: 3 });
    const destroyed = await runAzureDestroy(deps, {
      plan: designed.plan,
      engine: destroyEngine,
      allowWorkspaceFallback: true,
    });
    expect(destroyed.destroyed).toBe(true);
    expect(destroyEngine.applied).toBe(true);

    const { deps: badDeps } = await createTestDeps({ approve: true, confirmText: "wrong" });
    const badEngine = fakeEngine({ hasDestroy: true, deleteCount: 3 });
    await expect(
      runAzureDestroy(badDeps, {
        plan: designed.plan,
        engine: badEngine,
        allowWorkspaceFallback: true,
      }),
    ).rejects.toThrow(OpsCrewError);
    expect(badEngine.applied).toBe(false);
  });

  it("rejects malformed Azure plugin missing required render/design hooks", async () => {
    const { deps } = await createTestDeps();
    const incompletePlugin: ManagedCloudProviderDefinition = {
      contractVersion: 1,
      id: "azure",
      displayName: "Azure",
      packageName: "@opscrew/provider-azure",
      credentials: { envVars: [], secretPatterns: [], consoleUrl: "", instructions: "" },
      regions: [],
      presets: ["lean"],
      createConnector: () => fakeConnector(),
    };
    await expect(runAzureDesign(deps, { plugin: incompletePlugin })).rejects.toThrow(
      /missing required design\/render hooks/,
    );
  });
});
