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
  planAwsRetarget,
  runAwsAdvise,
  runAwsDesign,
  runAwsDestroy,
  runAwsDrift,
  runAwsLogs,
  runAwsProvision,
  runAwsRestoreDrill,
  runAwsRotateSecrets,
  runAwsSnapshotList,
  runAwsSnapshotTake,
  runAwsStatus,
  runAwsVerify,
} from "./index";

const PLAN_HASH = "a".repeat(64);
const DESTROY_HASH = "b".repeat(64);

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
    provider: "aws",
    region: "us-east",
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
  const root = await mkdtemp(path.join(os.tmpdir(), "opscrew-aws-agent-"));
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
      accountId: "123456789012",
      principalArn: "arn:aws:iam::123456789012:user/tester",
    })),
    readStatus: vi.fn(async () => ({
      healthy: true,
      region: "us-east-1",
      accountId: "123456789012",
      compute: {
        kind: "ecs-fargate",
        status: "ACTIVE",
        desiredCount: 2,
        runningCount: 2,
        endpoint: "https://shop.example.com",
      },
      services: [{ name: "postgres", service: "rds-postgres", status: "available" }],
      alarms: [{ name: "shop-api-5xx", state: "OK" as const }],
    })),
    readLogs: vi.fn(async () => [
      { timestamp: "2026-11-27T12:00:00.000Z", stream: "ecs/web/1", message: "ready on 3000" },
    ]),
    writeSecrets: vi.fn(async ({ secrets }: { secrets: readonly ManagedCloudSecretWrite[] }) => ({
      written: secrets.map((s) => s.name),
    })),
    listSnapshots: vi.fn(async () => [
      {
        id: "shop-api-prod-20261127",
        service: "rds-postgres",
        engine: "postgres",
        createdAt: "2026-11-27T11:00:00.000Z",
        status: "available",
        sizeGb: 20,
      },
    ]),
    takeSnapshot: vi.fn(async ({ snapshotId, service }) => ({
      id: snapshotId,
      service,
      engine: "postgres",
      createdAt: "2026-11-27T12:00:00.000Z",
      status: "creating",
    })),
    runRestoreDrill: vi.fn(async ({ snapshotId, service }) => ({
      snapshotId,
      service,
      verified: true,
      durationMs: 420,
      cleanedUp: true,
      detail: "Restored into isolated private instance and deleted cleanly.",
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
        changes: destroy
          ? [
              {
                address: "aws_vpc.main",
                type: "aws_vpc",
                name: "main",
                provider: "registry.opentofu.org/hashicorp/aws",
                action: "delete",
              },
            ]
          : [
              {
                address: "aws_vpc.main",
                type: "aws_vpc",
                name: "main",
                provider: "registry.opentofu.org/hashicorp/aws",
                action: "create",
              },
            ],
        counts: { create: destroy ? 0 : 1, update: 0, delete: deleteCount, replace: 0 },
        hasDestroy: destroy,
        planJson: options?.planJson ?? {
          resource_changes: [
            {
              address: "aws_cloudwatch_log_group.app",
              type: "aws_cloudwatch_log_group",
              change: { actions: ["create"], after: { retention_in_days: 30 } },
            },
          ],
        },
      };
    }),
    apply: vi.fn(async (): Promise<IacApplyResult> => {
      engine.applied = true;
      engine.applyCalls += 1;
      return {
        ok: true,
        outputs: options?.outputs ?? {},
        log: "Apply complete!",
      };
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

describe("AWS core phase orchestration (Feature 034 T3408 & T3409)", () => {
  it("designs AWS presets, applies --set overrides, and persists validated plan.yaml", async () => {
    const { deps } = await createTestDeps();
    const res = await runAwsDesign(deps, {
      optionId: "aws-balanced",
      setFlags: ["compute.service=ec2-compose"],
    });
    expect(res.options.map((o) => o.id)).toEqual(["aws-lean", "aws-balanced", "aws-production-ha"]);
    expect(res.target.provider).toBe("aws");
    expect(res.target.compute).toBe("ec2-compose");
    expect(res.appliedOverrides).toHaveLength(1);
    expect(res.plan.target.provider).toBe("aws");
    const saved = await readFile(deps.paths.files.plan, "utf8");
    expect(saved).toContain("provider: aws");
    expect(saved).toContain("ec2-compose");
  });

  it("blocks AWS provision when SecOps policy detects an unsafe resource (never asks approval or applies)", async () => {
    const { deps, audit } = await createTestDeps();
    const designed = await runAwsDesign(deps, { optionId: "aws-balanced" });
    const engine = fakeEngine({
      planJson: {
        planned_values: {
          root_module: {
            resources: [
              {
                address: "aws_db_instance.main",
                mode: "managed",
                type: "aws_db_instance",
                values: { publicly_accessible: true, storage_encrypted: false },
              },
            ],
          },
        },
        resource_changes: [
          {
            address: "aws_db_instance.main",
            type: "aws_db_instance",
            change: {
              actions: ["create"],
              after: { publicly_accessible: true, storage_encrypted: false },
            },
          },
        ],
      },
    });
    const connector = fakeConnector();

    await expect(
      runAwsProvision(deps, {
        plan: designed.plan,
        engine,
        githubRepo: "acme/shop",
        connector,
      }),
    ).rejects.toThrow(/Blocked AWS plan due to/);

    expect(engine.applied).toBe(false);
    expect(audit.entries.some((e) => e.kind === "iac" && e.decision === "refused")).toBe(true);
  });

  it("provisions with hash-bound approval, writes secrets out-of-band without leaking values, and wires Cloudflare ACM proxied=false", async () => {
    const { deps, audit, root } = await createTestDeps();
    const designed = await runAwsDesign(deps, { optionId: "aws-balanced" });
    const engine = fakeEngine({
      outputs: {
        acm_validation_records: [
          { name: "_abc.shop.example.com", value: "_xyz.acm-validations.aws." },
        ],
      },
    });
    const connector = fakeConnector();
    const cloudflareRecords: unknown[] = [];

    const result = await runAwsProvision(deps, {
      plan: designed.plan,
      engine,
      githubRepo: "acme/shop",
      connector,
      secrets: [
        {
          store: "secrets-manager",
          name: "/opscrew/shop-api/prod/APP_SECRET",
          value: "super-secret-value-xyz",
        },
      ],
      cloudflare: {
        upsertDnsRecord: async (rec) => {
          cloudflareRecords.push(rec);
        },
      },
    });

    expect(result.applied).toBe(true);
    expect(result.renderedFiles.some((f) => f.endsWith("providers.tf"))).toBe(true);
    expect(result.renderedFiles.some((f) => f.endsWith("opscrew-deploy.yml"))).toBe(true);
    expect(result.writtenSecretNames).toEqual(["/opscrew/shop-api/prod/APP_SECRET"]);
    expect(result.acmRecordsWired).toEqual([
      {
        name: "_abc.shop.example.com",
        content: "_xyz.acm-validations.aws.",
        proxied: false,
      },
    ]);
    expect(cloudflareRecords).toHaveLength(1);

    // Ensure secret value NEVER appears in audit log or rendered HCL!
    const allAudit = JSON.stringify(audit.entries);
    expect(allAudit).not.toContain("super-secret-value-xyz");
    const secretsTf = await readFile(
      path.join(root, designed.plan.infra.dir, "secrets.tf"),
      "utf8",
    );
    expect(secretsTf).not.toContain("super-secret-value-xyz");
  });

  it("runs status, logs, verify, drift, snapshot list/take/drill, rotate, advise, and retarget", async () => {
    const { deps } = await createTestDeps();
    const designed = await runAwsDesign(deps, { optionId: "aws-balanced" });
    const connector = fakeConnector();
    const engine = fakeEngine();

    const status = await runAwsStatus(deps, { plan: designed.plan, connector });
    expect(status.status.healthy).toBe(true);
    expect(status.lines.some((l) => l.includes("ecs-fargate"))).toBe(true);

    const logs = await runAwsLogs(deps, { plan: designed.plan, connector });
    expect(logs.logGroup).toBe("/opscrew/shop-api/prod");
    expect(logs.lines[0]?.message).toBe("ready on 3000");

    const verify = await runAwsVerify(deps, { plan: designed.plan, connector });
    expect(verify.ok).toBe(true);

    const drift = await runAwsDrift(deps, {
      plan: designed.plan,
      engine,
      githubRepo: "acme/shop",
      connector,
    });
    expect(drift.driftedFiles.length).toBeGreaterThan(0);

    const snaps = await runAwsSnapshotList(deps, { plan: designed.plan, connector });
    expect(snaps).toHaveLength(1);

    const taken = await runAwsSnapshotTake(deps, { plan: designed.plan, connector });
    expect(taken.id).toContain("shop-api-prod");

    const drill = await runAwsRestoreDrill(deps, {
      plan: designed.plan,
      connector,
      snapshotId: "shop-api-prod-20261127",
    });
    expect(drill.verified).toBe(true);
    expect(drill.cleanedUp).toBe(true);

    const rotated = await runAwsRotateSecrets(deps, {
      plan: designed.plan,
      connector,
      secrets: [
        { store: "ssm-parameter", name: "/opscrew/shop-api/prod/JWT", value: "new-secret-123" },
      ],
    });
    expect(rotated.written).toEqual(["/opscrew/shop-api/prod/JWT"]);

    const advice = await runAwsAdvise(deps, { plan: designed.plan });
    expect(advice.length).toBeGreaterThan(0);

    const retarget = await planAwsRetarget(deps, {
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
    expect(retarget.target.compute).toBe("ec2-compose");
    expect(retarget.steps.length).toBeGreaterThanOrEqual(4);
  });

  it("refuses AWS destroy without matching typed confirmation and succeeds when confirmed", async () => {
    const { deps: badDeps } = await createTestDeps({ approve: true, confirmText: "wrong-name" });
    const designed = await runAwsDesign(badDeps, { optionId: "aws-lean" });
    const engine1 = fakeEngine({ hasDestroy: true, deleteCount: 4 });

    await expect(runAwsDestroy(badDeps, { plan: designed.plan, engine: engine1 })).rejects.toThrow(
      OpsCrewError,
    );
    expect(engine1.applied).toBe(false);

    const { deps: goodDeps } = await createTestDeps({
      approve: true,
      confirmText: designed.plan.app.name,
    });
    const engine2 = fakeEngine({ hasDestroy: true, deleteCount: 4 });
    const destroyed = await runAwsDestroy(goodDeps, { plan: designed.plan, engine: engine2 });
    expect(destroyed.destroyed).toBe(true);
    expect(engine2.applied).toBe(true);
  });

  it("rejects malformed plugin missing required render/design hooks", async () => {
    const { deps } = await createTestDeps();
    const incompletePlugin: ManagedCloudProviderDefinition = {
      contractVersion: 1,
      id: "aws",
      displayName: "AWS",
      packageName: "@opscrew/provider-aws",
      credentials: { envVars: [], secretPatterns: [], consoleUrl: "", instructions: "" },
      regions: [],
      presets: ["lean"],
      createConnector: () => fakeConnector(),
    };
    await expect(runAwsDesign(deps, { plugin: incompletePlugin })).rejects.toThrow(
      /missing required design\/render hooks/,
    );
  });
});
