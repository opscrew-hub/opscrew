import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { testPlan } from "@opscrew/agents/testing";
import {
  CostLedger,
  OpsCrewError,
  Redactor,
  RunReportSchema,
  resolveProjectPaths,
} from "@opscrew/core";
import { fakeSecret } from "@opscrew/core/testing";
import { DeployPlanSchema, writeArtifact } from "@opscrew/plan-schema";
import sodium from "libsodium-wrappers";
import { afterEach, describe, expect, it } from "vitest";
import { withServices } from "./deps";
import { main } from "./program";
import { checkActionsPlanFile, ReportCollector } from "./report";
import { createTestContext } from "./test-context";

async function generateKeyPair() {
  await sodium.ready;
  const kp = sodium.crypto_box_keypair();
  return {
    publicKey: sodium.to_base64(kp.publicKey, sodium.base64_variants.ORIGINAL),
    publicKeyBytes: kp.publicKey,
    privateKeyBytes: kp.privateKey,
  };
}

describe("CLI --report, sealed secrets, and Actions guard (Feature 041)", () => {
  const dirs: string[] = [];

  afterEach(async () => {
    for (const dir of dirs.splice(0)) {
      await rm(dir, { recursive: true, force: true });
    }
  });

  async function tempDir() {
    const dir = await mkdtemp(path.join(tmpdir(), "opscrew-cli-report-"));
    dirs.push(dir);
    return dir;
  }

  it("writes a valid report.json v1 on a successful read-only command", async () => {
    const dir = await tempDir();
    const reportFile = path.join(dir, "out", "report.json");
    const ctx = createTestContext({ cwd: dir });

    const code = await main(["node", "opscrew", "--report", reportFile, "providers"], ctx);
    expect(code).toBe(0);

    const report = RunReportSchema.parse(JSON.parse(await readFile(reportFile, "utf8")));
    expect(report.schemaVersion).toBe(1);
    expect(report.op).toBe("providers");
    expect(report.status).toBe("ok");
    expect(report.plans).toEqual([]);
    expect(report.secrets).toEqual([]);
    expect(report.costs).toEqual({ totalUsd: 0, byModel: [], entries: [] });
  });

  it("writes a valid failed report.json on CLI usage errors (CommanderError)", async () => {
    const dir = await tempDir();
    const reportFile = path.join(dir, "report.json");
    const ctx = createTestContext({ cwd: dir });

    const code = await main(["node", "opscrew", "--report", reportFile, "promote"], ctx);
    expect(code).toBe(2);

    const report = RunReportSchema.parse(JSON.parse(await readFile(reportFile, "utf8")));
    expect(report.status).toBe("failed");
    expect(report.failure?.code).toBe("CLI_USAGE");
    expect(report.failure?.firstLine).toContain("--to");
  });

  it("refuses local-only commands when OPSCREW_ACTIONS_RUN=1 and writes failure + nextSteps", async () => {
    const dir = await tempDir();
    const reportFile = path.join(dir, "report.json");
    const ctx = createTestContext({
      cwd: dir,
      env: { OPSCREW_ACTIONS_RUN: "1" },
    });

    const code = await main(["node", "opscrew", "--report", reportFile, "localhost", "trust"], ctx);
    expect(code).toBe(1);

    const report = RunReportSchema.parse(JSON.parse(await readFile(reportFile, "utf8")));
    expect(report.status).toBe("failed");
    expect(report.op).toBe("localhost trust");
    expect(report.failure?.code).toBe("PHASE_PRECONDITION");
    expect(report.failure?.firstLine).toContain("cannot run in GitHub Actions");
    expect(report.nextSteps[0]).toContain("npx opscrew localhost trust");
  });

  it("rejects partial or invalid sealed-secret key flags before running the command", async () => {
    const dir = await tempDir();
    const reportFile = path.join(dir, "report.json");
    const ctx = createTestContext({ cwd: dir });

    const code = await main(
      ["node", "opscrew", "--report", reportFile, "--secrets-key-id", "k1", "providers"],
      ctx,
    );
    expect(code).toBe(2);

    const report = RunReportSchema.parse(JSON.parse(await readFile(reportFile, "utf8")));
    expect(report.status).toBe("failed");
    expect(report.failure?.code).toBe("INVALID_INPUT");
  });

  it("records approvals as needs-approval, aggregates only new CostLedger entries, and seals secrets", async () => {
    const dir = await tempDir();
    const home = path.join(dir, "home");
    const reportFile = path.join(dir, "report.json");
    const paths = resolveProjectPaths(dir, { env: { OPSCREW_HOME: home } });
    await mkdir(paths.stateDir, { recursive: true });

    // Pre-existing cost entry from an earlier run (must be excluded from this run's delta).
    const ledger = new CostLedger(paths.files.costs);
    await ledger.append({
      at: "2026-11-27T08:00:00.000Z",
      phase: "analyze",
      model: "claude-sonnet-4-6",
      costUsd: 0.5,
    });

    const kp = await generateKeyPair();
    const redactor = new Redactor();
    const secretVal = fakeSecret("generic-password");
    const collector = new ReportCollector({
      filePath: reportFile,
      sealedTargets: { repo: { keyId: "repo-key-7", publicKey: kp.publicKey } },
      redactor,
      version: "0.2.13-test",
    });
    collector.setOp("provision", false);
    collector.attachCosts(paths.files.costs);

    // Simulate two new AI calls during this run.
    await ledger.append({
      at: "2026-11-27T09:00:01.000Z",
      phase: "analyze",
      model: "claude-sonnet-4-6",
      costUsd: 0.015,
    });
    await ledger.append({
      at: "2026-11-27T09:00:02.000Z",
      phase: "adapt",
      model: "claude-opus-5-5",
      costUsd: 0.03,
    });

    await collector.sealedSecrets?.seal("OPSCREW_RECOVERY_KEY", secretVal, { kind: "repo" });

    const handler = collector.wrapApprovalHandler({
      request: async () => ({
        approved: false,
        approver: "--approve flag",
        decidedAt: "2026-11-27T09:00:03.000Z",
        reason: "No plan hash approved",
      }),
    });
    await handler.request({
      kind: "iac-apply",
      title: "Create 2 resources",
      details: `Create server (never leak ${secretVal})`,
      planHash: "b".repeat(64),
      allowDestroy: true,
      confirmPhrase: "my-app",
      costDelta: { amount: 5.5, currency: "EUR" },
    });

    const finalized = await collector.finalize({
      exitCode: 1,
      error: new OpsCrewError("APPROVAL_REFUSED", "Not approved", {
        hint: "Pass --approve bbbb... and --confirm my-app.",
      }),
    });

    expect(finalized).toBeDefined();
    const raw = await readFile(reportFile, "utf8");
    expect(raw).not.toContain(secretVal);

    const parsed = RunReportSchema.parse(JSON.parse(raw));
    expect(parsed.status).toBe("needs-approval");
    expect(parsed.plans).toHaveLength(1);
    expect(parsed.plans[0]).toMatchObject({
      kind: "iac-apply",
      planHash: "b".repeat(64),
      allowDestroy: true,
      needsConfirm: true,
      confirmPhrase: "my-app",
      approved: false,
    });
    expect(parsed.costs.totalUsd).toBe(0.045);
    expect(parsed.costs.entries).toHaveLength(2);
    expect(parsed.costs.byModel).toEqual([
      { model: "claude-opus-5-5", costUsd: 0.03, calls: 1 },
      { model: "claude-sonnet-4-6", costUsd: 0.015, calls: 1 },
    ]);
    expect(parsed.secrets).toHaveLength(1);
    const firstSecret = parsed.secrets[0];
    expect(firstSecret).toBeDefined();
    const decrypted = sodium.to_string(
      sodium.crypto_box_seal_open(
        sodium.from_base64(firstSecret?.encryptedValue ?? "", sodium.base64_variants.ORIGINAL),
        kp.publicKeyBytes,
        kp.privateKeyBytes,
      ),
    );
    expect(decrypted).toBe(secretVal);
  });

  it("secrets restore --from-env refuses cleanly when OPSCREW_RECOVERY_KEY is unset and when combined with --key-file", async () => {
    const dir = await tempDir();
    const reportFile = path.join(dir, "report.json");
    const ctx1 = createTestContext({ cwd: dir, env: {} });
    const code1 = await main(
      ["node", "opscrew", "--report", reportFile, "secrets", "restore", "--from-env"],
      ctx1,
    );
    expect(code1).toBe(2);
    const rep1 = RunReportSchema.parse(JSON.parse(await readFile(reportFile, "utf8")));
    expect(rep1.failure?.firstLine).toContain("OPSCREW_RECOVERY_KEY is not set");

    const ctx2 = createTestContext({
      cwd: dir,
      env: { OPSCREW_RECOVERY_KEY: "AGE-SECRET-KEY-1TEST" },
    });
    const code2 = await main(
      ["node", "opscrew", "secrets", "restore", "--from-env", "--key-file", "key.txt"],
      ctx2,
    );
    expect(code2).toBe(2);
    expect(ctx2.errors).toContain("Use either --from-env or --key-file");
  });

  it("secrets restore --from-env never leaks OPSCREW_RECOVERY_KEY even when sops or validation fails", async () => {
    const dir = await tempDir();
    const reportFile = path.join(dir, "report.json");
    const fakeAge = "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ";
    await mkdir(path.join(dir, "opscrew"), { recursive: true });
    await writeFile(path.join(dir, "opscrew", "secrets.sops.json"), "{}");
    const ctx = withServices(
      createTestContext({ cwd: dir, env: { OPSCREW_RECOVERY_KEY: fakeAge } }),
      {},
    );

    const code = await main(
      ["node", "opscrew", "--report", reportFile, "secrets", "restore", "--from-env"],
      ctx,
    );
    expect(code).not.toBe(0);
    const raw = await readFile(reportFile, "utf8");
    expect(raw).not.toContain(fakeAge);
    expect(ctx.output).not.toContain(fakeAge);
    expect(ctx.errors).not.toContain(fakeAge);
  });

  it("refuses sealed secret keys when --report is not set so secrets cannot be silently lost", async () => {
    const dir = await tempDir();
    const kp = await generateKeyPair();
    const ctx = createTestContext({ cwd: dir });
    const code = await main(
      ["node", "opscrew", "--secrets-key-id", "k1", "--secrets-key", kp.publicKey, "providers"],
      ctx,
    );
    expect(code).toBe(2);
    expect(ctx.errors).toContain("require --report");
  });

  it("refuses plans targeting localhost or home hosting when OPSCREW_ACTIONS_RUN=1", async () => {
    const dir = await tempDir();
    const reportFile = path.join(dir, "report.json");
    const base = testPlan();
    const localhostPlan = DeployPlanSchema.parse({
      ...base,
      target: {
        provider: "localhost",
        mode: "local-compose",
        arch: "amd64",
        ports: { https: 443, http: 80 },
        image: "local-build",
        edge: "caddy",
      },
      dns: { provider: "none", proxied: false },
      cost: {
        monthly: { amount: 0, currency: "EUR" },
        breakdown: [],
        pricesIncludeVat: false,
        source: "static",
        asOf: "2026-06-15T00:00:00.000Z",
      },
    });
    await mkdir(path.join(dir, "opscrew"), { recursive: true });
    await writeArtifact("plan", path.join(dir, "opscrew", "plan.yaml"), localhostPlan);
    const ctx = createTestContext({ cwd: dir, env: { OPSCREW_ACTIONS_RUN: "1" } });
    const code = await main(["node", "opscrew", "--report", reportFile, "values", "list"], ctx);
    expect(code).toBe(1);
    const rep = RunReportSchema.parse(JSON.parse(await readFile(reportFile, "utf8")));
    expect(rep.status).toBe("failed");
    expect(rep.failure?.code).toBe("PHASE_PRECONDITION");
    expect(rep.failure?.firstLine).toContain("localhost");

    const homePlanFile = path.join(dir, "opscrew", "plan-home.yaml");
    await writeFile(
      homePlanFile,
      "schemaVersion: 1\ntarget:\n  provider: own\n  home:\n    ipv4: true\n",
    );
    expect(() => checkActionsPlanFile(homePlanFile, { OPSCREW_ACTIONS_RUN: "1" })).toThrow(
      /home server/,
    );
  });

  it("ignores corrupt pre-existing lines in costs.jsonl when computing per-run AI cost delta", async () => {
    const dir = await tempDir();
    const home = path.join(dir, "home");
    const reportFile = path.join(dir, "report.json");
    const paths = resolveProjectPaths(dir, { env: { OPSCREW_HOME: home } });
    await mkdir(paths.stateDir, { recursive: true });
    await writeFile(
      paths.files.costs,
      `${JSON.stringify({ at: "2026-11-27T08:00:00Z", phase: "analyze", costUsd: 0.5 })}\n{broken-line\n`,
    );

    const collector = new ReportCollector({
      filePath: reportFile,
      redactor: new Redactor(),
      version: "0.2.13-test",
    });
    collector.setOp("analyze");
    collector.attachCosts(paths.files.costs);

    const ledger = new CostLedger(paths.files.costs);
    await ledger.append({
      at: "2026-11-27T09:00:00Z",
      phase: "analyze",
      model: "claude-sonnet-4-6",
      costUsd: 0.02,
    });

    const rep = await collector.finalize({ exitCode: 0 });
    expect(rep?.costs.entries).toHaveLength(1);
    expect(rep?.costs.totalUsd).toBe(0.02);
  });
});
