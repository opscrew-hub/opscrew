import { mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { testPlan } from "@opscrew/agents/testing";
import { OpsCrewError, RunReportSchema } from "@opscrew/core";
import { writeArtifact } from "@opscrew/plan-schema";
import { afterEach, describe, expect, it, vi } from "vitest";
import { PlanOnlyApprovalHandler } from "./approval";
import { runDestroyCommand } from "./commands/destroy";
import { main } from "./program";
import { ReportCollector } from "./report";
import { createTestContext } from "./test-context";
import { refusePlanOnlyWithApprove, runApprovalPlanOnly } from "./ui/deploy";

describe("Feature 041: --plan-only parity across mutating commands", () => {
  const dirs: string[] = [];

  afterEach(async () => {
    for (const dir of dirs.splice(0)) {
      await rm(dir, { recursive: true, force: true });
    }
  });

  async function tempDir() {
    const dir = await mkdtemp(path.join(tmpdir(), "opscrew-plan-only-"));
    dirs.push(dir);
    return dir;
  }

  it("exposes --plan-only on destroy, promote, rollback, restore, rotate, retarget, secure, and values set|unset", async () => {
    const dir = await tempDir();
    const cases: string[][] = [
      ["destroy", "--help"],
      ["promote", "--help"],
      ["rollback", "--help"],
      ["restore", "--help"],
      ["rotate", "--help"],
      ["retarget", "--help"],
      ["secure", "--help"],
      ["values", "set", "--help"],
      ["values", "unset", "--help"],
    ];
    for (const args of cases) {
      const ctx = createTestContext({ cwd: dir });
      const code = await main(["node", "opscrew", ...args], ctx);
      expect(code, `help for ${args.join(" ")}`).toBe(0);
      expect(ctx.output, `${args.join(" ")} should advertise --plan-only`).toContain("--plan-only");
    }
  });

  it("refuses --plan-only paired with --approve before running", async () => {
    const hash = "a".repeat(64);
    expect(() => refusePlanOnlyWithApprove(true, hash, "opscrew promote --to prod")).toThrow(
      /Use either --plan-only or --approve/,
    );
    expect(() => refusePlanOnlyWithApprove(true, [hash], "opscrew destroy")).toThrow(
      /Use either --plan-only or --approve/,
    );

    const dir = await tempDir();
    const reportFile = path.join(dir, "report.json");
    const ctx = createTestContext({ cwd: dir });
    const code = await main(
      [
        "node",
        "opscrew",
        "--report",
        reportFile,
        "promote",
        "--to",
        "staging",
        "--plan-only",
        "--approve",
        hash,
      ],
      ctx,
    );
    expect(code).toBe(2);
    const rep = RunReportSchema.parse(JSON.parse(await readFile(reportFile, "utf8")));
    expect(rep.status).toBe("failed");
    expect(rep.failure?.code).toBe("INVALID_INPUT");
  });

  it("PlanOnlyApprovalHandler + runApprovalPlanOnly prints and records the plan, stops cleanly, and marks report needs-approval", async () => {
    const dir = await tempDir();
    const reportFile = path.join(dir, "report.json");
    const ctx = createTestContext({ cwd: dir });
    ctx.report = new ReportCollector({
      filePath: reportFile,
      redactor: ctx.redactor,
      version: ctx.version,
    });
    ctx.report.setOp("promote", true);

    const handler = ctx.report.wrapApprovalHandler(
      new PlanOnlyApprovalHandler({ print: ctx.stdout }),
    );
    const out = await runApprovalPlanOnly(ctx, true, async () => {
      const decision = await handler.request({
        kind: "promote",
        title: "Promote sha256:abc to prod",
        details: "Image digest sha256:abc",
        planHash: "c".repeat(64),
        allowDestroy: false,
      });
      if (!decision.approved) {
        throw new OpsCrewError("APPROVAL_REFUSED", decision.reason ?? "refused");
      }
      return "mutated";
    });

    expect(out).toBeUndefined();
    expect(ctx.output).toContain("Promote sha256:abc to prod");
    expect(ctx.output).toContain("Stopped after planning (--plan-only)");

    const rep = await ctx.report.finalize({ exitCode: 0 });
    expect(rep?.status).toBe("needs-approval");
    expect(rep?.plans).toHaveLength(1);
    expect(rep?.plans[0]).toMatchObject({
      kind: "promote",
      planHash: "c".repeat(64),
      approved: false,
    });
  });

  it("destroy --plan-only previews without mutating and records confirmPhrase in report.json", async () => {
    const dir = await tempDir();
    const reportFile = path.join(dir, "report.json");
    await mkdir(path.join(dir, "opscrew"), { recursive: true });
    await writeArtifact(
      "plan",
      path.join(dir, "opscrew", "plan.yaml"),
      testPlan({ deployed: true, httpAllowedFrom: "any", userSecret: false }),
    );

    const ctx = createTestContext({ cwd: dir });
    ctx.report = new ReportCollector({
      filePath: reportFile,
      redactor: ctx.redactor,
      version: ctx.version,
    });
    ctx.report.setOp("destroy", true);

    const mutateSpy = vi.fn();
    await runDestroyCommand(ctx, { planOnly: true }, async (_deps, options) => {
      const ok = await options.confirm?.({
        name: "shop-prod",
        provider: "hetzner",
        deleteProtection: true,
        resources: [
          {
            address: "hcloud_server.app",
            type: "hcloud_server",
            name: "app",
            provider: "hetzner",
            action: "delete",
          },
        ],
        snapshot: false,
        confirmPrompt: 'Type "shop-prod" to delete the Hetzner server.',
      });
      if (!ok) throw new OpsCrewError("APPROVAL_REFUSED", "not confirmed");
      mutateSpy();
      return { destroyed: [], secretsRemoved: [], remaining: [] };
    });

    expect(mutateSpy).not.toHaveBeenCalled();
    expect(ctx.output).toContain("shop-prod");
    expect(ctx.output).toContain("Stopped after planning (--plan-only)");

    const rep = await ctx.report.finalize({ exitCode: 0 });
    expect(rep?.status).toBe("needs-approval");
    expect(rep?.plans).toHaveLength(1);
    expect(rep?.plans[0]).toMatchObject({
      kind: "iac-apply",
      allowDestroy: true,
      needsConfirm: true,
      confirmPhrase: "shop-prod",
      approved: false,
    });
  });
});
