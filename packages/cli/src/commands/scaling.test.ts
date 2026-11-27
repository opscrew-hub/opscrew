import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { recordServerAddress } from "@opscrew/agents";
import {
  figuresOutput,
  figuresRemote,
  nextPostgresFacts,
  SERVER_IPV4,
  testPlan,
} from "@opscrew/agents/testing";
import { ProjectStateStore, resolveProjectPaths } from "@opscrew/core";
import {
  type Architecture,
  DeployPlanSchema,
  readArtifact,
  writeArtifact,
} from "@opscrew/plan-schema";
import { afterEach, describe, expect, it } from "vitest";
import { parse, stringify } from "yaml";
import { withServices } from "../deps";
import { main } from "../program";
import { createTestContext } from "../test-context";
import { projectContext, run, type TempProject, tempProject } from "../ui/__fixtures__/harness";

const argv = (...args: string[]) => ["node", "opscrew", ...args];

const ANSWERS = [
  "expectedMonthlyUsers: <1k",
  "budgetMonthly: 50 EUR",
  "region: eu-central",
  "uptime: standard",
  "dataCriticality: important",
  "",
].join("\n");

let project: TempProject | undefined;
let scratchDir: string | undefined;

afterEach(async () => {
  await project?.cleanup();
  project = undefined;
  if (scratchDir !== undefined) {
    await rm(scratchDir, { recursive: true, force: true });
    scratchDir = undefined;
  }
});

describe("CLI multi-copy scaling (T3313)", () => {
  it("opscrew design preserves app.servers and scaling, allocates WireGuard, and enables PgBouncer", async () => {
    project = await tempProject("nextjs-postgres");
    await writeFile(path.join(project.dir, "answers.yaml"), ANSWERS);
    const firstCtx = projectContext(project);
    expect(await run(firstCtx, "analyze", "--no-ai")).toBe(0);
    expect(
      await run(firstCtx, "interview", "--answers", path.join(project.dir, "answers.yaml")),
    ).toBe(0);
    expect(await run(firstCtx, "design")).toBe(0);
    const option = /Chose the recommended option, ([a-z0-9-]+)\./.exec(
      firstCtx.output,
    )?.[1] as string;

    const planFile = resolveProjectPaths(project.root, { env: project.env }).files.plan;
    const raw = parse(await readFile(planFile, "utf8")) as Record<string, unknown>;
    const app = raw.app as Record<string, unknown>;
    app.servers = ["web2"];
    raw.servers = [{ name: "web2" }];
    raw.scaling = { loadBalancer: { kind: "edge", policy: "least_conn" } };
    await writeFile(planFile, stringify(raw));

    const secondCtx = projectContext(project);
    expect(await run(secondCtx, "design", "--option", option), secondCtx.errors).toBe(0);

    const plan = await readArtifact("plan", planFile);
    expect(plan.app.servers).toEqual(["web2"]);
    expect(plan.scaling).toEqual({ loadBalancer: { kind: "edge", policy: "least_conn" } });
    expect(plan.network?.members.map((m) => m.name)).toEqual(["app", "web2"]);
    const db = plan.services.find((s) => s.kind === "postgres");
    expect(db?.kind === "postgres" && db.options.pooler).toBe("pgbouncer");
    expect(`${secondCtx.output}${secondCtx.errors}`).toContain("Server web2");
    expect(`${secondCtx.output}${secondCtx.errors}`).toContain("Enabled PgBouncer");
  });

  it("opscrew status renders multi-copy web servers, load-balancer policy, worker copies, and front server label", async () => {
    scratchDir = await mkdtemp(path.join(tmpdir(), "opscrew-cli-scaling-status-"));
    const paths = resolveProjectPaths(scratchDir, { env: {} });
    const base = testPlan({ deployed: true, userSecret: false });
    const multiCopy = DeployPlanSchema.parse({
      ...base,
      app: { ...base.app, servers: ["web2"] },
      processes: {
        workers: [
          {
            name: "jobs",
            command: "node worker.js",
            source: "procfile",
            count: 1,
            single: false,
            stopGraceSeconds: 30,
            memoryMb: 256,
            enabled: true,
            servers: ["web2"],
          },
        ],
        cron: [],
      },
      servers: [
        {
          name: "web2",
          target: {
            provider: "hetzner",
            mode: "vps-compose",
            location: "nbg1",
            serverType: "cx23",
            backups: true,
          },
        },
      ],
      scaling: { loadBalancer: { kind: "edge", policy: "least_conn" } },
      network: {
        range: "10.200.4.0/24",
        members: [
          {
            name: "app",
            address: "10.200.4.1",
            port: 51820,
            publicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
          },
          {
            name: "web2",
            address: "10.200.4.2",
            port: 51820,
            publicKey: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=",
          },
        ],
      },
    });
    await writeArtifact("plan", paths.files.plan, multiCopy);
    await recordServerAddress(paths, { ipv4: SERVER_IPV4 });
    await new ProjectStateStore(paths.files.state).markPhase("provision", "ok");

    const ctx = createTestContext({ cwd: scratchDir });
    expect(await main(argv("status"), ctx)).toBe(0);
    expect(ctx.output).toContain(
      "Scaling: 2 web servers (app, web2; edge load balancer: least_conn).",
    );
    expect(ctx.output).toContain("Worker copies: jobs on app, web2.");
    expect(ctx.output).toContain(
      `Front server address (app; kept on this computer only, never in the repository):\n  ${SERVER_IPV4}\n`,
    );
  });

  it("opscrew advise surfaces scale-out blockers from architecture.json cleanly in text and JSON", async () => {
    scratchDir = await mkdtemp(path.join(tmpdir(), "opscrew-cli-scaling-advise-"));
    const paths = resolveProjectPaths(scratchDir, { env: {} });
    const base = testPlan({ deployed: true, userSecret: false });
    const ceilingPlan = DeployPlanSchema.parse({
      ...base,
      target: {
        ...base.target,
        serverType: "ccx63",
      },
    });
    await writeArtifact("plan", paths.files.plan, ceilingPlan);
    const arch: Architecture = {
      schemaVersion: 1,
      generatedAt: "2026-10-11T10:00:00.000Z",
      generator: { tool: "opscrew", version: "0.0.0-test" },
      facts: {
        ...nextPostgresFacts(),
        statelessIssues: [
          {
            kind: "local-sessions",
            framework: "express",
            file: "src/app.ts",
            evidence: "express-session MemoryStore detected",
            remediation: "Switch sessions to Valkey/Redis.",
          },
        ],
      },
      summary: "Test app",
      risks: [],
      aiEnriched: false,
    };
    await writeArtifact("architecture", paths.files.architecture, arch);
    await recordServerAddress(paths, { ipv4: SERVER_IPV4 });
    await mkdir(path.dirname(paths.files.deployKey), { recursive: true });
    await writeFile(paths.files.deployKey, "placeholder key\n");

    const remote = figuresRemote(figuresOutput("shop", { cpus: 48, load15: 60, memory: 0.5 }));
    const textCtx = createTestContext({ cwd: scratchDir });
    withServices(textCtx, { provision: { remote } });
    expect(await main(argv("advise"), textCtx)).toBe(0);
    expect(textCtx.output).toContain("[size.app.scale-out-blocked]");
    expect(textCtx.output).toContain("express-session MemoryStore detected");

    const jsonCtx = createTestContext({ cwd: scratchDir });
    withServices(jsonCtx, { provision: { remote } });
    expect(await main(argv("advise", "--json"), jsonCtx)).toBe(0);
    const parsed = JSON.parse(jsonCtx.output) as { proposals: Array<{ id: string }> };
    expect(parsed.proposals.map((p) => p.id)).toContain("size.app.scale-out-blocked");
  });
});
