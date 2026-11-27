import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { type RunAdviseOptions, recordServerAddress } from "@opscrew/agents";
import {
  figuresOutput,
  figuresRemote,
  forbiddenFetch,
  makeRequirements,
  nextPostgresFacts,
  ScriptedRunner,
  SERVER_IPV4,
  testPlan,
} from "@opscrew/agents/testing";
import { resolveProjectPaths } from "@opscrew/core";
import { type Architecture, DeployPlanSchema, writeArtifact } from "@opscrew/plan-schema";
import { afterEach, describe, expect, it } from "vitest";
import { resolveMcpDeps } from "../deps";
import { createOpscrewMcpServer } from "../server";
import { registerAdviseTool } from "./advise";
import { registerStatusTool } from "./status";

const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => {
  while (cleanups.length > 0) await cleanups.pop()?.();
});

function textOf(result: CallToolResult): string {
  return result.content.map((c) => (c.type === "text" ? c.text : "")).join("\n");
}

describe("MCP multi-copy scaling verification (T3313)", () => {
  it("opscrew_detect surfaces statelessIssues in both text and structured facts", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "opscrew-mcp-scaling-detect-"));
    cleanups.push(() => rm(dir, { recursive: true, force: true }));
    const root = path.join(dir, "repo");
    await mkdir(path.join(root, "src"), { recursive: true });
    await writeFile(
      path.join(root, "package.json"),
      JSON.stringify({
        name: "shop",
        dependencies: { express: "^5.0.0", "express-session": "^1.18.0" },
      }),
    );
    await writeFile(
      path.join(root, "src", "server.js"),
      [
        'import express from "express";',
        'import session from "express-session";',
        "const app = express();",
        "app.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false }));",
        "app.listen(3000);",
      ].join("\n"),
    );

    const server = createOpscrewMcpServer({
      version: "0.0.0-test",
      env: { OPSCREW_HOME: path.join(dir, "home") },
      fetch: forbiddenFetch,
      runner: new ScriptedRunner(),
      cwd: root,
    });
    const client = new Client({ name: "opscrew-test", version: "0.0.0" });
    const [a, b] = InMemoryTransport.createLinkedPair();
    await Promise.all([client.connect(a), server.connect(b)]);
    cleanups.push(async () => {
      await client.close();
      await server.close();
    });

    const result = (await client.callTool({
      name: "opscrew_detect",
      arguments: {},
    })) as CallToolResult;
    expect(result.isError).toBeFalsy();
    const text = textOf(result);
    expect(text).toContain("Stateless readiness notes (for multi-server scaling):");
    expect(text).toContain("local-sessions");
    const data = result.structuredContent as { facts: { statelessIssues?: unknown[] } };
    expect(data.facts.statelessIssues?.length).toBeGreaterThan(0);
  });

  it("opscrew_select_design preserves app.servers and scaling, shows multi-server total cost, and prints warnings in text", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "opscrew-mcp-scaling-design-"));
    cleanups.push(() => rm(dir, { recursive: true, force: true }));
    const root = path.join(dir, "repo");
    await mkdir(path.join(root, "src"), { recursive: true });
    await writeFile(
      path.join(root, "package.json"),
      JSON.stringify({
        name: "shop",
        dependencies: { express: "^5.0.0", pg: "^8.12.0", "express-session": "^1.18.0" },
      }),
    );
    await writeFile(
      path.join(root, "src", "server.js"),
      [
        'import express from "express";',
        'import session from "express-session";',
        "const app = express();",
        "app.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false }));",
        "app.listen(3000);",
      ].join("\n"),
    );

    const server = createOpscrewMcpServer({
      version: "0.0.0-test",
      env: { OPSCREW_HOME: path.join(dir, "home") },
      fetch: forbiddenFetch,
      runner: new ScriptedRunner(),
      cwd: root,
    });
    const client = new Client({ name: "opscrew-test", version: "0.0.0" });
    const [a, b] = InMemoryTransport.createLinkedPair();
    await Promise.all([client.connect(a), server.connect(b)]);
    cleanups.push(async () => {
      await client.close();
      await server.close();
    });

    await client.callTool({
      name: "opscrew_save_requirements",
      arguments: {
        answers: {
          expectedMonthlyUsers: "<1k",
          budgetMonthly: "50 EUR",
          region: "eu-central",
          uptime: "standard",
          dataCriticality: "important",
          provider: "hetzner",
        },
      },
    });
    const options = (await client.callTool({
      name: "opscrew_design_options",
      arguments: {},
    })) as CallToolResult;
    const optionId = (options.structuredContent as { recommendedId: string }).recommendedId;
    expect(
      (
        (await client.callTool({
          name: "opscrew_select_design",
          arguments: { optionId },
        })) as CallToolResult
      ).isError,
    ).toBeFalsy();

    // Edit plan.yaml by hand to add a cross-region web copy + load balancer policy (no network yet).
    const planFile = path.join(root, "opscrew", "plan.yaml");
    const textBefore = await readFile(planFile, "utf8");
    const edited = `${textBefore.replace(
      /\napp:\n/,
      "\napp:\n  servers:\n    - web2\n",
    )}\nservers:\n  - name: web2\n    target:\n      provider: hetzner\n      location: hel1\nscaling:\n  loadBalancer:\n    kind: edge\n    policy: least_conn\n`;
    await writeFile(planFile, edited);

    const redesigned = (await client.callTool({
      name: "opscrew_select_design",
      arguments: { optionId },
    })) as CallToolResult;
    expect(redesigned.isError, textOf(redesigned)).toBeFalsy();
    const text = textOf(redesigned);
    expect(text).toContain("total across 2 servers");
    expect(text).toContain("Warnings:");
    expect(text).toContain("different regions");
    expect(text).toContain("local sessions");
    const data = redesigned.structuredContent as {
      plan: { app: { servers?: string[] }; scaling?: unknown };
      warnings: string[];
    };
    expect(data.plan.app.servers).toEqual(["web2"]);
    expect(data.plan.scaling).toEqual({ loadBalancer: { kind: "edge", policy: "least_conn" } });
    expect(data.warnings.some((w) => w.includes("different regions"))).toBe(true);
  });

  it("opscrew_status renders scaling summary in text and structured data for multi-copy plans", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "opscrew-mcp-scaling-status-"));
    cleanups.push(() => rm(dir, { recursive: true, force: true }));
    const env = { OPSCREW_HOME: path.join(dir, "home") };
    const paths = resolveProjectPaths(dir, { env });
    const base = testPlan({ userSecret: false });
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
      scaling: { loadBalancer: { kind: "edge", policy: "ip_hash" } },
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

    const deps = resolveMcpDeps({
      version: "0.0.0-test",
      env,
      fetch: forbiddenFetch,
      runner: new ScriptedRunner(),
      cwd: dir,
    });
    const server = new McpServer({ name: "opscrew", version: "0.0.0-test" });
    registerStatusTool(server, deps);
    const client = new Client({ name: "test", version: "0.0.0" });
    const [a, b] = InMemoryTransport.createLinkedPair();
    await Promise.all([server.connect(a), client.connect(b)]);
    cleanups.push(async () => {
      await client.close();
      await server.close();
    });

    const result = (await client.callTool({
      name: "opscrew_status",
      arguments: {},
    })) as CallToolResult;
    expect(result.isError, textOf(result)).toBeFalsy();
    const text = textOf(result);
    expect(text).toContain("Scaling: 2 web servers (app, web2; edge load balancer: ip_hash).");
    expect(text).toContain("Worker copies: jobs on app, web2.");
    const data = result.structuredContent as {
      scaling?: {
        webServers: string[];
        loadBalancer: { kind: string; policy: string };
        workerCopies: Record<string, string[]>;
      };
    };
    expect(data.scaling).toEqual({
      webServers: ["app", "web2"],
      loadBalancer: { kind: "edge", policy: "ip_hash" },
      workerCopies: { jobs: ["app", "web2"] },
    });
  });

  it("opscrew_advise renders scale-out blockers cleanly in text and structured proposals", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "opscrew-mcp-scaling-advise-"));
    cleanups.push(() => rm(dir, { recursive: true, force: true }));
    const env = { OPSCREW_HOME: path.join(dir, "home") };
    const paths = resolveProjectPaths(dir, { env });
    const base = testPlan({ deployed: true, userSecret: false });
    const ceilingPlan = DeployPlanSchema.parse({
      ...base,
      target: { ...base.target, serverType: "ccx63" },
    });
    await writeArtifact("plan", paths.files.plan, ceilingPlan);
    await writeArtifact(
      "requirements",
      paths.files.shared.requirementsBase,
      makeRequirements({ dataCriticality: "important" }),
    );
    const arch: Architecture = {
      schemaVersion: 1,
      generatedAt: "2026-10-11T10:00:00.000Z",
      generator: { tool: "opscrew", version: "0.0.0-test" },
      facts: {
        ...nextPostgresFacts(),
        statelessIssues: [
          {
            kind: "local-uploads",
            framework: "express",
            file: "src/upload.ts",
            evidence: "multer.diskStorage() writes uploads to local disk",
            remediation: "Upload to S3-compatible object storage.",
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

    const options: RunAdviseOptions = {
      services: {
        remote: figuresRemote(figuresOutput("shop", { cpus: 48, load15: 60, memory: 0.5 })),
      },
      github: {
        dependabotAlerts: async () => ({ state: "on", alerts: [] }),
        dependabotPulls: async () => [],
        issuesSince: async () => [],
        tokenExpiry: async () => undefined,
      },
      cloudflare: null,
    };
    const deps = resolveMcpDeps({
      version: "0.0.0-test",
      env,
      fetch: forbiddenFetch,
      runner: new ScriptedRunner((_command, args) =>
        args.includes("get-url")
          ? { exitCode: 0, stdout: "https://github.com/acme/shop.git\n", stderr: "" }
          : { exitCode: 1, stdout: "", stderr: "" },
      ),
      cwd: dir,
      clock: { now: () => new Date("2026-10-11T12:00:00.000Z") },
    });
    const server = new McpServer({ name: "opscrew", version: "0.0.0-test" });
    registerAdviseTool(server, deps, options);
    const client = new Client({ name: "test", version: "0.0.0" });
    const [a, b] = InMemoryTransport.createLinkedPair();
    await Promise.all([server.connect(a), client.connect(b)]);
    cleanups.push(async () => {
      await client.close();
      await server.close();
    });

    const result = (await client.callTool({
      name: "opscrew_advise",
      arguments: {},
    })) as CallToolResult;
    expect(result.isError, textOf(result)).toBeFalsy();
    const text = textOf(result);
    expect(text).toContain("[size.app.scale-out-blocked]");
    expect(text).toContain("multer.diskStorage()");
    const data = result.structuredContent as { proposals: Array<{ id: string }> };
    expect(data.proposals.map((p) => p.id)).toContain("size.app.scale-out-blocked");
  });
});
