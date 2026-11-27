import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { forbiddenFetch, ScriptedRunner } from "@opscrew/agents/testing";
import { afterEach, describe, expect, it } from "vitest";
import { resolveMcpDeps } from "../deps";
import { registerPluginsTool } from "./plugins";

const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => {
  while (cleanups.length > 0) await cleanups.pop()?.();
});

const textOf = (result: CallToolResult) =>
  result.content.map((c) => (c.type === "text" ? c.text : "")).join("\n");

describe("opscrew_plugins", () => {
  it("is read-only and lists official managed-cloud provider plugins", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "opscrew-mcp-plugins-"));
    cleanups.push(() => rm(dir, { recursive: true, force: true }));
    const env = { OPSCREW_HOME: path.join(dir, "home") };
    const deps = resolveMcpDeps({
      version: "0.0.0-test",
      env,
      fetch: forbiddenFetch,
      runner: new ScriptedRunner(),
      cwd: dir,
      clock: { now: () => new Date("2026-11-27T12:00:00.000Z") },
    });
    const server = new McpServer({ name: "opscrew", version: "0.0.0-test" });
    registerPluginsTool(server, deps);
    const client = new Client({ name: "test", version: "0.0.0" });
    const [a, b] = InMemoryTransport.createLinkedPair();
    await Promise.all([server.connect(a), client.connect(b)]);
    cleanups.push(() => client.close());

    const { tools } = await client.listTools();
    const tool = tools.find((t) => t.name === "opscrew_plugins");
    expect(tool?.annotations?.readOnlyHint).toBe(true);

    const res = (await client.callTool({
      name: "opscrew_plugins",
      arguments: { projectDir: dir },
    })) as CallToolResult;
    expect(res.isError).not.toBe(true);
    expect(textOf(res)).toContain("@opscrew/provider-aws");
    expect(textOf(res)).toContain("npx opscrew plugin add aws");
    const structured = res.structuredContent as {
      plugins: Array<{ id: string; installed: boolean }>;
    };
    expect(structured.plugins.find((p) => p.id === "aws")?.installed).toBe(false);
  });
});
