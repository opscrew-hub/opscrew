import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { ScriptedRunner } from "@opscrew/agents/testing";
import { describe, expect, it } from "vitest";
import { createOpscrewMcpServer } from "./server";

/**
 * A client without MCP tool search loads every tool definition into every session, so the list
 * has a budget (issue #9): about 10,000 tokens at four characters a token.
 */
const TOOL_LIST_BUDGET = 40_000;

/** No tool may be removed to meet the budget. */
const TOOL_COUNT = 44;

describe("tools/list", () => {
  it(`stays under ${TOOL_LIST_BUDGET} characters with every tool listed`, async () => {
    const server = createOpscrewMcpServer({
      version: "0.0.0-test",
      env: {},
      fetch: async () => {
        throw new Error("no network in this test");
      },
      runner: new ScriptedRunner(),
      cwd: process.cwd(),
    });
    const client = new Client({ name: "opscrew-test", version: "0.0.0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await Promise.all([client.connect(clientTransport), server.connect(serverTransport)]);
    try {
      const { tools } = await client.listTools();
      const total = JSON.stringify(tools).length;
      const descriptions = tools.reduce((sum, t) => sum + (t.description?.length ?? 0), 0);
      const inputSchemas = tools.reduce((sum, t) => sum + JSON.stringify(t.inputSchema).length, 0);
      const instructions = client.getInstructions()?.length ?? 0;
      console.info(
        `tools/list: ${tools.length} tools, ${total} characters (descriptions ${descriptions}, input schemas ${inputSchemas}); instructions ${instructions}`,
      );
      expect(tools).toHaveLength(TOOL_COUNT);
      expect(total).toBeLessThanOrEqual(TOOL_LIST_BUDGET);
    } finally {
      await client.close();
      await server.close();
    }
  });
});
