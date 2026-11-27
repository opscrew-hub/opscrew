import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { main } from "../program";
import { createTestContext } from "../test-context";

const argv = (...args: string[]) => ["node", "opscrew", ...args];
const tempDirs: string[] = [];

afterEach(async () => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir !== undefined) await rm(dir, { recursive: true, force: true });
  }
});

async function makeTempHome(): Promise<string> {
  const dir = await mkdtemp(path.join(os.tmpdir(), "opscrew-cli-plugin-"));
  tempDirs.push(dir);
  return dir;
}

describe("opscrew plugin", () => {
  it("lists official managed-cloud provider plugins in text and --json", async () => {
    const home = await makeTempHome();
    const ctxText = createTestContext({ env: { OPSCREW_HOME: home }, cwd: home });
    expect(await main(argv("plugin", "list"), ctxText)).toBe(0);
    expect(ctxText.output).toContain("aws");
    expect(ctxText.output).toContain("@opscrew/provider-aws");
    expect(ctxText.output).toContain("not installed");

    const ctxJson = createTestContext({ env: { OPSCREW_HOME: home }, cwd: home });
    expect(await main(argv("plugin", "list", "--json"), ctxJson)).toBe(0);
    const parsed = JSON.parse(ctxJson.output) as {
      plugins: Array<{ id: string; packageName: string; installed: boolean }>;
    };
    expect(parsed.plugins.map((p) => p.id)).toContain("aws");
    expect(parsed.plugins.find((p) => p.id === "aws")?.installed).toBe(false);
  });

  it("reports cleanly when removing a plugin that is not installed and rejects unknown ids", async () => {
    const home = await makeTempHome();
    const ctxRemove = createTestContext({ env: { OPSCREW_HOME: home }, cwd: home });
    expect(await main(argv("plugin", "remove", "aws"), ctxRemove)).toBe(0);
    expect(ctxRemove.output).toContain('Provider plugin "aws" was not installed.');

    const ctxBad = createTestContext({ env: { OPSCREW_HOME: home }, cwd: home });
    expect(await main(argv("plugin", "add", "evil-third-party"), ctxBad)).not.toBe(0);
    expect(ctxBad.errors).toContain("official @opscrew/provider-* plugins");
  });
});
