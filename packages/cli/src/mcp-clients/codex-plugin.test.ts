import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Redactor } from "@opscrew/core";
import { fakeSecret } from "@opscrew/core/testing";
import { describe, expect, it } from "vitest";
import { CREDENTIAL_VARIABLES, codexEntry, codexTable, SERVER_NAME } from "./entry";

/** The repository's root, where the plugin's folder and the marketplace files are. */
const ROOT = fileURLToPath(new URL("../../../../", import.meta.url));

// biome-ignore lint/suspicious/noExplicitAny: the files are loosely typed JSON.
async function readJson(file: string): Promise<any> {
  return JSON.parse(await readFile(path.join(ROOT, file), "utf8"));
}

const redactor = new Redactor();

/**
 * Where `value` holds a token: a credential variable set to a value (as a key), or a string the
 * redactor would mask. Names alone, as in `env_vars`, are fine.
 */
function tokenProblems(value: unknown, where = "the file"): string[] {
  if (typeof value === "string") {
    return redactor.redact(value) === value ? [] : [`${where} looks like a token`];
  }
  if (Array.isArray(value))
    return value.flatMap((item, i) => tokenProblems(item, `${where}[${i}]`));
  if (typeof value !== "object" || value === null) return [];
  return Object.entries(value).flatMap(([key, inner]) => [
    ...(CREDENTIAL_VARIABLES.includes(key) ? [`${where}.${key} sets a credential variable`] : []),
    ...tokenProblems(inner, `${where}.${key}`),
  ]);
}

describe("the Codex plugin", () => {
  it("runs the server npx opscrew mcp writes into config.toml, at the pinned release", async () => {
    const codex = await readJson("plugin/.codex-plugin/plugin.json");
    const claude = await readJson("plugin/.claude-plugin/plugin.json");
    const pinned = (await readJson("plugin/package.json")).dependencies.opscrew;
    expect(Object.keys(codex).sort()).toEqual(
      ["description", "interface", "mcpServers", "name", "skills", "version"].sort(),
    );
    expect(codex.name).toBe(claude.name);
    expect(codex.version).toBe(claude.version);
    expect(codex.mcpServers).toEqual({ [SERVER_NAME]: codexEntry(pinned) });
    expect(codex.interface).toEqual({
      displayName: "OpsCrew",
      shortDescription: expect.any(String),
      developerName: "OpsCrew",
      category: "Developer Tools",
      websiteURL: "https://opscrew.dev",
    });
  });

  it("reads the one copy of the skills, each with a name and a description", async () => {
    const codex = await readJson("plugin/.codex-plugin/plugin.json");
    expect(codex.skills).toBe("./skills/");
    const folder = path.join(ROOT, "plugin", "skills");
    const skills = (await readdir(folder, { withFileTypes: true })).filter((e) => e.isDirectory());
    expect(skills.map((skill) => skill.name)).toContain("opscrew-deploy");
    for (const skill of skills) {
      const text = await readFile(path.join(folder, skill.name, "SKILL.md"), "utf8");
      const frontmatter = /^---\r?\n([\s\S]*?)\r?\n---\r?\n/.exec(text)?.[1] ?? "";
      expect(frontmatter, skill.name).toMatch(new RegExp(`^name: ${skill.name}\\r?$`, "m"));
      expect(frontmatter, skill.name).toMatch(/^description: \S/m);
    }
  });

  it("holds no token value anywhere, and the check finds one", async () => {
    const codex = await readJson("plugin/.codex-plugin/plugin.json");
    expect(tokenProblems(codex)).toEqual([]);
    const withValue = structuredClone(codex);
    withValue.mcpServers.opscrew.env.HCLOUD_TOKEN = fakeSecret("hcloud-token");
    expect(tokenProblems(withValue)).toEqual([
      "the file.mcpServers.opscrew.env.HCLOUD_TOKEN sets a credential variable",
    ]);
    const inText = { ...codex, description: `Use ${fakeSecret("github-token")}` };
    expect(tokenProblems(inText)).toEqual(["the file.description looks like a token"]);
  });

  it("is listed in Codex's marketplace file from ./plugin, with the name and version of Claude's", async () => {
    const codex = await readJson(".agents/plugins/marketplace.json");
    const claude = await readJson(".claude-plugin/marketplace.json");
    expect(codex.name).toBe(claude.name);
    expect(codex.interface).toEqual({ displayName: "OpsCrew" });
    const coreClaude = claude.plugins.filter(
      (plugin: { name: string }) => plugin.name === "opscrew",
    );
    expect(codex.plugins).toEqual(
      coreClaude.map((plugin: { name: string; version: string }) => ({
        name: plugin.name,
        version: plugin.version,
        source: { source: "local", path: "./plugin" },
        policy: { installation: "AVAILABLE", authentication: "ON_INSTALL" },
        category: "Developer Tools",
      })),
    );
  });

  it("matches the Codex table the guide shows", async () => {
    const guide = await readFile(path.join(ROOT, "docs", "guide", "mcp-clients.md"), "utf8");
    expect(guide.replace(/\r\n/g, "\n")).toContain(`\`\`\`toml\n${codexTable("<version>")}\`\`\``);
  });
});
