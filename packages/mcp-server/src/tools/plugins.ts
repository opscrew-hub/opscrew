import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { listInstalledPlugins, OFFICIAL_PROVIDER_PLUGINS } from "@opscrew/core";
import type { ResolvedMcpDeps } from "../deps";
import { projectDirInput, runTool } from "./shared";

/**
 * `opscrew_plugins` (Feature 034, ADR 0040): read-only list of official separately-installed
 * managed-cloud provider plugins (`aws`, later `azure`, `gcp`) and whether each is installed.
 * Installing or removing plugins stays a terminal command (`npx opscrew plugin add <id>`).
 */
export function registerPluginsTool(server: McpServer, deps: ResolvedMcpDeps): void {
  server.registerTool(
    "opscrew_plugins",
    {
      title: "List managed-cloud provider plugins",
      description:
        "List official separately-installed managed-cloud provider plugins (such as AWS) and whether each is installed on this computer. Installing plugins runs in the user's terminal: `npx opscrew plugin add aws`.",
      inputSchema: { ...projectDirInput },
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    ({ projectDir }) =>
      runTool(deps, "opscrew_plugins", projectDir, async (call) => {
        const phase = await call.phaseDeps();
        const installed = await listInstalledPlugins(phase.paths.homeDir);
        const byId = new Map(installed.map((rec) => [rec.id, rec]));
        const plugins = Object.values(OFFICIAL_PROVIDER_PLUGINS).map((spec) => {
          const rec = byId.get(spec.id);
          return {
            id: spec.id,
            packageName: spec.packageName,
            version: spec.version,
            displayName: spec.displayName,
            installed: rec !== undefined,
            verifiedProvenance: rec?.verifiedProvenance ?? false,
            ...(spec.companionClaudePlugin === undefined
              ? {}
              : { companionClaudePlugin: spec.companionClaudePlugin }),
          };
        });
        const lines = plugins.map(
          (p) =>
            `${p.id} (${p.packageName}@${p.version}): ${p.installed ? "installed" : `not installed — install with \`npx opscrew plugin add ${p.id}\``}`,
        );
        return {
          text: lines.join("\n"),
          data: { plugins },
        };
      }),
  );
}
