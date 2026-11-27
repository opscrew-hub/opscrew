import {
  installProviderPlugin,
  listInstalledPlugins,
  OFFICIAL_PROVIDER_PLUGINS,
  removeProviderPlugin,
} from "@opscrew/core";
import type { Command } from "commander";
import type { CliContext } from "../context";
import { createPhaseDeps } from "../deps";

/**
 * `opscrew plugin list|add <id>|remove <id>` (Feature 034, ADR 0040):
 * Manages official separately-installed managed-cloud provider plugins (`aws`, later `azure`, `gcp`)
 * under `~/.opscrew/plugins/<id>` with `--ignore-scripts` and npm signature/provenance verification.
 */
export function register(program: Command, ctx: CliContext): void {
  const plugin = program
    .command("plugin")
    .description("Install, list, or remove official managed-cloud provider plugins (e.g. aws)");

  plugin
    .command("list")
    .description("List official managed-cloud provider plugins and their install status")
    .option("--json", "Print plugin status as JSON")
    .action(async (flags: { json?: boolean }) => {
      const deps = createPhaseDeps(ctx, { ai: false });
      const installed = await listInstalledPlugins(deps.paths.homeDir);
      const byId = new Map(installed.map((rec) => [rec.id, rec]));
      const rows = Object.values(OFFICIAL_PROVIDER_PLUGINS).map((spec) => {
        const rec = byId.get(spec.id);
        return {
          id: spec.id,
          packageName: spec.packageName,
          version: rec?.version ?? spec.version,
          displayName: spec.displayName,
          installed: rec !== undefined,
          verifiedProvenance: rec?.verifiedProvenance ?? false,
          ...(rec?.installedAt === undefined ? {} : { installedAt: rec.installedAt }),
          ...(spec.companionClaudePlugin === undefined
            ? {}
            : { companionClaudePlugin: spec.companionClaudePlugin }),
        };
      });
      if (flags.json === true) {
        ctx.stdout(`${JSON.stringify({ plugins: rows }, null, 2)}\n`);
        return;
      }
      for (const row of rows) {
        const state = row.installed
          ? `installed (${row.version}, ${row.verifiedProvenance ? "provenance verified" : "UNVERIFIED"})`
          : "not installed";
        ctx.stdout(`${row.id.padEnd(8)}  ${row.packageName.padEnd(24)}  ${state}\n`);
      }
    });

  plugin
    .command("add <id>")
    .description(
      "Install an official managed-cloud provider plugin (e.g. `opscrew plugin add aws`)",
    )
    .action(async (id: string) => {
      const deps = createPhaseDeps(ctx, { ai: false });
      const record = await installProviderPlugin(id, {
        homeDir: deps.paths.homeDir,
        runner: deps.runner,
        reporter: deps.reporter,
        env: deps.env,
        now: () => deps.clock.now(),
      });
      ctx.stdout(
        `Installed ${record.packageName}@${record.version} into ${record.installDir} (provenance verified).\n`,
      );
    });

  plugin
    .command("remove <id>")
    .description("Remove an installed managed-cloud provider plugin")
    .action(async (id: string) => {
      const deps = createPhaseDeps(ctx, { ai: false });
      const removed = await removeProviderPlugin(id, deps.paths.homeDir);
      ctx.stdout(
        removed
          ? `Removed provider plugin "${id}".\n`
          : `Provider plugin "${id}" was not installed.\n`,
      );
    });
}
