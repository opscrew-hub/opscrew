import { drillSnapshot, restoreServerSnapshot, restoreSnapshot } from "@opscrew/agents";
import type { ApprovalHandler, Clock } from "@opscrew/contracts";
import { isPlanHash, OpsCrewError } from "@opscrew/core";
import { CLOUD_PROVIDERS } from "@opscrew/providers";
import { type Command, Option } from "commander";
import { FlagConfirmation } from "../approval";
import type { CliContext } from "../context";
import { createPhaseDeps, servicesOf } from "../deps";
import { CliExit, REFUSED_EXIT_CODE } from "../exit";
import { quietReporter } from "../reporter";
import { refusePlanOnlyWithApprove, runApprovalPlanOnly } from "../ui/deploy";
import { type AppEnvFlags, addEnvOption, chooseEnvironment, givenFlags } from "../ui/environment";
import { printNextSteps } from "../ui/output";
import { skipOtherAppsOption } from "./provision";
import { readKeyFile } from "./secrets";

interface RestoreFlags extends AppEnvFlags {
  planOnly?: boolean;
  /** `--server`: rebuild the server from a whole-server snapshot at its provider. */
  server?: boolean;
  /** `--only <service>`: the one service put back. */
  only?: string;
  /** `--allow-other-version`: put back the data of a snapshot another version took. */
  allowOtherVersion?: boolean;
  /** `--from offsite`: the copy off the server, in its bucket or SFTP folder. */
  from?: "offsite";
  /** `--key-file <path>`: the age key file that opens the off-server copies. */
  keyFile?: string;
  /** `--confirm <name>`: in a script, the name typed to approve the restore. */
  confirm?: string;
  /** `--approve <hash>`: in a script, the restore's hash an earlier run showed. */
  approve?: string;
  /** `--drill`: restore the snapshot into a throwaway copy to prove it, never the app's data. */
  drill?: boolean;
  /** `--keep`: with --drill, the copy stays for inspection. */
  keep?: boolean;
  /** `--remove`: with --drill, a kept copy goes. */
  remove?: boolean;
  /** `--json`: with --drill, the drill's report as JSON. */
  json?: boolean;
  /** `--skip-other-apps-check`: with --server, go on without the look for other apps there. */
  skipOtherAppsCheck?: boolean;
}

/**
 * Refuses a drill's flags that don't go together, before any work (exit code 2): `--drill` takes
 * no `--server`, `--from` or `--key-file` (a drill restores the snapshot where it is), and
 * `--remove` nothing but itself; `--keep`, `--remove` and `--json` need `--drill`.
 */
function checkDrillFlags(flags: RestoreFlags, id: string | undefined, given: string): void {
  const drill = `opscrew restore --drill${id === undefined ? "" : ` ${id}`}`;
  const needDrill = [
    [flags.keep === true, "--keep"],
    [flags.remove === true, "--remove"],
    [flags.json === true, "--json"],
  ] as const;
  const without = needDrill.filter(([set]) => set).map(([, name]) => name);
  if (flags.drill !== true) {
    if (without.length === 0) return;
    throw new OpsCrewError(
      "INVALID_INPUT",
      `${without.join(", ")} ${without.length === 1 ? "goes" : "go"} only with --drill.`,
      {
        hint: `Run \`${drill} ${without.join(" ")}${given}\`.`,
      },
    );
  }
  if (flags.server === true || flags.from !== undefined || flags.keyFile !== undefined) {
    throw new OpsCrewError(
      "INVALID_INPUT",
      "--drill restores the snapshot where it is, into a throwaway copy, so it takes no --server, --from or --key-file.",
      { hint: `Run \`${drill}${given}\` without them.` },
    );
  }
  if (flags.remove !== true) return;
  const extra = [
    [id !== undefined, "snapshot id"],
    [flags.only !== undefined, "--only"],
    [flags.keep === true, "--keep"],
    [flags.allowOtherVersion === true, "--allow-other-version"],
  ] as const;
  const named = extra.filter(([set]) => set).map(([, name]) => name);
  if (named.length === 0) return;
  throw new OpsCrewError(
    "INVALID_INPUT",
    `--drill --remove takes no ${named.join(", ")}: it removes the drill's kept copy, whichever snapshot it holds.`,
    { hint: `Run \`opscrew restore --drill --remove${given}\`.` },
  );
}

/**
 * Refuses flags that don't go together, before any work (exit code 2), and returns the trimmed
 * `--approve` hash. `given` holds the `--app`/`--env` flags the user gave, for the hints. Only a
 * drill goes without the snapshot's id (then the latest).
 */
function checkFlags(
  flags: RestoreFlags,
  raw: string | undefined,
  given: string,
): string | undefined {
  checkDrillFlags(flags, raw, given);
  const drill = flags.drill === true;
  if (raw === undefined && !drill) {
    throw new OpsCrewError("INVALID_INPUT", "opscrew restore needs the snapshot's id.", {
      hint: `\`opscrew snapshot list${given}\` shows the snapshots and their ids; \`opscrew restore --drill${given}\` drills the latest.`,
    });
  }
  const id = raw ?? "";
  const command = drill
    ? `opscrew restore --drill${raw === undefined ? "" : ` ${raw}`}${given}`
    : `opscrew restore${flags.server === true ? " --server" : ""} ${id}${given}`;
  const what = drill ? "drill" : "restore";
  const approve = flags.approve?.trim();
  if (approve !== undefined && !isPlanHash(approve)) {
    throw new OpsCrewError(
      "INVALID_INPUT",
      `--approve expects the 64-character SHA-256 ${what} hash an earlier run showed.`,
      { hint: `Run \`${command}\` to see the ${what} and its hash.` },
    );
  }
  if (flags.skipOtherAppsCheck === true && flags.server !== true) {
    throw new OpsCrewError(
      "INVALID_INPUT",
      "--skip-other-apps-check goes only with --server: of the restores, only rebuilding the whole server can break other apps on it.",
      { hint: `Run \`${command}\` without it.` },
    );
  }
  if (drill) return approve;
  const data = [
    [flags.only !== undefined, "--only"],
    [flags.allowOtherVersion === true, "--allow-other-version"],
    [flags.from !== undefined, "--from"],
    [flags.keyFile !== undefined, "--key-file"],
  ] as const;
  const extra = data.filter(([set]) => set).map(([, name]) => name);
  if (flags.server === true && extra.length > 0) {
    throw new OpsCrewError(
      "INVALID_INPUT",
      `--server takes no ${extra.join(", ")}: the provider rebuilds the whole server from its snapshot.`,
      {
        hint: `Run \`${command}\` without them, or leave --server out to put a snapshot's data back.`,
      },
    );
  }
  if (flags.keyFile !== undefined && flags.from === undefined) {
    throw new OpsCrewError(
      "INVALID_INPUT",
      "--key-file goes only with --from offsite: it opens the encrypted copy off the server.",
      {
        hint: `Run \`${command} --from offsite --key-file <path>\`, or \`${command}\` without --key-file.`,
      },
    );
  }
  if (flags.from === "offsite" && flags.keyFile === undefined) {
    throw new OpsCrewError(
      "INVALID_INPUT",
      "--from offsite needs --key-file <path>: the age key file that opens the encrypted copy.",
      { hint: `Run \`${command} --from offsite --key-file <path>\`.` },
    );
  }
  return approve;
}

/**
 * The run's approvals: a restore loses data, so it is destroy-grade. In a terminal the name is
 * typed; in a script `--confirm <name>` approves it only with `--approve` and its hash, and the
 * request (what is lost, and its hash) is shown first, as is any request refused. `--yes` never
 * approves it.
 */
function restoreApprovals(
  ctx: CliContext,
  confirm: string | undefined,
  approve: string | undefined,
): (base: ApprovalHandler, clock: Clock) => ApprovalHandler {
  return (base, clock) =>
    new FlagConfirmation(base, {
      // A Portainer's drill asks as a stack plan by its hash; every other restore and drill as a
      // command on the machine.
      kinds: ["remote-exec", "stack-apply"],
      what: "a restore",
      names: confirm === undefined ? [] : [confirm],
      hashes: approve === undefined ? [] : [approve],
      interactive: ctx.isInteractive,
      print: ctx.stdout,
      clock,
      showInScript: true,
    });
}

/** The command's line in `opscrew --help`, and the first line of its own help. */
const SUMMARY =
  "Put a snapshot's data back in an environment without changing the version that runs, with --drill prove it restores in a throwaway copy, or with --server rebuild a server from its whole-server snapshot";

/**
 * `opscrew restore` (feature 024, US3, US4, US6), through the agents' restores:
 * - `opscrew restore <id> [--only <service>] [--allow-other-version] [--from offsite
 *   --key-file <path>]`: the snapshot's data put back where it lives, the version that runs unchanged; a
 *   snapshot of another version is refused unless `--allow-other-version`.
 * - `opscrew restore --server <id>`: the provider rebuilds the server from its whole-server
 *   snapshot in place; OpsCrew then checks the app answers.
 * - `opscrew restore --drill [<id>] [--only <service>] [--keep] [--allow-other-version] [--json]`
 *   (029 US7): the snapshot, the latest by default, restored into a throwaway copy where it is,
 *   with no internet and none of the production `.env`, the app started on it and checked, then
 *   the copy removed; `opscrew restore --drill --remove` removes a kept copy.
 * Destroy-grade: a terminal asks for the name (the app's, with `--server` the server's, with
 * `--drill` `<app>-drill`); a script gives `--confirm <name>` and `--approve <hash>`, which an
 * earlier run showed; `--yes` never approves it. Exit codes: 0 restored (a drill healthy, or its
 * copy removed), 1 refused, not approved, or a drill that did not end healthy, 2 error.
 */
export function register(program: Command, ctx: CliContext): void {
  const command = program
    .command("restore")
    .summary(SUMMARY)
    .description(
      [
        SUMMARY,
        "",
        "Everything written since the snapshot is lost, so you approve it as a destroy: by typing",
        "the app's name (with --server, the server's); in a script, --confirm <name> with",
        "--approve <hash>. A copy of the data as it is now is taken first and put back if the",
        "restore fails.",
        "",
        "With --drill, the snapshot is restored into a throwaway copy where it is, with no",
        "internet, no published port and none of your production .env; the app starts on it and",
        "is checked, then the copy goes. You approve it by typing <app>-drill.",
      ].join("\n"),
    )
    .argument(
      "[id]",
      "The snapshot's id, as `opscrew snapshot list` shows it (with --drill, the latest by default)",
    )
    .option("--only <service>", "Put back only this service's data")
    .option(
      "--allow-other-version",
      "Put back the data alone of a snapshot taken while another version ran (the version that runs stays)",
    )
    .addOption(
      new Option(
        "--from <where>",
        "offsite: restore the encrypted copy off the server (in its bucket or SFTP folder), decrypted on this computer",
      ).choices(["offsite"]),
    )
    .option(
      "--key-file <path>",
      "With --from offsite: the file with your age key, which opens the copy",
    )
    .option(
      "--server",
      `Rebuild the server from this whole-server snapshot at its provider (${CLOUD_PROVIDERS.map((provider) => provider.name).join(", ")})`,
    )
    .option(
      "--drill",
      "Prove the snapshot restores: restore it into a throwaway copy with no internet, start the app on it and check it, then remove the copy",
    )
    .option("--keep", "With --drill: keep the copy for you to look at")
    .option("--remove", "With --drill: remove a copy kept with --keep")
    .option("--json", "With --drill: print the drill's report as JSON")
    .option(
      "--confirm <name>",
      "In a script, with --approve: the app's name (with --server, the server's; with --drill, <app>-drill), typed to approve it",
    )
    .option(
      "--plan-only",
      "Show the restore plan, its hash, and required --confirm name without changing anything",
    )
    .option(
      "--approve <hash>",
      "In a script: restore exactly as the restore with this hash, which an earlier run showed",
    )
    .addOption(skipOtherAppsOption("With --server"));
  addEnvOption(command)
    .addHelpText(
      "after",
      [
        "",
        "  opscrew snapshot list                         the snapshots and their ids",
        "  opscrew restore <id>                          put a snapshot's data back",
        "  opscrew restore <id> --only db                only the service db",
        "  opscrew restore <id> --from offsite --key-file <path>   from the copy off the server",
        "  opscrew restore --server <id>                 rebuild the server from it",
        "  opscrew restore --drill                       prove the latest snapshot restores",
        "  opscrew restore --drill --remove              remove a copy kept with --keep",
      ].join("\n"),
    )
    .action(async (raw: string | undefined, flags: RestoreFlags) => {
      const trimmed = raw?.trim();
      const given = givenFlags(flags);
      const approve = checkFlags(flags, trimmed, given);
      refusePlanOnlyWithApprove(flags.planOnly, approve, `opscrew restore${given}`);
      const id = trimmed ?? "";
      const json = flags.json === true;
      const { app, name, flag } = await chooseEnvironment(ctx, flags, "restore");
      const deps = createPhaseDeps(ctx, {
        ai: false,
        app,
        environment: name,
        ...(flags.planOnly === true ? { planOnly: true } : {}),
        wrapApprovals: restoreApprovals(ctx, flags.confirm?.trim(), approve),
        // Progress is dropped for `--json`, so stdout holds only the report; problems go to stderr.
        ...(json ? { reporter: quietReporter(ctx.reporter) } : {}),
      });
      const services = servicesOf(ctx).snapshot;
      const withServices = services === undefined ? {} : { services };
      if (flags.drill === true) {
        const only = flags.only?.trim();
        const report = await runApprovalPlanOnly(ctx, flags.planOnly, () =>
          drillSnapshot(deps, trimmed, {
            ...(only === undefined ? {} : { only }),
            ...(flags.keep === true ? { keep: true } : {}),
            ...(flags.remove === true ? { remove: true } : {}),
            ...(flags.allowOtherVersion === true ? { allowOtherVersion: true } : {}),
            ...withServices,
          }),
        );
        if (report === undefined) return;
        if (json) ctx.stdout(`${JSON.stringify(report, null, 2)}\n`);
        if (!["healthy", "removed", "none"].includes(report.outcome)) {
          throw new CliExit(REFUSED_EXIT_CODE);
        }
        return;
      }
      if (flags.server === true) {
        const restored = await runApprovalPlanOnly(ctx, flags.planOnly, () =>
          restoreServerSnapshot(deps, id, {
            ...withServices,
            ...(flags.skipOtherAppsCheck === true ? { skipOtherAppsCheck: true } : {}),
          }),
        );
        if (restored === undefined) return;
        if (!restored.checked) {
          printNextSteps(ctx, [`run \`opscrew verify${flag}\` to check the app.`]);
        }
        return;
      }
      const only = flags.only?.trim();
      const identity =
        flags.keyFile === undefined ? undefined : await readKeyFile(ctx, flags.keyFile);
      const restored = await runApprovalPlanOnly(ctx, flags.planOnly, async () => {
        await restoreSnapshot(deps, id, {
          ...(only === undefined ? {} : { only }),
          ...(flags.allowOtherVersion === true ? { allowOtherVersion: true } : {}),
          ...(flags.from === undefined ? {} : { from: flags.from }),
          ...(identity === undefined ? {} : { identity }),
          ...withServices,
        });
        return true;
      });
      if (restored === undefined) return;
      printNextSteps(ctx, [`run \`opscrew verify${flag}\` to check the app.`]);
    });
}
