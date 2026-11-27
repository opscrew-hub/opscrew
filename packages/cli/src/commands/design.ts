import {
  commandFlags,
  inspectOwnServerForDesign,
  type OwnServerDesignInput,
  readEnvironmentRequirements,
  runDesign,
} from "@opscrew/agents";
import type { Money, Requirements } from "@opscrew/plan-schema";
import type { Command } from "commander";
import type { CliContext } from "../context";
import { createPhaseDeps, promptsOf, servicesOf } from "../deps";
import { addEnvOption, chooseEnvironment } from "../ui/environment";
import { chooseOption } from "../ui/options";
import { askQuestions } from "../ui/questions";
import { addHostKeyOption, checkApproveFlags } from "./provision";

interface DesignFlags {
  option?: string;
  set?: string[];
  hostKey?: string;
  /** `--app <key>`: the repository's app. */
  app?: string;
  /** `--env <name>`: the app's environment (one `opscrew env add` added, or prod). */
  env?: string;
}

/**
 * `opscrew design`: prices 2–3 options on the provider chosen in the interview (live when its API
 * token is set, otherwise its dated static price table), lets the user pick one in the terminal (or takes `--option <id>`, or the
 * recommendation when no terminal is available) and writes `opscrew/plan.yaml` (FR-107). For a
 * server the user already owns it first connects (the host key confirmed in the terminal, or
 * `--host-key`, and pinned) and inspects the server read-only, then offers it as the one option,
 * without a price (FR-913). `--env` designs another environment again, from its own answers over
 * prod's. A service placed on an extra server of the user's that this computer has no login for
 * asks for that server's address and SSH login once in a terminal (feature 018).
 */
export function register(program: Command, ctx: CliContext): void {
  const command = program
    .command("design")
    .description("Design the production architecture and estimate its monthly cost")
    .option("--option <id>", "Choose this option without asking (ids are listed by the command)")
    .option(
      "--set <override>",
      "Override a managed-cloud component setting (e.g. compute.service=ec2-compose); repeatable",
      (value: string, previous: string[]) => [...previous, value],
      [] as string[],
    );
  addEnvOption(command);
  addHostKeyOption(command).action(async (flags: DesignFlags) => {
    checkApproveFlags("design", flags);
    const { app, name, flag } = await chooseEnvironment(ctx, flags, "design", { allowNew: true });
    const deps = createPhaseDeps(ctx, { ai: false, app, environment: name });
    const optionId = flags.option?.trim() || undefined;
    const interactive = optionId === undefined && ctx.isInteractive;

    const requirements: Requirements | undefined = await readEnvironmentRequirements(
      deps.paths,
    ).catch(() => undefined);
    const budget: Money | undefined = interactive ? requirements?.budgetMonthly : undefined;
    let ownServer: OwnServerDesignInput | undefined;
    if (requirements?.provider === "own") {
      const hostKey = flags.hostKey?.trim();
      const own = servicesOf(ctx).provision?.own;
      ownServer = await inspectOwnServerForDesign(deps, {
        ...(hostKey === undefined ? {} : { hostKey }),
        ...(own === undefined ? {} : { services: own }),
      });
    }
    const prompts = promptsOf(ctx);
    const extraServers = servicesOf(ctx).provision?.own;
    const setFlags = flags.set?.map((s) => s.trim()).filter((s) => s.length > 0);
    const result = await runDesign(deps, {
      ...(optionId === undefined ? {} : { optionId }),
      ...(setFlags !== undefined && setFlags.length > 0 ? { setFlags } : {}),
      ...(ownServer === undefined ? {} : { ownServer }),
      // An extra server of the user's that this computer has no login for: asked once.
      ...(ctx.isInteractive
        ? {
            askServerLogin: (_server, questions) =>
              askQuestions(questions, {
                prompts,
                cancel: { what: "the design", rerun: `opscrew design${flag}` },
              }),
          }
        : {}),
      ...(extraServers === undefined ? {} : { extraServers }),
      ...(interactive
        ? {
            choose: (options) =>
              chooseOption(options, {
                prompts,
                write: ctx.stdout,
                ...(budget === undefined ? {} : { budget }),
              }),
          }
        : {}),
    });

    if (optionId === undefined && !interactive) {
      const nextFlag = await commandFlags(ctx.cwd, name, app);
      const others = result.options.filter((option) => option.id !== result.chosen.id);
      ctx.stdout(
        `\nChose the recommended option, ${result.chosen.id}.${
          others.length > 0
            ? ` To plan another one, run \`opscrew design${nextFlag} --option <id>\` with one of: ${others.map((o) => o.id).join(", ")}.`
            : ""
        }\n`,
      );
    }
    // runDesign itself prints the next step (`opscrew adapt`).
  });
}
