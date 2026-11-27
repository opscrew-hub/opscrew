import { readFile } from "node:fs/promises";
import {
  appValueRows,
  changeAppValues,
  checkValueChange,
  chooseDeployBranch,
  parseDotenv,
  publishDeploySetup,
  requireGitRepo,
  setupGitHub,
} from "@opscrew/agents";
import { errorText, listText, OpsCrewError, toPosixRelative } from "@opscrew/core";
import { readArtifact } from "@opscrew/plan-schema";
import type { Command } from "commander";
import type { CliContext } from "../context";
import { createPhaseDeps, promptsOf, servicesOf } from "../deps";
import { runApprovalPlanOnly } from "../ui/deploy";
import { type AppEnvFlags, addEnvOption, chooseEnvironment, givenFlags } from "../ui/environment";
import { textTable } from "../ui/output";
import { cancelled } from "../ui/prompts";
import { userPath } from "../ui/recovery";

/** The flags of `values set` and `values unset`. */
interface ChangeFlags extends AppEnvFlags {
  planOnly?: boolean;
  fromFile?: string;
  plain?: boolean;
  redeploy?: boolean;
  /** `--yes`: in a script, store the secrets and propose the plan's change. */
  yes?: boolean;
}

/** Standard input: a terminal (a hidden prompt asks), or a pipe or file read whole. */
export interface ValueInput {
  isTTY: boolean;
  read(): Promise<string>;
}

/** The process's standard input. */
const processStdin: ValueInput = {
  isTTY: process.stdin.isTTY === true,
  read: async () => {
    const chunks: Buffer[] = [];
    for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk));
    return Buffer.concat(chunks).toString("utf8");
  },
};

/**
 * Refuses `NAME=value` among `names` before anything else, without echoing the value (registered
 * with the redactor at once): a value never goes on the command line, where shell history keeps it.
 */
function refuseValuesInArguments(
  ctx: CliContext,
  command: "set" | "unset",
  names: readonly string[],
  flags: AppEnvFlags,
) {
  const given = names.filter((name) => name.includes("="));
  for (const argument of given) ctx.redactor.addLiteral(argument.slice(argument.indexOf("=") + 1));
  const [first] = given;
  if (first === undefined) return;
  const name = first.slice(0, first.indexOf("="));
  throw new OpsCrewError(
    "INVALID_INPUT",
    `A value never goes on the command line, where your shell's history keeps it, so OpsCrew took none of ${name}'s. Nothing was changed.`,
    {
      hint:
        command === "set"
          ? `Run \`opscrew values set${givenFlags(flags)} ${name}\` and paste the value when asked, pipe it in (\`< file\`), or use \`--from-file <file>\`.`
          : `Give the names alone: \`opscrew values unset${givenFlags(flags)} ${name}\`.`,
    },
  );
}

/** A value read from standard input: one line loses its line end; several are kept exactly. */
function inputValue(text: string): string {
  const single = text.replace(/\r?\n$/, "");
  return /[\r\n]/.test(single) ? text : single;
}

const refuse = (message: string, hint: string) =>
  new OpsCrewError("INVALID_INPUT", `${message} Nothing was changed.`, { hint });

/**
 * The values of `--from-file`, each registered with the redactor as it is read; `undefined`
 * without it.
 * @throws OpsCrewError `INVALID_INPUT` with names, for an unreadable file, one with no value, and
 * an empty value.
 */
async function fileValues(
  ctx: CliContext,
  names: readonly string[],
  flags: ChangeFlags,
  again: string,
): Promise<Record<string, string> | undefined> {
  if (flags.fromFile === undefined) return undefined;
  if (names.length > 0) {
    throw refuse(
      "--from-file sets every value of its file, so it doesn't go with names.",
      `Run \`${again} --from-file <file>\` alone, or leave --from-file out to set one name.`,
    );
  }
  const file = userPath(ctx, flags.fromFile);
  let text: string;
  try {
    text = await readFile(file, "utf8");
  } catch (error) {
    throw refuse(`OpsCrew could not read ${file}.`, `Check the path (${errorText(error)}).`);
  }
  const values = Object.fromEntries(parseDotenv(text));
  for (const value of Object.values(values)) ctx.redactor.addLiteral(value, "app-env");
  if (Object.keys(values).length === 0) {
    throw refuse(
      `${file} holds no value.`,
      "Write one NAME=value line per value (a value with line ends in double quotes, with \\n).",
    );
  }
  const empty = Object.keys(values).filter((name) => values[name] === "");
  if (empty.length > 0) {
    const one = empty.length === 1;
    throw refuse(
      `${file} gives ${listText(empty)} an empty value.`,
      `Give ${one ? "it a value" : "them values"}, or remove ${one ? "it" : "them"} with \`opscrew values unset${givenFlags(flags)} ${empty.join(" ")}\`.`,
    );
  }
  return values;
}

/**
 * The one name's value from standard input (a hidden prompt in a terminal), registered with the
 * redactor as it is read.
 * @throws OpsCrewError `INVALID_INPUT` for an empty value; `APPROVAL_REFUSED` when cancelled.
 */
async function inputValueOf(
  ctx: CliContext,
  name: string,
  flags: ChangeFlags,
  environment: string,
  again: string,
): Promise<string> {
  const input = servicesOf(ctx).valueInput ?? processStdin;
  let value: string;
  if (input.isTTY) {
    const prompts = promptsOf(ctx);
    const answer = await prompts.password({
      message: `The value of ${name} for ${environment} (it isn't shown; pipe a value with line ends in instead)`,
    });
    if (prompts.isCancel(answer)) throw cancelled("setting the value", `${again} ${name}`);
    value = answer;
  } else {
    value = inputValue(await input.read());
  }
  ctx.redactor.addLiteral(value, "app-env");
  if (value === "") {
    throw refuse(
      `The value of ${name} is empty.`,
      `To remove ${name}, run \`opscrew values unset${givenFlags(flags)} ${name}\`.`,
    );
  }
  return value;
}

/**
 * `values set` or `unset`: the names checked before any value is asked for or read and before
 * GitHub is reached, the values stored after their approval, and the plan's change (and the
 * recovery copy) proposed in the deploy pull request.
 */
async function change(
  ctx: CliContext,
  command: "set" | "unset",
  names: readonly string[],
  flags: ChangeFlags,
): Promise<void> {
  refuseValuesInArguments(ctx, command, names, flags);
  const { app, name, flag } = await chooseEnvironment(ctx, flags, `values ${command}`);
  const again = `opscrew values ${command}${flag}`;
  const fromFile = command === "set" ? await fileValues(ctx, names, flags, again) : undefined;
  if (command === "set" && fromFile === undefined && names.length !== 1) {
    throw refuse(
      names.length === 0
        ? "Name the value to set."
        : "Standard input holds one value, for one name.",
      `Run \`${again} <NAME>\` for one value, or \`${again} --from-file <file>\` for several.`,
    );
  }
  if (command === "unset" && names.length === 0) {
    throw refuse("Name the values to remove.", `For example \`${again} STRIPE_SECRET_KEY\`.`);
  }
  const setNames =
    command === "unset" ? [] : fromFile === undefined ? names : Object.keys(fromFile);
  const deps = createPhaseDeps(ctx, {
    ai: false,
    app,
    environment: name,
    ...(flags.planOnly === true ? { planOnly: true } : {}),
    ...(flags.yes === true ? { assumeYes: true } : {}),
  });
  const plan = await readArtifact("plan", deps.paths.files.plan);
  const services = servicesOf(ctx).provision ?? {};
  // Every check that needs no value runs before one is asked for or read.
  const checked = await checkValueChange(
    deps,
    plan,
    {
      set: setNames,
      unset: command === "unset" ? names : [],
      ...(flags.plain === true ? { plain: true } : {}),
      ...(flags.redeploy === true ? { redeploy: true } : {}),
    },
    services,
  );
  const [one] = setNames;
  const values =
    fromFile ??
    (one === undefined ? {} : { [one]: await inputValueOf(ctx, one, flags, name, again) });
  const git = await requireGitRepo(deps);
  const github = await setupGitHub(deps, git, services);
  const branch = await chooseDeployBranch(deps, git, github, plan);
  const changed = await runApprovalPlanOnly(ctx, flags.planOnly, () =>
    changeAppValues(deps, plan, checked, values, github),
  );
  if (changed === undefined) return;
  const published = await publishDeploySetup(deps, {
    git,
    github,
    plan: changed.plan,
    paths: changed.planChanged ? [toPosixRelative(deps.paths.root, deps.paths.files.plan)] : [],
    push: true,
    branch,
  });
  if (published.prUrl !== undefined) ctx.stdout(`Pull request: ${published.prUrl}\n`);
}

/** `values list`: each name, whether it is secret and where its value comes from; no value. */
async function list(ctx: CliContext, flags: AppEnvFlags): Promise<void> {
  const { app, name } = await chooseEnvironment(ctx, flags, "values list");
  const deps = createPhaseDeps(ctx, { ai: false, app, environment: name });
  const plan = await readArtifact("plan", deps.paths.files.plan);
  const rows = appValueRows(plan);
  if (rows.length === 0) {
    ctx.stdout(`The app has no values in ${name}.\n`);
    return;
  }
  ctx.stdout(
    `${textTable([
      ["Name", "Secret", "From"],
      ...rows.map((row) => [row.name, row.secret ? "yes" : "no", row.source]),
    ])}\n`,
  );
}

/** Adds `--redeploy` and `--yes` to `command`. */
function addChangeOptions(command: Command): Command {
  return command
    .option(
      "--plan-only",
      "Show which secrets and plan entries would change without storing or pushing anything",
    )
    .option(
      "--redeploy",
      "Start the environment's deploy workflow afterwards, so the app gets them now",
    )
    .option(
      "--yes",
      "In a script: store them in GitHub and propose the plan's change without asking",
    );
}

/**
 * `opscrew values set|unset|list`: an environment's app values, changed without a full provision.
 * A value comes only from standard input or a file, never from the command line, and no output
 * shows one. No MCP tool: values stay in the terminal.
 */
export function register(program: Command, ctx: CliContext): void {
  const values = program
    .command("values")
    .description(
      "Set, remove or list an environment's app values without a full provision (values come from standard input or a file, never the command line)",
    );
  const setting = values
    .command("set")
    .description(
      "Set a value from standard input (a hidden prompt in a terminal, or a pipe such as `< key.pem`), or every value of a dotenv file",
    )
    .argument("[name...]", "The value's name, such as STRIPE_SECRET_KEY")
    .option("--from-file <file>", "Set every value of this dotenv file instead")
    .option("--plain", "A name the plan doesn't have yet is added as not secret");
  addChangeOptions(addEnvOption(setting)).action((names: string[], flags: ChangeFlags) =>
    change(ctx, "set", names, flags),
  );
  const unsetting = values
    .command("unset")
    .description("Remove values and their names from the plan")
    .argument("<name...>", "The values' names");
  addChangeOptions(addEnvOption(unsetting)).action((names: string[], flags: ChangeFlags) =>
    change(ctx, "unset", names, flags),
  );
  const listing = values
    .command("list")
    .description("List the app's values: each name, whether it is secret and where it comes from");
  addEnvOption(listing).action((flags: AppEnvFlags) => list(ctx, flags));
}
