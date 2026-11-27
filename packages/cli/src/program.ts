import path from "node:path";
import { Command, CommanderError } from "commander";
import { description } from "../package.json";
import { ALL_COMMANDS } from "./commands/index";
import { type CliContext, createDefaultContext } from "./context";
import { servicesOf } from "./deps";
import { CliExit, ERROR_EXIT_CODE, exitCodeFor, printError } from "./exit";
import {
  checkActionsAllowed,
  ReportCollector,
  type ReportGlobalFlags,
  resolveReportPath,
  resolveSealedTargets,
} from "./report";

/** Command path without the root `opscrew` binary name, for example `provision` or `secrets restore`. */
function commandPath(cmd: Command): string {
  const parts: string[] = [];
  let current: Command | null = cmd;
  while (current !== null && current.parent !== null) {
    parts.unshift(current.name());
    current = current.parent;
  }
  return parts.join(" ") || "opscrew";
}

/** Builds the `opscrew` program with every command registered. Errors are thrown, not exited. */
export function createProgram(ctx: CliContext): Command {
  const program = new Command()
    .name("opscrew")
    .description(description)
    .version(ctx.version, "-V, --version", "Print the OpsCrew version")
    .helpOption("-h, --help", "Show help for a command")
    .option("--cwd <dir>", "Project directory to work in (defaults to the current directory)")
    .option("--report <path>", "Write a redacted JSON run report (schemaVersion 1) to this path")
    .option(
      "--secrets-key-id <id>",
      "GitHub Actions repository secrets public key ID (for sealed report secrets)",
    )
    .option("--secrets-key <base64>", "GitHub Actions repository secrets base64 public key")
    .option("--env-secrets-key-id <id>", "GitHub Actions environment secrets public key ID")
    .option("--env-secrets-key <base64>", "GitHub Actions environment secrets base64 public key")
    .option(
      "--env-secrets-name <name>",
      "GitHub environment name the environment secrets key belongs to",
    )
    // Global options go before the command, so `promote --version <id>` is promote's own.
    .enablePositionalOptions()
    .exitOverride()
    .configureOutput({
      writeOut: (text) => ctx.stdout(text),
      writeErr: (text) => ctx.stderr(text),
    })
    .hook("preAction", (_thisCommand, actionCommand) => {
      const opts = program.opts<ReportGlobalFlags & { cwd?: string }>();
      if (opts.cwd !== undefined) ctx.cwd = path.resolve(ctx.cwd, opts.cwd);
      const reportPath = resolveReportPath(ctx.cwd, opts, ctx.env);
      const op = commandPath(actionCommand);
      const actionOpts = actionCommand.opts<{ planOnly?: boolean }>();
      // Initialize collector before validating keys/actions so any early failure still writes report.json.
      if (reportPath !== undefined) {
        const clock = servicesOf(ctx).clock;
        ctx.report = new ReportCollector({
          filePath: reportPath,
          ...(clock === undefined ? {} : { clock }),
          redactor: ctx.redactor,
          version: ctx.version,
        });
        ctx.report.setOp(op, actionOpts.planOnly === true);
      }
      const sealedTargets = resolveSealedTargets(opts, ctx.env);
      if (sealedTargets !== undefined) {
        const clock = servicesOf(ctx).clock;
        ctx.report = new ReportCollector({
          ...(reportPath === undefined ? {} : { filePath: reportPath }),
          sealedTargets,
          ...(clock === undefined ? {} : { clock }),
          redactor: ctx.redactor,
          version: ctx.version,
        });
        ctx.report.setOp(op, actionOpts.planOnly === true);
      }
      checkActionsAllowed(op, ctx.env);
    });
  for (const command of ALL_COMMANDS) command.register(program, ctx);
  return program;
}

/**
 * Runs the CLI for `argv` (as in `process.argv`) and returns the exit code: 0 on success, 1 for
 * errors, or the code a command asked for. Stack traces are printed only with `OPSCREW_DEBUG=1`.
 */
export function main(argv: readonly string[], ctx?: CliContext): Promise<number> {
  const context = ctx ?? createDefaultContext();
  return runProgram(createProgram(context), argv, context);
}

/** Parses `argv` with `program` and maps any error to output and an exit code (see `main`). */
export async function runProgram(
  program: Command,
  argv: readonly string[],
  ctx: CliContext,
): Promise<number> {
  let exitCode = 0;
  let caught: unknown;
  try {
    await program.parseAsync([...argv]);
    exitCode = 0;
  } catch (error) {
    caught = error;
    exitCode = handleError(error, ctx);
  }
  // If parsing failed before preAction ran (e.g. CommanderError), still write report.json when configured.
  if (ctx.report === undefined && caught !== undefined) {
    const opts = program.opts<ReportGlobalFlags & { cwd?: string }>();
    const baseCwd = opts.cwd !== undefined ? path.resolve(ctx.cwd, opts.cwd) : ctx.cwd;
    const reportPath = resolveReportPath(baseCwd, opts, ctx.env);
    if (reportPath !== undefined) {
      const clock = servicesOf(ctx).clock;
      ctx.report = new ReportCollector({
        filePath: reportPath,
        ...(clock === undefined ? {} : { clock }),
        redactor: ctx.redactor,
        version: ctx.version,
      });
    }
  }
  if (ctx.report !== undefined) {
    await ctx.report.finalize({ exitCode, ...(caught === undefined ? {} : { error: caught }) });
  }
  return exitCode;
}

function handleError(error: unknown, ctx: CliContext): number {
  // Commander has already printed its own message (or the help / version text). Every command
  // inherits the program's exit override, so usage errors of every command exit 2 here.
  if (error instanceof CommanderError) return error.exitCode === 0 ? 0 : ERROR_EXIT_CODE;
  if (error instanceof CliExit) return error.exitCode;
  printError(ctx, error);
  return exitCodeFor(error);
}
