import { isUserFacingError, OpsCrewError } from "@opscrew/core";
import type { CliContext } from "../context";
import { CliExit, exitCodeFor, printError } from "../exit";

/**
 * Runs a phase and turns any error into plain-English output (see `printError`) and a
 * {@link CliExit} with the code from {@link exitCodeFor}. `extraHint` may add advice for an error.
 */
export async function runPhaseCommand<T>(
  ctx: CliContext,
  run: () => Promise<T>,
  extraHint?: (error: unknown) => string | undefined,
): Promise<T> {
  try {
    return await run();
  } catch (error) {
    if (error instanceof CliExit) throw error;
    const extra = extraHint?.(error);
    printError(ctx, error, extra === undefined ? {} : { extraHint: extra });
    throw new CliExit(exitCodeFor(error));
  }
}

/** True for the refusal a non-interactive run without `--yes` gives every approval it is asked. */
function refusedForYes(ctx: CliContext, yes: boolean | undefined, error: unknown): boolean {
  return (
    !ctx.isInteractive &&
    yes !== true &&
    isUserFacingError(error) &&
    error.code === "APPROVAL_REFUSED"
  );
}

/**
 * A `--plan-only` run: its `--yes`, and whether its refusal is the one for a missing `--yes` (not,
 * say, a `--confirm` name that differs).
 */
export interface PlanOnlyRun {
  yes: boolean | undefined;
  stopsForYes?: () => boolean;
}

const PLAN_ONLY_STOP_CODES = new Set([
  "APPROVAL_REFUSED",
  "PLAN_NOT_APPROVED",
  "DESTROY_NOT_APPROVED",
]);

/** Refuses `--plan-only` combined with `--approve` before doing any work. */
export function refusePlanOnlyWithApprove(
  planOnly: boolean | undefined,
  approve: string | readonly string[] | undefined,
  command: string,
): void {
  const hasApprove =
    typeof approve === "string"
      ? approve.trim() !== ""
      : Array.isArray(approve) && approve.length > 0;
  if (planOnly === true && hasApprove) {
    throw new OpsCrewError("INVALID_INPUT", "Use either --plan-only or --approve, not both.", {
      hint: `Run \`${command} --plan-only\` to see the plan and its hash, then \`${command} --approve <hash>\` to apply it.`,
    });
  }
}

/**
 * Runs a mutating command under `--plan-only` (Feature 041): when `planOnly` is true, stopping at
 * the approval gate exits cleanly (returning `undefined`) with `report.json` marked
 * `"needs-approval"` and nothing changed.
 */
export async function runApprovalPlanOnly<T>(
  ctx: CliContext,
  planOnly: boolean | undefined,
  run: () => Promise<T>,
): Promise<T | undefined> {
  if (planOnly !== true) return run();
  ctx.report?.markPlanOnly();
  try {
    return await run();
  } catch (error) {
    if (isUserFacingError(error) && PLAN_ONLY_STOP_CODES.has(error.code)) {
      ctx.stdout("\nStopped after planning (--plan-only); nothing was changed.\n");
      return undefined;
    }
    throw error;
  }
}

/**
 * {@link runPhaseCommand} for a command that may be a `--plan-only` run (`planOnly`). Such a run in
 * a script without `--yes` stops at the first step that needs it (writing the files the next plans
 * are made from): it showed what it could, as asked, and changed nothing, so it says so and how to
 * go on, and answers `undefined` (exit 0). Any other error, and a refusal in a terminal or with
 * `--yes`, keeps its message and exit code.
 */
export async function runPlanOnlyCommand<T>(
  ctx: CliContext,
  planOnly: PlanOnlyRun | undefined,
  run: () => Promise<T>,
  extraHint?: (error: unknown) => string | undefined,
): Promise<T | undefined> {
  return runPhaseCommand(
    ctx,
    async () => {
      try {
        return await run();
      } catch (error) {
        const stops = planOnly?.stopsForYes?.() ?? true;
        if (planOnly === undefined || !stops || !refusedForYes(ctx, planOnly.yes, error)) {
          throw error;
        }
        ctx.reporter.warn((error as Error).message);
        ctx.stdout(
          "\nThis --plan-only run stopped there: outside a terminal that step needs --yes, and nothing was changed. Run the same command with --yes to see every plan and its hash; it prints the `--approve <hash>` command that applies them.\n",
        );
        return undefined;
      }
    },
    extraHint,
  );
}

/**
 * Hint for an approval refused in a non-interactive run without `--yes`. For `provision`, which has
 * `--confirm <app>`, it also says how a script applies a plan that deletes or replaces resources.
 */
export function assumeYesHint(
  ctx: CliContext,
  yes: boolean | undefined,
  command?: string,
): (error: unknown) => string | undefined {
  const deletions =
    command === "provision"
      ? "a plan that deletes or replaces resources also needs --confirm <app name> (opscrew provision --approve <hash> --confirm <app name>), a move's maintenance window --allow-downtime, other destroys and changed host keys need an interactive terminal."
      : "destroys and changed host keys need an interactive terminal.";
  return (error) =>
    refusedForYes(ctx, yes, error)
      ? `This run is not interactive: add --yes to approve writing the generated files, storing the GitHub secrets, pushing and opening the pull request. Infrastructure changes need --approve <hash>; ${deletions}`
      : undefined;
}

/** Commander option parser for a repeatable option: collects every value in order. */
export function collect(value: string, previous: string[] | undefined): string[] {
  return [...(previous ?? []), value];
}

/** One plan of a `--plan-only` run that needs its own approval. */
export interface PlannedHash {
  /** What the plan changes, for example `infrastructure (Cloudflare)` or `host plan for your server`. */
  label: string;
  hash: string;
}

/**
 * Prints the hashes of a `--plan-only` run that made several plans (a server the user owns: the
 * infrastructure plan and the host plan), each labelled, with the exact command that applies
 * exactly these plans (one `--approve` per plan) and nothing else.
 */
export function printPlanHashes(
  ctx: CliContext,
  plans: readonly PlannedHash[],
  approveCommand: string,
): void {
  ctx.report?.recordPlannedHashes(plans, approveCommand);
  if (plans.length === 1 && plans[0] !== undefined) {
    printPlanHash(ctx, plans[0].hash, approveCommand);
    return;
  }
  const width = Math.max(...plans.map((plan) => plan.label.length));
  ctx.stdout(
    [
      "",
      "Plan hashes (SHA-256), one approval each:",
      "",
      ...plans.map((plan) => `    ${`${plan.label}:`.padEnd(width + 1)}  ${plan.hash}`),
      "",
      "Review the plans above. To apply exactly these plans, run:",
      "",
      `    ${approveCommand}`,
      "",
      "Only saved plans with these hashes are applied; if one no longer matches, OpsCrew refuses it and you plan again.",
      "",
    ].join("\n"),
  );
}

/**
 * Prints the plan hash of a `--plan-only` run on its own line, with the exact command that applies
 * that plan and nothing else.
 */
function printPlanHash(ctx: CliContext, planHash: string, approveCommand: string): void {
  ctx.stdout(
    [
      "",
      "Plan hash (SHA-256):",
      "",
      `    ${planHash}`,
      "",
      "Review the plan above. To apply exactly this plan, run:",
      "",
      `    ${approveCommand}`,
      "",
      "Only the saved plan with this hash is applied; if it no longer matches, OpsCrew refuses and you plan again.",
      "",
    ].join("\n"),
  );
}
