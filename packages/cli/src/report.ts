import { readFileSync } from "node:fs";
import path from "node:path";
import { createSealedSecretSink, type SealedSecretTargets } from "@opscrew/connector-github";
import {
  type ApprovalDecision,
  type ApprovalHandler,
  type ApprovalRequest,
  type Clock,
  RUN_REPORT_SCHEMA_VERSION,
  type RunReport,
  type RunReportFailure,
  type RunReportPlan,
  type RunReportPullRequest,
  type RunReportStatus,
  type RunReportVerify,
  type SealedSecretSink,
} from "@opscrew/contracts";
import {
  CostLedger,
  firstLineOf,
  isUserFacingError,
  OpsCrewError,
  type Redactor,
  summarizeRunCosts,
  systemClock,
  writeRunReport,
} from "@opscrew/core";
import { CommanderError } from "commander";
import { CliExit } from "./exit";
import type { PlannedHash } from "./ui/deploy";

/** Global CLI flags that configure Feature 041 `report.json` and sealed-box secret handoff. */
export interface ReportGlobalFlags {
  report?: string;
  secretsKeyId?: string;
  secretsKey?: string;
  envSecretsKeyId?: string;
  envSecretsKey?: string;
  envSecretsName?: string;
}

/**
 * Operations that require the user's own local computer and are refused when running inside
 * GitHub Actions (`OPSCREW_ACTIONS_RUN=1`).
 */
export const ACTIONS_EXCLUDED_OPS = new Set([
  "localhost",
  "localhost trust",
  "localhost untrust",
  "mcp",
  "mcp install",
  "mcp uninstall",
  "vpn",
  "vpn add",
  "vpn remove",
  "vpn list",
  "vpn grant",
  "vpn revoke",
  "secrets folder",
]);

/** True when `OPSCREW_ACTIONS_RUN` marks this invocation as an Actions run. */
export function isActionsRun(env: Record<string, string | undefined>): boolean {
  const value = env.OPSCREW_ACTIONS_RUN?.trim().toLowerCase();
  return value === "1" || value === "true" || value === "yes";
}

/** Refuses local-only operations when running inside GitHub Actions (`OPSCREW_ACTIONS_RUN=1`). */
export function checkActionsAllowed(op: string, env: Record<string, string | undefined>): void {
  if (!isActionsRun(env)) return;
  const top = op.split(" ")[0] ?? op;
  if (ACTIONS_EXCLUDED_OPS.has(op) || ACTIONS_EXCLUDED_OPS.has(top)) {
    throw new OpsCrewError(
      "PHASE_PRECONDITION",
      `\`opscrew ${op}\` needs your own computer and cannot run in GitHub Actions.`,
      {
        hint: `Run \`npx opscrew ${op}\` locally on your computer instead.`,
      },
    );
  }
}

/** Resolves `--report <path>` or `OPSCREW_REPORT_PATH` against `cwd`. */
export function resolveReportPath(
  cwd: string,
  flags: Pick<ReportGlobalFlags, "report">,
  env: Record<string, string | undefined>,
): string | undefined {
  const raw = flags.report?.trim() || env.OPSCREW_REPORT_PATH?.trim();
  if (raw === undefined || raw === "") return undefined;
  return path.resolve(cwd, raw);
}

/**
 * Resolves sealed-secret public keys from CLI flags or `OPSCREW_SECRETS_*` env vars.
 * Returns `undefined` when no key option is supplied; throws `INVALID_INPUT` if partially supplied.
 */
export function resolveSealedTargets(
  flags: Omit<ReportGlobalFlags, "report">,
  env: Record<string, string | undefined>,
): SealedSecretTargets | undefined {
  const repoKeyId = flags.secretsKeyId?.trim() || env.OPSCREW_SECRETS_KEY_ID?.trim();
  const repoKey = flags.secretsKey?.trim() || env.OPSCREW_SECRETS_KEY?.trim();
  const envKeyId = flags.envSecretsKeyId?.trim() || env.OPSCREW_ENV_SECRETS_KEY_ID?.trim();
  const envKey = flags.envSecretsKey?.trim() || env.OPSCREW_ENV_SECRETS_KEY?.trim();
  const envName = flags.envSecretsName?.trim() || env.OPSCREW_ENV_SECRETS_NAME?.trim();

  const hasRepo = Boolean(repoKeyId || repoKey);
  const hasEnv = Boolean(envKeyId || envKey);
  if (!hasRepo && !hasEnv) return undefined;
  if (!hasRepo) {
    throw new OpsCrewError(
      "INVALID_INPUT",
      "Environment secrets public key was passed without the repository secrets public key.",
      { hint: "Also pass --secrets-key-id and --secrets-key for repository secrets." },
    );
  }
  return {
    repo: { keyId: repoKeyId ?? "", publicKey: repoKey ?? "" },
    ...(hasEnv
      ? {
          environment: {
            ...(envName ? { name: envName } : {}),
            keyId: envKeyId ?? "",
            publicKey: envKey ?? "",
          },
        }
      : {}),
  };
}

/** Counts valid non-empty JSONL lines currently present in a cost ledger file (0 if missing). */
function countExistingLines(filePath: string): number {
  try {
    const raw = readFileSync(filePath, "utf8");
    return raw.split(/\r?\n/).filter((line) => line.trim().length > 0).length;
  } catch {
    return 0;
  }
}

const APPROVAL_WAIT_CODES = new Set([
  "APPROVAL_REFUSED",
  "PLAN_NOT_APPROVED",
  "DESTROY_NOT_APPROVED",
]);

/** Collects structured facts throughout one CLI run and writes `report.json` v1 on exit. */
export class ReportCollector {
  readonly filePath: string | undefined;
  readonly sealedSecrets: SealedSecretSink | undefined;
  private op = "opscrew";
  private app: string | undefined;
  private environment = "prod";
  private planOnly = false;
  private summary: string | undefined;
  private readonly plans: RunReportPlan[] = [];
  private readonly changes: string[] = [];
  private readonly nextSteps: string[] = [];
  private pullRequest: RunReportPullRequest | undefined;
  private verify: RunReportVerify | undefined;
  private costsFile: string | undefined;
  private initialCostEntries = 0;
  private readonly startedAt: string;
  private readonly clock: Clock;
  private readonly redactor: Redactor;
  private readonly version: string;

  constructor(options: {
    filePath?: string;
    sealedTargets?: SealedSecretTargets;
    clock?: Clock;
    redactor: Redactor;
    version: string;
  }) {
    this.filePath = options.filePath;
    this.clock = options.clock ?? systemClock;
    this.redactor = options.redactor;
    this.version = options.version;
    this.startedAt = this.clock.now().toISOString();
    this.sealedSecrets =
      options.sealedTargets === undefined
        ? undefined
        : createSealedSecretSink(options.sealedTargets, options.redactor);
  }

  setOp(op: string, planOnly = false): void {
    this.op = op;
    this.planOnly = planOnly;
  }

  setTarget(target: { app?: string | undefined; environment?: string | undefined }): void {
    if (target.app !== undefined) this.app = target.app;
    if (target.environment !== undefined) this.environment = target.environment;
  }

  attachCosts(costsFile: string): void {
    if (this.costsFile !== undefined) return;
    this.costsFile = costsFile;
    this.initialCostEntries = countExistingLines(costsFile);
  }

  setSummary(text: string): void {
    this.summary = text;
  }

  addChange(text: string): void {
    this.changes.push(text);
  }

  setPullRequest(pr: RunReportPullRequest): void {
    this.pullRequest = pr;
  }

  setVerify(verify: RunReportVerify): void {
    this.verify = verify;
  }

  addNextStep(step: string): void {
    if (!this.nextSteps.includes(step)) this.nextSteps.push(step);
  }

  recordApproval(request: ApprovalRequest, decision: ApprovalDecision): void {
    const plan: RunReportPlan = {
      kind: request.kind,
      title: request.title,
      details: request.details,
      ...(request.planHash === undefined ? {} : { planHash: request.planHash }),
      allowDestroy: request.allowDestroy === true,
      needsConfirm: request.confirmPhrase !== undefined || request.allowDestroy === true,
      ...(request.confirmPhrase === undefined ? {} : { confirmPhrase: request.confirmPhrase }),
      ...(request.costDelta === undefined ? {} : { costDelta: request.costDelta }),
      ...(request.policy === undefined ? {} : { policy: request.policy }),
      approved: decision.approved,
      ...(decision.reason === undefined ? {} : { reason: decision.reason }),
    };
    this.plans.push(plan);
  }

  /**
   * Records hashes printed by a `--plan-only` command that didn't call `approvals.request`
   * directly (such as `provision --plan-only`, `addon --plan-only`, `portainer --plan-only`).
   */
  recordPlannedHashes(
    planned: readonly PlannedHash[],
    approveCommand: string,
    extra?: { allowDestroy?: boolean; confirmPhrase?: string },
  ): void {
    this.planOnly = true;
    for (const item of planned) {
      const exists = this.plans.some(
        (existing) => existing.planHash?.toLowerCase() === item.hash.toLowerCase(),
      );
      if (exists) continue;
      this.plans.push({
        kind: item.label.includes("host")
          ? "host-apply"
          : item.label.includes("stack")
            ? "stack-apply"
            : item.label.includes("Cloudflare")
              ? "cloudflare-apply"
              : item.label.includes("Pages")
                ? "pages-apply"
                : item.label.includes("hosting")
                  ? "hosting-apply"
                  : "iac-apply",
        title: item.label,
        details: `Saved plan awaiting approval (${item.label}).`,
        planHash: item.hash,
        allowDestroy: extra?.allowDestroy === true,
        needsConfirm: extra?.confirmPhrase !== undefined || extra?.allowDestroy === true,
        ...(extra?.confirmPhrase === undefined ? {} : { confirmPhrase: extra.confirmPhrase }),
        approved: false,
      });
    }
    this.addNextStep(`Review the plan above and run: ${approveCommand}`);
  }

  /** Wraps `handler` so every approval request and decision is recorded in this report. */
  wrapApprovalHandler(handler: ApprovalHandler): ApprovalHandler {
    return {
      request: async (request: ApprovalRequest): Promise<ApprovalDecision> => {
        const decision = await handler.request(request);
        this.recordApproval(request, decision);
        return decision;
      },
    };
  }

  /** Builds and atomically writes `report.json` when `filePath` was configured. */
  async finalize(outcome: {
    exitCode: number;
    error?: unknown;
  }): Promise<RunReport | undefined> {
    if (this.filePath === undefined) return undefined;
    const finishedAt = this.clock.now().toISOString();
    const costEntries =
      this.costsFile === undefined
        ? []
        : (await new CostLedger(this.costsFile, this.clock).entries()).slice(
            this.initialCostEntries,
          );
    const costs = summarizeRunCosts(costEntries);
    const hasPendingPlan = this.plans.some((plan) => !plan.approved);

    let status: RunReportStatus;
    let failure: RunReportFailure | undefined;

    if (outcome.exitCode === 0 && outcome.error === undefined) {
      status = this.planOnly && hasPendingPlan ? "needs-approval" : "ok";
    } else if (
      isUserFacingError(outcome.error) &&
      APPROVAL_WAIT_CODES.has(outcome.error.code) &&
      hasPendingPlan
    ) {
      status = "needs-approval";
      if (outcome.error.hint) this.addNextStep(outcome.error.hint);
    } else {
      status = "failed";
      failure = this.buildFailure(outcome.error, outcome.exitCode);
      if (failure.hint) this.addNextStep(failure.hint);
    }

    const report: RunReport = {
      schemaVersion: RUN_REPORT_SCHEMA_VERSION,
      op: this.op,
      ...(this.app === undefined ? {} : { app: this.app }),
      environment: this.environment,
      opscrewVersion: this.version,
      startedAt: this.startedAt,
      finishedAt,
      status,
      ...(this.summary === undefined ? {} : { summary: this.summary }),
      plans: this.plans,
      changes: this.changes,
      secrets: [...(this.sealedSecrets?.entries() ?? [])],
      costs,
      ...(this.pullRequest === undefined ? {} : { pullRequest: this.pullRequest }),
      ...(this.verify === undefined ? {} : { verify: this.verify }),
      ...(failure === undefined ? {} : { failure }),
      nextSteps: this.nextSteps,
    };

    return writeRunReport(this.filePath, report, this.redactor);
  }

  private buildFailure(error: unknown, exitCode: number): RunReportFailure {
    if (error instanceof CommanderError) {
      return {
        code: "CLI_USAGE",
        step: this.op,
        firstLine: firstLineOf(error.message, this.redactor),
      };
    }
    if (isUserFacingError(error)) {
      return {
        code: error.code,
        step: this.op,
        firstLine: firstLineOf(error.message, this.redactor),
        ...(error.hint === undefined ? {} : { hint: error.hint }),
      };
    }
    if (error instanceof CliExit) {
      return {
        code: exitCode === 1 ? "REFUSED" : "FAILED",
        step: this.op,
        firstLine: `Command exited with code ${exitCode}.`,
      };
    }
    const message = error instanceof Error ? error.message : String(error ?? `Exit code ${exitCode}`);
    return {
      code: "UNEXPECTED",
      step: this.op,
      firstLine: firstLineOf(message, this.redactor),
    };
  }
}
