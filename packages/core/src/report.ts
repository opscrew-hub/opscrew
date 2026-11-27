import { readFileSync } from "node:fs";
import { mkdir } from "node:fs/promises";
import path from "node:path";
import {
  APPROVAL_KINDS,
  PHASES,
  RUN_REPORT_SCHEMA_VERSION,
  type RunReport,
  type RunReportCostEntry,
  type RunReportCosts,
  type RunReportFailure,
  type RunReportModelCost,
  type RunReportPlan,
  type RunReportSecret,
  type RunReportSecretDelete,
  SEVERITIES,
} from "@opscrew/contracts";
import { z } from "zod";
import { OpsCrewError } from "./errors";
import type { Redactor } from "./redact";
import { type CostEntry, writeFileAtomic } from "./state";

const MoneySchema = z.object({
  amount: z.number().finite(),
  currency: z.enum(["EUR", "USD"]),
});

const PolicyResultSchema = z.object({
  policyId: z.string().min(1),
  title: z.string(),
  severity: z.enum(SEVERITIES),
  passed: z.boolean(),
  message: z.string(),
  resource: z.string().optional(),
});

const RunReportPlanSchema: z.ZodType<RunReportPlan> = z.object({
  kind: z.enum(APPROVAL_KINDS),
  title: z.string(),
  details: z.string(),
  planHash: z.string().optional(),
  allowDestroy: z.boolean(),
  needsConfirm: z.boolean(),
  confirmPhrase: z.string().optional(),
  costDelta: MoneySchema.optional(),
  policy: z.array(PolicyResultSchema).optional(),
  approved: z.boolean(),
  reason: z.string().optional(),
});

const RunReportSecretPlaceSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("repo") }),
  z.object({ kind: z.literal("environment"), environment: z.string().min(1) }),
]);

const BASE64_PATTERN = /^[A-Za-z0-9+/]+={0,2}$/;

const RunReportSecretSchema: z.ZodType<RunReportSecret> = z.object({
  name: z.string().min(1),
  keyId: z.string().min(1),
  encryptedValue: z.string().min(1).regex(BASE64_PATTERN, "must be base64 ciphertext"),
  place: RunReportSecretPlaceSchema,
});

const RunReportSecretDeleteSchema: z.ZodType<RunReportSecretDelete> = z.object({
  name: z.string().min(1),
  place: RunReportSecretPlaceSchema,
});

const RunReportCostEntrySchema: z.ZodType<RunReportCostEntry> = z.object({
  at: z.string(),
  phase: z.enum(PHASES),
  model: z.string().optional(),
  costUsd: z.number().finite().nonnegative(),
});

const RunReportModelCostSchema: z.ZodType<RunReportModelCost> = z.object({
  model: z.string().min(1),
  costUsd: z.number().finite().nonnegative(),
  calls: z.number().int().positive(),
});

const RunReportCostsSchema: z.ZodType<RunReportCosts> = z.object({
  totalUsd: z.number().finite().nonnegative(),
  byModel: z.array(RunReportModelCostSchema),
  entries: z.array(RunReportCostEntrySchema),
});

const RunReportFailureSchema: z.ZodType<RunReportFailure> = z.object({
  code: z.string().min(1),
  step: z.string().min(1),
  firstLine: z.string(),
  hint: z.string().optional(),
});

/** Zod schema validating `report.json` v1 (Feature 041). */
export const RunReportSchema: z.ZodType<RunReport> = z.object({
  schemaVersion: z.literal(RUN_REPORT_SCHEMA_VERSION),
  op: z.string().min(1),
  app: z.string().optional(),
  environment: z.string().min(1),
  opscrewVersion: z.string().min(1),
  startedAt: z.string().min(1),
  finishedAt: z.string().min(1),
  status: z.enum(["ok", "needs-approval", "failed"]),
  summary: z.string().optional(),
  plans: z.array(RunReportPlanSchema),
  changes: z.array(z.string()),
  secrets: z.array(RunReportSecretSchema),
  deletedSecrets: z.array(RunReportSecretDeleteSchema),
  costs: RunReportCostsSchema,
  pullRequest: z
    .object({ url: z.string().min(1), number: z.number().int().positive().optional() })
    .optional(),
  verify: z.object({ passed: z.boolean(), summary: z.string() }).optional(),
  failure: RunReportFailureSchema.optional(),
  nextSteps: z.array(z.string()),
});

/**
 * Counts valid {@link CostEntry} records currently in `filePath`, skipping corrupt or truncated
 * lines identically to `CostLedger.entries()` so a prior partial line never shifts the run offset.
 */
export function countValidCostEntriesSync(filePath: string): number {
  let raw: string;
  try {
    raw = readFileSync(filePath, "utf8");
  } catch {
    return 0;
  }
  let valid = 0;
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed.length === 0) continue;
    try {
      if (RunReportCostEntrySchema.safeParse(JSON.parse(trimmed)).success) valid += 1;
    } catch {
      // Skip corrupt/truncated lines identically to CostLedger.entries().
    }
  }
  return valid;
}

/** Round a USD total to 6 decimal places to avoid IEEE-754 summation noise. */
function roundUsd(value: number): number {
  return Math.round(value * 1_000_000) / 1_000_000;
}

/**
 * Aggregates AI spend entries recorded during a single run into total USD and per-model subtotals,
 * sorted deterministically by model name.
 */
export function summarizeRunCosts(entries: readonly CostEntry[]): RunReportCosts {
  const byModelMap = new Map<string, { costUsd: number; calls: number }>();
  let totalUsd = 0;
  for (const entry of entries) {
    totalUsd += entry.costUsd;
    const model = entry.model ?? "unknown";
    const current = byModelMap.get(model);
    if (current === undefined) {
      byModelMap.set(model, { costUsd: entry.costUsd, calls: 1 });
    } else {
      current.costUsd += entry.costUsd;
      current.calls += 1;
    }
  }
  const byModel: RunReportModelCost[] = [...byModelMap.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([model, stats]) => ({
      model,
      costUsd: roundUsd(stats.costUsd),
      calls: stats.calls,
    }));
  return {
    totalUsd: roundUsd(totalUsd),
    byModel,
    entries: entries.map((entry) => ({
      at: entry.at,
      phase: entry.phase,
      ...(entry.model === undefined ? {} : { model: entry.model }),
      costUsd: roundUsd(entry.costUsd),
    })),
  };
}

/**
 * Validates a GitHub Actions Curve25519 public key pair (`keyId` + base64 32-byte public key)
 * before running any command work. Throws `INVALID_INPUT` on missing or malformed values.
 */
export function validateSealedKeyPair(
  keyId: string | undefined,
  publicKeyBase64: string | undefined,
  label = "secrets public key",
): { keyId: string; publicKey: string } {
  const id = keyId?.trim() ?? "";
  const key = publicKeyBase64?.trim() ?? "";
  if (id === "" || key === "") {
    throw new OpsCrewError(
      "INVALID_INPUT",
      `Both key ID and base64 public key are required for the ${label}.`,
      {
        hint: "Pass both --secrets-key-id and --secrets-key (or set both env vars), or omit both.",
      },
    );
  }
  if (!BASE64_PATTERN.test(key)) {
    throw new OpsCrewError("INVALID_INPUT", `The ${label} is not valid base64.`, {
      hint: "Fetch it from GitHub's Actions secrets public-key API without modification.",
    });
  }
  const bytes = Buffer.from(key, "base64");
  if (bytes.length !== 32) {
    throw new OpsCrewError(
      "INVALID_INPUT",
      `The ${label} must decode to 32 bytes (Curve25519 public key), got ${bytes.length}.`,
      { hint: "Fetch it from GitHub's Actions secrets public-key API without modification." },
    );
  }
  return { keyId: id, publicKey: key };
}

/** First non-empty line of a message, redacted, for `report.failure.firstLine`. */
export function firstLineOf(text: string, redactor: Pick<Redactor, "redact">): string {
  const redacted = redactor.redact(text);
  const first =
    redacted
      .split(/\r?\n/)
      .map((line) => line.trim())
      .find((line) => line.length > 0) ?? "";
  return first;
}

/** Returns a deep copy of `report` with every non-ciphertext string passed through `redactor`. */
export function redactRunReport(report: RunReport, redactor: Pick<Redactor, "redact">): RunReport {
  const r = (value: string) => redactor.redact(value);
  return {
    ...report,
    ...(report.summary === undefined ? {} : { summary: r(report.summary) }),
    plans: report.plans.map((plan) => ({
      ...plan,
      title: r(plan.title),
      details: r(plan.details),
      ...(plan.confirmPhrase === undefined ? {} : { confirmPhrase: r(plan.confirmPhrase) }),
      ...(plan.reason === undefined ? {} : { reason: r(plan.reason) }),
      ...(plan.policy === undefined
        ? {}
        : {
            policy: plan.policy.map((item) => ({
              ...item,
              title: r(item.title),
              message: r(item.message),
              ...(item.resource === undefined ? {} : { resource: r(item.resource) }),
            })),
          }),
    })),
    changes: report.changes.map(r),
    // Ciphertext entries carry base64 libsodium sealed boxes (never plaintext).
    secrets: report.secrets.map((entry) => ({
      ...entry,
      name: r(entry.name),
      keyId: r(entry.keyId),
    })),
    deletedSecrets: report.deletedSecrets.map((entry) => ({
      ...entry,
      name: r(entry.name),
    })),
    costs: {
      totalUsd: report.costs.totalUsd,
      byModel: report.costs.byModel.map((item) => ({ ...item, model: r(item.model) })),
      entries: report.costs.entries.map((entry) => ({
        ...entry,
        ...(entry.model === undefined ? {} : { model: r(entry.model) }),
      })),
    },
    ...(report.pullRequest === undefined
      ? {}
      : { pullRequest: { ...report.pullRequest, url: r(report.pullRequest.url) } }),
    ...(report.verify === undefined
      ? {}
      : { verify: { passed: report.verify.passed, summary: r(report.verify.summary) } }),
    ...(report.failure === undefined
      ? {}
      : {
          failure: {
            code: report.failure.code,
            step: r(report.failure.step),
            firstLine: firstLineOf(report.failure.firstLine, redactor),
            ...(report.failure.hint === undefined ? {} : { hint: r(report.failure.hint) }),
          },
        }),
    nextSteps: report.nextSteps.map(r),
  };
}

/**
 * Redacts, validates against {@link RunReportSchema}, and atomically writes `report` as formatted
 * JSON to `filePath` (creating parent directories if needed). Returns the redacted report.
 */
export async function writeRunReport(
  filePath: string,
  report: RunReport,
  redactor: Pick<Redactor, "redact">,
): Promise<RunReport> {
  const redacted = redactRunReport(report, redactor);
  const validated = RunReportSchema.parse(redacted);
  await mkdir(path.dirname(path.resolve(filePath)), { recursive: true });
  await writeFileAtomic(filePath, `${JSON.stringify(validated, null, 2)}\n`);
  return validated;
}
