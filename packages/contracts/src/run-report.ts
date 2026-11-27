import type { IsoDateTime, Money } from "./common";
import type { PhaseName } from "./runtime";
import type { ApprovalKind, PolicyResult } from "./safety";

/** Schema version of `report.json` emitted by `opscrew --report <path>` (Feature 041). */
export const RUN_REPORT_SCHEMA_VERSION = 1 as const;

/** Overall outcome of a CLI invocation recorded in `report.json`. */
export type RunReportStatus = "ok" | "needs-approval" | "failed";

/** One approval-gated plan encountered during a run. */
export interface RunReportPlan {
  kind: ApprovalKind;
  title: string;
  details: string;
  planHash?: string;
  allowDestroy: boolean;
  needsConfirm: boolean;
  confirmPhrase?: string;
  costDelta?: Money;
  policy?: PolicyResult[];
  approved: boolean;
  reason?: string;
}

/** Where a sealed GitHub Actions secret should be stored by the dashboard's GitHub App. */
export type RunReportSecretPlace = { kind: "repo" } | { kind: "environment"; environment: string };

/** One secret to delete via the dashboard's GitHub App when `GITHUB_TOKEN` lacks Secrets: write. */
export interface RunReportSecretDelete {
  name: string;
  place: RunReportSecretPlace;
}

/**
 * One newly generated or updated secret, encrypted with libsodium `crypto_box_seal` to GitHub's
 * non-secret Actions public key so `report.json` carries ciphertext only.
 */
export interface RunReportSecret {
  name: string;
  keyId: string;
  encryptedValue: string;
  place: RunReportSecretPlace;
}

/** Aggregated AI spend for one model during this run. */
export interface RunReportModelCost {
  model: string;
  costUsd: number;
  calls: number;
}

/** One AI cost entry recorded during this run. */
export interface RunReportCostEntry {
  at: IsoDateTime;
  phase: PhaseName;
  model?: string;
  costUsd: number;
}

/** AI spend recorded during this run only, totalled overall and per model. */
export interface RunReportCosts {
  totalUsd: number;
  byModel: RunReportModelCost[];
  entries: RunReportCostEntry[];
}

/** Pull request opened or updated during the run. */
export interface RunReportPullRequest {
  url: string;
  number?: number;
}

/** Summary of a post-apply or standalone `verify` check. */
export interface RunReportVerify {
  passed: boolean;
  summary: string;
}

/** Structured failure summary when `status` is `"failed"`. */
export interface RunReportFailure {
  code: string;
  step: string;
  firstLine: string;
  hint?: string;
}

/**
 * Versioned, redacted machine-readable report written by `opscrew --report <path>` (Feature 041).
 * Consumed by the hosted dashboard after a GitHub Actions `workflow_dispatch` run.
 */
export interface RunReport {
  schemaVersion: typeof RUN_REPORT_SCHEMA_VERSION;
  op: string;
  app?: string;
  environment: string;
  opscrewVersion: string;
  startedAt: IsoDateTime;
  finishedAt: IsoDateTime;
  status: RunReportStatus;
  summary?: string;
  plans: RunReportPlan[];
  changes: string[];
  secrets: RunReportSecret[];
  deletedSecrets: RunReportSecretDelete[];
  costs: RunReportCosts;
  pullRequest?: RunReportPullRequest;
  verify?: RunReportVerify;
  failure?: RunReportFailure;
  nextSteps: string[];
}

/**
 * Captures secret writes and deletes during an Actions run by sealing values to GitHub's Actions
 * public key instead of calling GitHub's write-only Secrets API (which `GITHUB_TOKEN` cannot access).
 */
export interface SealedSecretSink {
  seal(name: string, value: string, place: RunReportSecretPlace): Promise<RunReportSecret>;
  recordDelete(name: string, place: RunReportSecretPlace): void;
  entries(): readonly RunReportSecret[];
  deletedEntries(): readonly RunReportSecretDelete[];
}
