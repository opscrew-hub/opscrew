# Implementation Plan: OpsCrew Running in the User's GitHub Actions (041)

**Branch**: `041-actions-runs` | **Date**: 2026-11-27 | **Spec**: [spec.md](spec.md)

## Summary

Adds a versioned, redacted `report.json` contract (`schemaVersion: 1`) across all OpsCrew CLI commands, libsodium sealed-box secret handoff (`secrets[]`) for runs whose `GITHUB_TOKEN` cannot write GitHub Secrets, non-interactive `secrets restore --from-env` hydration, per-run AI cost totals in `report.json`, and `--plan-only` parity across mutating commands so the hosted dashboard can orchestrate every OpsCrew operation via GitHub Actions `workflow_dispatch` with zero local CLI installation.

## Technical Context

- **Language:** TypeScript strict ESM. **New dependencies:** none (`libsodium-wrappers` is already in `@opscrew/connector-github`; `zod` is already in `@opscrew/core`).
- **Packages touched:**
  - `@opscrew/contracts` — new `src/run-report.ts` exported from root (`RunReport`, `RunReportPlan`, `RunReportSecret`, `RunReportCosts`, `RunReportFailure`, `RUN_REPORT_SCHEMA_VERSION`).
  - `@opscrew/core` — new `src/report.ts` (`RunReportSchema`, `redactRunReport`, `writeRunReport`, `summarizeRunCosts`, `validateSealedPublicKey`) exported from root.
  - `@opscrew/connector-github` — export `sealSecret` from root (already in `src/seal.ts`) and add `SealedSecretRecorder` / `wrapGitHubForSealedReport` helper so any secret write can be redirected into sealed `RunReportSecret` entries without touching GitHub's write-only Secrets API.
  - `@opscrew/agents` — `secrets/restore.ts` (`--from-env` / `OPSCREW_RECOVERY_KEY` helper), `secrets/copy.ts` (optional `sealNewKey` callback for first-run recovery key sealing without writing plaintext key file to disk), `provision/secrets.ts` (support optional sealed-secret sink).
  - `opscrew` (`packages/cli`) — global `--report <path>` (`OPSCREW_REPORT_PATH`), `--secrets-key-id` / `--secrets-key` / `--env-secrets-key-id` / `--env-secrets-key` / `--env-secrets-name`, `ReportCollector` attached to `CliContext`, recording `ApprovalHandler` wrapper in `createPhaseDeps`, AI cost delta capture, `secrets restore --from-env --on-conflict`, `--plan-only` parity for `destroy`, `retarget`, `rollback`, `restore`, `rotate`, `promote`, `secure`, `values`, and Actions local-target guard.
  - `docs/guide/actions-runs.md` — user and operator guide for running OpsCrew in GitHub Actions.
- **Testing:** Vitest unit and CLI integration tests with real libsodium Curve25519 keypairs, `FakeGitHub`, fake SOPS, and `fakeSecret` values (zero network calls).

## Constitution Check

- **I. Safety gate:** Strengthened — every mutating command enforces the two-run hash-bound model (`--plan-only` → `--approve <hash>` [+ `--confirm <name>`]). No standing approval is added; no safety check is bypassed.
- **IV. Secrets never leak:** Every string in `report.json` passes through `Redactor.redact` before serialization. New secrets are registered with `Redactor.addLiteral` before sealing and emitted only as libsodium `crypto_box_seal` base64 ciphertext. `OPSCREW_RECOVERY_KEY` is read from env into memory and registered with `Redactor` immediately.
- **V. Contracts have one owner:** `RunReport` types live solely in `@opscrew/contracts`; Zod validation and serialization live solely in `@opscrew/core`.
- **VII. Test first:** Every task starts with failing tests.
- **X. Simplicity:** Zero new dependencies; reuses `sealSecret`, `CostLedger`, `NonInteractiveApprovalHandler`, `FlagConfirmation`, and `refreshRecoveryCopy`/`restoreRecoveryCopy`.

## Key Architectural Decisions

1. **Global `--report` collector at the CLI boundary (`program.ts` + `deps.ts`), not per-command ad-hoc JSON:**
   - A `ReportCollector` lives on `CliContext` (created in `program.ts` `preAction` when `--report` or `OPSCREW_REPORT_PATH` is set, flushed in a `finally` block in `runProgram`).
   - `createPhaseDeps` wraps the approval handler in a thin `RecordingApprovalHandler` that records every `ApprovalRequest` and its `ApprovalDecision` into `ReportCollector`.
   - Commands can enrich `ReportCollector` with structured `summary`, `changes`, `pullRequest`, `verify`, and `nextSteps`, while even commands that fail early or throw `CommanderError` still produce a valid, redacted `report.json`.
2. **`status: "needs-approval"` vs `"ok"` vs `"failed"`:**
   - `"needs-approval"` when `--plan-only` produced one or more plans awaiting approval, OR when a non-interactive run stopped solely because an approval (`APPROVAL_REFUSED` / `PLAN_NOT_APPROVED` / `DESTROY_NOT_APPROVED`) has not been granted yet (with the exact plan hash / `confirmPhrase` recorded in `plans[]`).
   - `"ok"` when the command completed cleanly (including a `--plan-only` run with zero changes).
   - `"failed"` on `PLAN_HASH_MISMATCH`, policy/check failure, precondition failure, invalid input, or unexpected errors.
3. **Sealed secrets sink (`SealedSecretSink`) for Actions runs:**
   - GitHub Actions uses a separate public key for repository secrets vs. each environment's secrets.
   - `SealedSecretTarget` holds `{ repo: { keyId, publicKey }, environment?: { name, keyId, publicKey } }`.
   - When `setSecret(name, value, place)` is called in sealed mode, OpsCrew picks the matching public key (`place.kind === "repo"` → `repo`, `place.kind === "environment"` → `environment`), seals with `sealSecret(key, value)`, and records `{ name, keyId, encryptedValue, place }` in `ReportCollector`. If an environment secret is needed without an environment key provided, it fails closed with `PHASE_PRECONDITION` naming the missing `--env-secrets-key-id` / `--env-secrets-key` inputs.
4. **First-run recovery key sealing:**
   - Instead of writing a plaintext `age` private key to `--key-out <path>` on an ephemeral runner, `RefreshRecoveryOptions` gains an optional `sealFirstKey?: (identity: string) => Promise<void>` callback. When present, `refreshRecoveryCopy` generates the age keypair, encrypts `secrets.sops.json` to its public `age1…` recipient, and hands `identity` to `sealFirstKey` (which seals it as `OPSCREW_RECOVERY_KEY` into `report.json`'s `secrets[]`), never writing the private key to disk.
5. **AI cost delta:**
   - Before a command runs, `ReportCollector` snapshots the existing entry count of `paths.files.costs` (if present). At finalize time, it reads `CostLedger.entries()`, slices from the snapshot index onward, and populates `costs: { totalUsd, byModel, entries }`.
