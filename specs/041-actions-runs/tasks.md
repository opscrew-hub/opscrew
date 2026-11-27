# Tasks: OpsCrew Running in the User's GitHub Actions (041)

**Branch:** `041-actions-runs` | **Spec:** [spec.md](spec.md) | **Plan:** [plan.md](plan.md) | **Contract:** [contracts/report-schema.md](contracts/report-schema.md)

## Wave 1: Versioned `report.json` Contract & Writer

- [x] **T4101 — Report contract types (`@opscrew/contracts`)**
  - Add `packages/contracts/src/run-report.ts` exporting `RUN_REPORT_SCHEMA_VERSION`, `RunReportStatus`, `RunReportPlan`, `RunReportSecretPlace`, `RunReportSecret`, `RunReportModelCost`, `RunReportCosts`, `RunReportPullRequest`, `RunReportVerify`, `RunReportFailure`, `RunReport`, and `SealedSecretSink`. Re-export from `packages/contracts/src/index.ts`.
- [x] **T4102 — Report Zod schema, redaction, cost aggregator & atomic writer (`@opscrew/core`)**
  - Add `packages/core/src/report.ts` and `packages/core/src/report.test.ts` (TDD): `RunReportSchema`, `summarizeRunCosts(entries)`, `redactRunReport(report, redactor)`, `writeRunReport(filePath, report, redactor)`, and `validateSealedKeyPair(keyId, publicKeyBase64)`. Re-export from `packages/core/src/index.ts`.

## Wave 2: Sealed-Box Secret Handoff & Ephemeral Runner State Hydration

- [x] **T4103 — Export `sealSecret` & add `SealedReportSecretSink` (`@opscrew/connector-github`)**
  - Export `sealSecret` from `packages/connectors/github/src/index.ts`. Add `packages/connectors/github/src/sealed-sink.ts` + `sealed-sink.test.ts` (TDD) implementing `createSealedSecretSink(targets, redactor)` that validates Curve25519 keys, registers plaintext values with `redactor`, seals with `sealSecret`, and returns `RunReportSecret[]` (verified by `crypto_box_seal_open`).
- [x] **T4104 — Ephemeral runner hydration (`secrets restore --from-env`) & first-run recovery key sealing (`@opscrew/agents`)**
  - Extend `RefreshRecoveryOptions` in `packages/agents/src/secrets/copy.ts` with `sealFirstKey?: (identity: string) => Promise<void>` so first-run recovery keys can be sealed directly into `report.json` without writing a plaintext key file to disk. Add `packages/agents/src/secrets/copy.test.ts` coverage (TDD).
  - Support optional `sealedSecrets?: SealedSecretSink` in `packages/agents/src/provision/secrets.ts` (`setDeploySecrets`) so secret writes in Actions mode seal into `report.json` instead of calling GitHub's `setSecret` endpoint, with tests proving zero `PUT` calls and valid libsodium decryption.

## Wave 3: CLI Global `--report`, Recording Approvals & Actions Guard

- [x] **T4105 — `ReportCollector`, `RecordingApprovalHandler`, and global `--report` / `--secrets-key*` flags (`packages/cli`)**
  - Add `packages/cli/src/report.ts` and `packages/cli/src/report.test.ts` (TDD): `ReportCollector` capturing `op`, `app`, `environment`, `plans[]`, `changes[]`, `secrets[]`, `costs` delta from `CostLedger`, `pullRequest`, `verify`, `failure`, `nextSteps`, and `RecordingApprovalHandler`.
  - Wire global `--report <path>` (`OPSCREW_REPORT_PATH`), `--secrets-key-id`, `--secrets-key`, `--env-secrets-key-id`, `--env-secrets-key`, `--env-secrets-name` in `packages/cli/src/program.ts`, `packages/cli/src/context.ts`, and `packages/cli/src/deps.ts` so every command writes a valid, redacted `report.json` on `ok`, `needs-approval`, and `failed` (including `CommanderError`).
  - Wire `opscrew secrets restore --from-env` (reading `OPSCREW_RECOVERY_KEY`) and `--on-conflict use-copy|keep-local` in `packages/cli/src/commands/secrets.ts` + tests.
  - Add Actions local-target guard (`OPSCREW_ACTIONS_RUN=1`) refusing `localhost`, `mcp`, `vpn`, `secrets folder` with clear failure + `nextSteps` in `report.json`.

## Wave 4: `--plan-only` Parity Across Mutating Commands

- [x] **T4106 — `--plan-only` support in `destroy`, `promote`, `rollback`, `values` (`packages/cli`)**
  - Add `--plan-only` option and clean `needs-approval` reporting to `destroy`, `promote`, `rollback`, and `values set|unset` with TDD tests verifying Run 1 mutates nothing and emits exact plan hashes / `confirmPhrase` into `report.json`, and Run 2 applies on matching hash/confirm.
- [x] **T4107 — `--plan-only` support in `rotate`, `restore`, `retarget`, `secure` (`packages/cli`)**
  - Add `--plan-only` option and `needs-approval` reporting to `rotate`, `restore`, `retarget`, and `secure` with TDD tests.

## Wave 5: Guide Docs & Full-Repo Gate

- [ ] **T4108 — User & operator guide (`docs/guide/actions-runs.md`) and full-repo gate**
  - Write `docs/guide/actions-runs.md` covering the two-run model, `report.json` v1, sealed secret handoff, `OPSCREW_RECOVERY_KEY`, Anthropic/OpenAI WIF setup, and self-hosted runner cost savings.
  - Run full-repo gate (`pnpm lint`, `pnpm typecheck`, all Turbo test packages) on `041-actions-runs` and verify `gate exit 0`.
