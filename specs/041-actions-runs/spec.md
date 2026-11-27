# Feature Specification: OpsCrew Running in the User's GitHub Actions (041)

**Feature Branch**: `041-actions-runs`

**Created**: 2026-11-27

**Status**: Draft (roadmap 041; founder go-ahead 2026-11-21 & 2026-11-27; contract aligned with dashboard lead agreements of 2026-11-21, 2026-11-22, and 2026-11-25)

**Input**: `specs/roadmap.md` (041) and `specs/041-actions-runs/research.md` (R1–R9). Lets a user deploy, inspect, and operate their app from the hosted dashboard with nothing installed on their own computer, by running OpsCrew inside the user's own GitHub Actions while preserving Constitution I (hash-bound approvals) and Constitution IV (zero plaintext secrets in the dashboard, logs, or PRs).

## Scope Split (Core vs. Dashboard)

- **Core (this feature):**
  1. Versioned `report.json` schema (`schemaVersion: 1`), exported from `@opscrew/contracts` (types) and `@opscrew/core` (Zod schema, redacting writer, and AI cost aggregator).
  2. Global CLI `--report <path>` (or `OPSCREW_REPORT_PATH`) that writes a strictly redacted `report.json` on every command outcome (`ok`, `needs-approval`, `failed`), including plans/hashes/cost deltas/policy checks/`needsConfirm`, applied changes, verify result, pull request link, sealed `secrets[]`, per-model AI `costs`, failure details, and `nextSteps`.
  3. Sealed-box secret handoff (`--secrets-key-id`, `--secrets-key`, and optional `--env-secrets-key-id`, `--env-secrets-key`, `--env-secrets-name`, or `OPSCREW_SECRETS_*` env vars) so a workflow run whose `GITHUB_TOKEN` cannot write repository/environment secrets returns only libsodium-sealed ciphertext in `report.json`'s `secrets[]` for the dashboard's GitHub App to store.
  4. Ephemeral-runner state hydration and recovery-key sealing: `opscrew secrets restore --from-env` (reading `OPSCREW_RECOVERY_KEY`) and sealing newly generated recovery keys into `report.json`'s `secrets[]` on first run.
  5. Complete two-run `--plan-only` / `--approve <hash>` / `--confirm <name>` support across non-interactive commands (`provision`, `destroy`, `retarget`, `rollback`, `restore`, `rotate`, `promote`, `secure`, `addon`, `portainer`, `values`), and explicit refusal for local-machine-only targets (`localhost`, home hosting).
- **Dashboard (outside this repo, consumes this spec):**
  - Renders `opscrew-cloud.yml` (`operate` job with inputs `op`, `targets`, `args`, `hash`, `confirm`, `secrets_key_id`, `secrets_key`, `env_secrets_key_id`, `env_secrets_key`), dispatches runs via `workflow_dispatch` (`return_run_details: true`), reads `report.json` from the Actions artifact, displays plans for human approval, writes `secrets[]` ciphertext via its GitHub App, and displays AI costs per model.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Two-run plan and hash-bound apply with `report.json` (Priority: P1)

A user clicks "Provision" (or "Destroy", "Rotate", "Rollback", "Promote", "Retarget", "Restore", "Secure") in the dashboard. The dashboard dispatches Run 1 with `--plan-only --report report.json`. OpsCrew computes every plan, runs policy checks, changes nothing, and writes `report.json` with `status: "needs-approval"`, each plan's SHA-256 `planHash`, human-readable changes, monthly cost delta, policy results, and `needsConfirm` / `confirmPhrase`. After the user reviews and approves in the dashboard (typing the resource name when `needsConfirm` is true), the dashboard dispatches Run 2 with `--approve <hash>` (and `--confirm <name>` if needed) `--report report.json`. OpsCrew re-plans against live state, refuses with `status: "failed"` (`PLAN_HASH_MISMATCH`) if any hash changed, or applies and writes `report.json` with `status: "ok"`, applied changes, PR link, and next steps.

**Independent Test**: Run `opscrew provision --plan-only --yes --report <file>` against faked cloud/GitHub services, verify `report.json` parses cleanly against `RunReportSchema`, has `status: "needs-approval"`, exact `planHash`, cost delta, and policy results; then run with `--approve <hash> --yes --report <file>` and verify `status: "ok"`, and with a wrong hash verify `status: "failed"` with `code: "PLAN_HASH_MISMATCH"`.

### User Story 2 - Sealed-box secret handoff without exposing plaintext to the dashboard (Priority: P1)

During an Actions run, `GITHUB_TOKEN` cannot write repository or environment secrets. The dashboard passes GitHub's non-secret Actions public key (`--secrets-key-id`, `--secrets-key`, and optional environment key pair) to OpsCrew. When OpsCrew creates or updates a deploy secret (e.g. `OPSCREW_SSH_KEY`, `OPSCREW_APP_ENV`, or a first-run `OPSCREW_RECOVERY_KEY`), OpsCrew seals each value locally with libsodium `crypto_box_seal`, registers the plaintext with the redactor, and emits only `{ name, keyId, encryptedValue, place }` in `report.json`'s `secrets[]` array instead of calling GitHub's forbidden `PUT .../actions/secrets/{name}`.

**Independent Test**: Pass a test Curve25519 key pair's public key via `--secrets-key-id` and `--secrets-key`, run a command that creates deploy secrets with `fakeSecret` values, assert `report.json` contains zero plaintext secret substrings anywhere in the JSON text, and decrypt `secrets[].encryptedValue` with the test private key to verify byte-for-byte equality with the original secret.

### User Story 3 - Per-run AI cost accounting in `report.json` (Priority: P1)

When an Actions run executes an AI-assisted command (`analyze`, `adapt`, or `advise` with a model), OpsCrew summarizes only the `CostLedger` entries recorded during that run into `report.json`'s `costs` object (`totalUsd`, `byModel[]`, `entries[]`) so the dashboard can show AI spend per model without fetching `.opscrew/costs.jsonl`.

**Independent Test**: Pre-populate `.opscrew/costs.jsonl` with an older entry, run `opscrew analyze --report <file>` with a fake runtime that records two model calls across two models, and verify `report.json`'s `costs` contains only the two new entries, accurate `byModel` subtotals, and exact `totalUsd`.

### User Story 4 - Ephemeral runner state hydration via recovery copy (Priority: P2)

On a fresh GitHub-hosted runner with an empty `~/.opscrew`, the workflow sets `OPSCREW_RECOVERY_KEY` from a GitHub secret and runs `opscrew secrets restore --from-env --use-copy --report <file>` before running the target command. OpsCrew decrypts `opscrew/secrets.sops.json` into `~/.opscrew/projects/<id>/` and `.opscrew/` with `0600` permissions without ever prompting or writing the age private key to disk.

**Independent Test**: Run `opscrew secrets restore --from-env --report <file>` with `OPSCREW_RECOVERY_KEY` set and a fake SOPS binary; verify files are restored with `0600` mode, `report.json` has `status: "ok"`, and the age private key never appears in stdout, stderr, or `report.json`.

### User Story 5 - Complete `--plan-only` coverage and local-target refusal (Priority: P2)

Every mutating command used in Actions (`destroy`, `retarget`, `rollback`, `restore`, `rotate`, `promote`, `secure`, `values`) supports `--plan-only` so Run 1 can emit `report.json` with `planHash`, `needsConfirm`, and cost/change details without changing anything. Commands targeting local-only environments (`localhost`, home hosting, `mcp`, `vpn`) refuse cleanly when `--report` is paired with Actions execution (`OPSCREW_ACTIONS_RUN=1`) with a plain-English reason and `nextSteps`.

### Edge Cases

- A command crashes with an unexpected error or bad CLI flags (`CommanderError`): `--report <path>` still writes a valid `report.json` with `status: "failed"`, `failure.step`, redacted `failure.firstLine`, and `nextSteps`.
- A `--plan-only` run produces zero changes (already up to date): `report.json` reports `status: "ok"`, `plans: []`, and a plain-English summary saying nothing needs to change.
- A secret key pair is missing (`--secrets-key-id` without `--secrets-key`, or invalid base64 / wrong byte length): refused before any command work with `INVALID_INPUT` and `status: "failed"` in `report.json`.
- A public repository runs with `--report`: `report.json` contains zero plaintext secrets, zero private server IPs (redacted if registered), and zero personal tokens; sealed-box ciphertext in `secrets[]` is safe in public artifacts because only GitHub's private key can decrypt it.
- Multi-plan runs (e.g. own server = Cloudflare/infra plan + host plan): `plans[]` lists every plan in order with its own `kind`, `planHash`, `costDelta`, `policy`, and `needsConfirm`.

## Requirements *(mandatory)*

- **FR-4101 (Versioned report schema):** Export `RUN_REPORT_SCHEMA_VERSION = 1`, `RunReport`, `RunReportPlan`, `RunReportSecret`, `RunReportCosts`, `RunReportFailure`, and `RunReportStatus` from `@opscrew/contracts`, and `RunReportSchema`, `writeRunReport`, `summarizeRunCosts` from `@opscrew/core`.
- **FR-4102 (Global `--report <path>`):** `opscrew` accepts `--report <path>` (or `OPSCREW_REPORT_PATH`) on the root program, writes atomically on command completion (success, needs-approval, or failure), and runs every non-ciphertext string through `ctx.redactor.redact` before writing.
- **FR-4103 (Approval recording):** When `--report` is active, `createPhaseDeps` wraps the approval handler in a recording wrapper that captures every `ApprovalRequest` (`kind`, `title`, `details`, `planHash`, `allowDestroy`, `confirmPhrase`, `needsConfirm`, `costDelta`, `policy`, `approved`, `reason`) into the report.
- **FR-4104 (Sealed secret handoff):** `opscrew` accepts `--secrets-key-id <id>`, `--secrets-key <base64>` (and optional `--env-secrets-key-id`, `--env-secrets-key`, `--env-secrets-name`, or corresponding `OPSCREW_SECRETS_*` env vars). When configured, GitHub secret writes seal values with `sealSecret` (`crypto_box_seal`) and append `{ name, keyId, encryptedValue, place }` to `report.json`'s `secrets[]` without calling GitHub's `PUT .../actions/secrets/{name}` endpoint. Plaintext values are registered with the redactor immediately.
- **FR-4105 (Recovery copy hydration & first-run key sealing):** `opscrew secrets restore` accepts `--from-env` (reading `OPSCREW_RECOVERY_KEY`, registered as a secret env var in `@opscrew/core`) alongside `--use-copy` / `--keep-local` for non-interactive runner hydration. When `--secrets-key-id`/`--secrets-key` are configured and no recovery copy exists yet, `refreshRecoveryCopy` may seal a newly generated age identity directly into `secrets[]` as `OPSCREW_RECOVERY_KEY` (repo-scoped) without writing an unencrypted key file to disk.
- **FR-4106 (AI cost delta):** `report.json` includes `costs: { totalUsd, byModel, entries }` computed exclusively from `CostLedger` entries appended during the current command invocation.
- **FR-4107 (`--plan-only` parity):** Add `--plan-only` to `destroy`, `retarget`, `rollback`, `restore`, `rotate`, `promote`, `secure`, and `values set|unset`, ensuring Run 1 computes plans/hashes/required confirmation phrases without mutating infrastructure, GitHub secrets, or servers, and writes `status: "needs-approval"` to `report.json` when changes require approval.
- **FR-4108 (Local-only target guard):** When `OPSCREW_ACTIONS_RUN=1`, refuse `localhost`, `mcp`, `vpn`, `secrets folder`, and plans targeting `localhost` or home hosting before touching any external API, writing a clear `failure` + `nextSteps` to `report.json`.
- **FR-4109 (Dashboard contract documentation):** Document the exact `report.json` v1 schema, `operate` job inputs, `op` flags, `secrets[]` entry shape, and WIF/OIDC usage in `specs/041-actions-runs/contracts/report-schema.md` and `docs/guide/actions-runs.md`.

## Success Criteria *(mandatory)*

- **SC-4101:** `RunReportSchema.parse(JSON.parse(report))` succeeds on every CLI outcome (`ok`, `needs-approval`, `failed`).
- **SC-4102:** Tests with `fakeSecret` values prove zero plaintext secrets appear anywhere in `report.json`, stdout, stderr, or audit logs, while every `secrets[].encryptedValue` decrypts with libsodium `crypto_box_seal_open` to the exact plaintext.
- **SC-4103:** Two-run plan→apply tests (`provision`, `destroy`, `rotate`, `rollback`, `promote`, `values`) prove Run 1 mutates nothing and emits exact hashes/confirmPhrases, Run 2 applies only on matching hash + confirm, and Run 2 refuses on hash drift.
- **SC-4104:** `pnpm check` (lint + typecheck + full test suite) passes with zero regressions across all packages.
