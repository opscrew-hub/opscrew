# Research: OpsCrew Running in the User's GitHub Actions (Feature 041)

**Date:** 2026-11-26 | **Issue:** `#49` | **Scope:** Research only (no code), covering Feature 041 and the "Anthropic without a stored key in Actions" roadmap item.  
**Honesty rule:** Every answer cites official GitHub, Anthropic, or OpenAI documentation checked on **2026-11-26**. Any detail not directly confirmed in an official source is explicitly marked **unverified**.

---

## R1. Starting a Run from Outside (`workflow_dispatch` via REST API + GitHub App)

### Endpoint & GitHub App permissions
- **Endpoint:** `POST /repos/{owner}/{repo}/actions/workflows/{workflow_id}/dispatches`
- **Required GitHub App installation token permissions:**
  - `Actions: write` (to dispatch runs, cancel, or rerun);
  - `Actions: read` (to read run/job status, download logs, and fetch artifacts);
  - `Secrets: write` (only when the dashboard writes sealed-box ciphertext returned by a run into repo/env secrets, per roadmap 041);
  - `Pull requests: write` / `Contents: write` (only if the workflow itself opens PRs using its own `GITHUB_TOKEN`, not required on the dashboard's dispatch call).

### Inputs & payload limits
- **Maximum top-level inputs:** **25** input properties per `workflow_dispatch` trigger (expanded from GitHub's older limit of 10).
- **Input payload size limit:** reported `~65,535 characters` total JSON payload (**unverified** on the cited REST API page; `inputs` values are strings/booleans/numbers/choices — never pass plaintext secrets in `inputs` because dispatch inputs are recorded in run metadata and visible in the Actions UI/API!).

### Learning the run ID immediately (`return_run_details`)
- GitHub's `POST .../dispatches` endpoint supports `"return_run_details": true` in the request body:
  ```json
  {
    "ref": "main",
    "inputs": { "op": "provision", "targets": "prod", "args": "--plan-only" },
    "return_run_details": true
  }
  ```
- When `return_run_details: true`, GitHub responds with **`200 OK`** containing `{ "workflow_run_id": ..., "run_url": "...", "html_url": "..." }` directly — eliminating legacy timestamp/correlation-ID guessing!
- When omitted or `false`, GitHub returns **`204 No Content`** with an empty body.

### Following run status and logs
- **Push status updates (preferred over polling):** Subscribe the GitHub App to `workflow_run` (`requested`, `in_progress`, `completed`) and `workflow_job` (`queued`, `in_progress`, `completed`, `waiting`) webhooks.
- **Polling / reconciliation REST endpoints:**
  - `GET /repos/{owner}/{repo}/actions/runs/{run_id}` (overall `status` & `conclusion`);
  - `GET /repos/{owner}/{repo}/actions/runs/{run_id}/jobs` (per-step status & timestamps).
- **Logs:**
  - `GET /repos/{owner}/{repo}/actions/runs/{run_id}/logs` (returns `302` to a short-lived signed ZIP download URL, requires `Actions: read`);
  - `GET /repos/{owner}/{repo}/actions/jobs/{job_id}/logs` (plain-text log for one job).
  - **Limitation:** GitHub's public REST API does not expose a live streaming log WebSocket/SSE endpoint while a job is still running (job logs are reliably downloadable once the job completes; mid-run visibility comes from `workflow_job` step status webhooks or outbound progress updates).

### Citations (R1)
- GitHub REST API — Create a workflow dispatch event (`return_run_details`, `Actions: write`, 25 inputs): https://docs.github.com/en/rest/actions/workflows#create-a-workflow-dispatch-event (checked 2026-11-26)
- GitHub REST API — Download workflow run & job logs: https://docs.github.com/en/rest/actions/workflow-runs#download-workflow-run-logs (checked 2026-11-26)
- GitHub Webhooks — `workflow_run` and `workflow_job` events: https://docs.github.com/en/webhooks/webhook-events-and-payloads#workflow_run (checked 2026-11-26)

---

## R2. Approvals Inside a Run vs. OpsCrew's Two-Run Model

### Plan availability on private repositories (critical constraint!)

| GitHub feature | Public repo (all plans) | Private repo — Free | Private repo — Pro / Team | Private repo — Enterprise |
|---|---|---|---|---|
| **Environments, environment secrets, deployment branches** | Yes | **No** | **Yes** | **Yes** |
| **Required reviewers (up to 6 users/teams) & Wait timers (1–43,200 min / 30 days)** | Yes | **No** | **No** | **Yes** |
| **Custom deployment protection rules (GitHub App webhook gate, up to 6/env)** | Yes | **No** | **No** | **Yes** |

### Can a single job wait for an external hash-bound approval from the dashboard?
- **Option A — GitHub Environments required reviewers / custom deployment protection rules:**
  - Can pause a workflow run for up to **30 days** at zero Actions-minute cost while waiting.
  - **Dealbreakers for OpsCrew 041:** (1) Unavailable on private repositories for **Free, Pro, and Team** users (Enterprise-only!), and (2) GitHub's approval UI/API approves a deployment *environment gate* generically — it does not enforce OpsCrew's SHA-256 **plan hash** or typed destructive resource name (`--confirm <name>`) inside the runner.
- **Option B — A running job that polls/sleeps waiting for an external dashboard callback:**
  - Can technically verify a hash-bound approval once the dashboard answers, **but** burns paid Actions minutes continuously while waiting for a human to review the plan, occupies a concurrency slot, and is hard-killed at GitHub's **6-hour** hosted job execution limit (**5 days** on self-hosted runners).
- **Option C — Two separate `workflow_dispatch` runs (agreed in roadmap 041, strongly validated here):**
  1. **Plan run (`--plan-only`):** Runs OpsCrew, emits `report.json` containing the plan summary, cost delta, policy results, `planHash`, and `needsConfirm`. Finishes in seconds–minutes; **zero minutes burned while the user reviews the plan** (even if they approve days later!).
  2. **Apply run (`--approve <hash>` + `--confirm <name>`):** Dispatched by the dashboard only after the user approves in the UI; re-plans against live state and **refuses if the recomputed SHA-256 hash differs** from `<hash>`.
  - Works identically on **GitHub Free, Pro, Team, and Enterprise** (public and private repos), enforces constitution I's hash-bound gate deterministically inside OpsCrew, and wastes zero runner minutes.

### Citations (R2)
- GitHub Docs — Managing environments for deployment (plan matrix, required reviewers, 30-day wait timers): https://docs.github.com/en/actions/managing-workflow-runs-and-deployments/managing-deployments/managing-environments-for-deployment (checked 2026-11-26)
- GitHub Docs — Creating custom deployment protection rules (Enterprise-only on private repos, 30-day timeout): https://docs.github.com/en/actions/managing-workflow-runs-and-deployments/managing-deployments/creating-custom-deployment-protection-rules (checked 2026-11-26)

---

## R3. Secrets and Log Masking Limits

### Keeping the user's provider tokens invisible to the dashboard
1. **Stored user tokens:** The user saves cloud/DNS/hosting tokens directly into their repository's **GitHub Environment Secrets** (Pro/Team/Enterprise private repos, or public repos) or **Repository Secrets** (Free private repos). The dashboard's GitHub App only holds `Actions: write` (and optionally `Secrets: write` for sealed ciphertext) — **GitHub's Secrets API is write-only**, so the dashboard can **never read** any secret value back.
2. **Keyless cloud auth (OIDC):** For AWS, Azure, Google Cloud, Anthropic, and OpenAI, the workflow uses `permissions: { id-token: write }` to mint short-lived tokens at runtime — no static provider secret exists in GitHub at all.
3. **New state generated during a run (roadmap 041 sealed-box pattern):** A workflow's `GITHUB_TOKEN` cannot write repository/environment secrets. Passing the target's non-secret GitHub Actions public key (`key_id` + `key`) in `workflow_dispatch` inputs lets OpsCrew seal newly generated values (deploy SSH key, state passphrase) using libsodium sealed boxes (`crypto_box_seal`) and return **only ciphertext** in `report.json`. The dashboard writes the ciphertext via `PUT .../actions/secrets/{name}` without ever seeing plaintext.
4. **GitHub Secret quotas:** **48 KB** maximum size per secret; **100** repository secrets per repo; **100** environment secrets per environment; **1,000** organization secrets (only the first 100 alphabetically are exposed to any workflow). Larger encrypted blobs (such as OpsCrew's recovery copy) stay committed encrypted (`sops`/age) in the repo with only the decryption key in Secrets.

### What GitHub masks in logs — and its limits
GitHub's runner automatically registers secret values (and dynamic `::add-mask::` values) for runner-side stdout/stderr redaction, **but masking is best-effort and has critical blind spots**:
1. **Line-by-line literal matching only:** `::add-mask::` stops at the first newline. Passing a **multiline secret** (SSH private key, PEM cert, `.env` file, pretty-printed JSON) masks **only the first line**, leaving lines 2..N in plaintext unless each line is masked individually.
2. **Structured data & derived encodings are NOT masked:** GitHub explicitly warns *never to store structured data (JSON/YAML) as a secret* — JSON-escaped quotes, base64 encodings, URL encodings, substrings, or reformatted whitespace bypass exact-match masking.
3. **Persistence if leaked:** Once an unmasked line hits logs, it remains readable for the full log retention window (up to 90 days default) until the entire run's logs are deleted and the credential is rotated.
4. **OpsCrew requirement:** Never rely on GitHub's masking as the sole safeguard — every CLI output, error message, and `report.json` MUST continue passing through `@opscrew/core`'s `Redactor` before being written to stdout, stderr, or disk.

### Citations (R3)
- GitHub Docs — Using secrets in GitHub Actions (48 KB / 100 secret limits, structured data warning): https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions (checked 2026-11-26)
- GitHub Docs — Workflow commands (`::add-mask::`, line-by-line limitation): https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/workflow-commands-for-github-actions#masking-a-value-in-a-log (checked 2026-11-26)

---

## R4. AI Keys Without Storing Them: Anthropic & OpenAI Workload Identity Federation

### 1. Anthropic Console Workload Identity Federation (OIDC for GitHub Actions)
- **Status:** **Supported natively** on the Claude Platform (Console) — eliminates storing static `ANTHROPIC_API_KEY` secrets in GitHub Actions!
- **How it works:**
  1. In Claude Console (`Settings -> Workload identity`), the user creates an OIDC identity provider for `https://token.actions.githubusercontent.com`, binds a **Service Account** (scoped to a specific workspace), and defines a **Federation Rule** matching incoming JWTs via **`subject_prefix`**, **`claims`**, and/or **CEL** expressions.
  2. The GitHub Actions job requests `permissions: { id-token: write, contents: read }` and reads three non-secret IDs from Actions `vars`: `anthropic_organization_id`, `anthropic_service_account_id`, and `anthropic_federation_rule_id`.
  3. At runtime, the workflow (or OpsCrew's runtime / `anthropics/claude-code-action`) exchanges GitHub's OIDC JWT via an OAuth 2.0 JWT-bearer grant (`POST /v1/oauth/token`) for a short-lived Anthropic access token (`sk-ant-oat01-...`).
- **Scoping to one repository and environment:** **Yes!** The Federation Rule supports **`subject_prefix`**, exact **`claims`** matching, and **CEL** expressions against GitHub's OIDC JWT:
  - Repository + environment: `repo:<owner>/<repo>:environment:<env>` (or `repo:<owner>@<owner_id>/<repo>@<repo_id>:environment:<env>` for repos created on/after 2026-07-15 with immutable subject claims);
  - Repository + branch (for GitHub Free private repos): `repo:<owner>/<repo>:ref:refs/heads/<branch>`.
  - Fork pull requests cannot mint tokens matching these subjects.
- **Token lifetime:** The minted Anthropic access token's effective lifetime is the **lesser of** the Federation Rule's configured lifetime (`60 s` to `86,400 s` / 24 hours, default 1 hour) and **twice the GitHub OIDC token's remaining life**.
- **One exchange per GitHub token:** Each GitHub OIDC JWT can be exchanged **only once** (`jti` reuse is rejected), so a refresh or subsequent step must request a fresh GitHub OIDC JWT before calling `/v1/oauth/token` again.
- **Cost:** API token usage bills to the bound workspace/service account; Anthropic's WIF documentation does not state a separate federation surcharge (whether `$0` surcharge / all plan tiers apply is **unverified**).
- **Critical precedence gotcha:** If a static `ANTHROPIC_API_KEY` environment variable is also present in the job, **the static key silently takes precedence over WIF**. Workflows using WIF must unset / omit `ANTHROPIC_API_KEY`.
- **Note for OpsCrew 041:** Because OpsCrew 041 also supports routing through the dashboard's gateway (`ANTHROPIC_BASE_URL`), Anthropic WIF is ideal for **direct user-owned Actions runs** (no static key stored in the repo) AND for **managed dashboard runs** where the user wants billing directly in their own Anthropic workspace.

### 2. Does OpenAI offer the same?
- **Yes — OpenAI also supports Workload Identity Federation (WIF)!**
  - **Setup:** Registering `https://token.actions.githubusercontent.com` with claim mappings & trust rules scoped by repository, branch, or environment (the exact console path `Organization Settings > Security > Workload Identity Provider` is **unverified**).
  - **Exchange flow:** The job (`id-token: write`) fetches a GitHub OIDC token and exchanges it for a short-lived OpenAI access token mapped to a project service account (the exact exchange endpoint `https://auth.openai.com/oauth/token` and audience `https://api.openai.com/v1` are **unverified**).
  - **Token lifetime:** Reported `60–3,600 seconds` (1 hour maximum) is **unverified**.
  - **Cost & plan availability:** Any `$0` federation surcharge claim and whether self-serve WIF configuration is enabled on every basic pay-as-you-go organization or gated to Enterprise / specific usage tiers are **unverified** — verify on a standard developer org before exposing as default for solo users.
  - *(Fallback keyless paths also exist via cloud OIDC: AWS Bedrock / GCP Vertex AI for Claude, and Azure OpenAI via Entra WIF for OpenAI.)*

### Citations (R4)
- Anthropic Platform Docs — Workload Identity Federation: https://platform.claude.com/docs/en/manage-claude/workload-identity-federation (checked 2026-11-26)
- OpenAI Developer Docs — Workload Identity Federation: https://developers.openai.com/api/docs/guides/workload-identity-federation (checked 2026-11-26)

---

## R5. Reporting Back (`report.json` with Results, Sealed Secrets, and AI Cost per Model)

### Artifacts vs. Outbound HTTPS Callback from the Job

| Criterion | **GitHub Actions Artifact** (`actions/upload-artifact` v4) | **Outbound HTTPS Callback** (job `POST`s `report.json` to dashboard) |
|---|---|---|
| **Size limits** | Individual artifact upload up to ~10 GB (**unverified** exact per-file cap; total account storage per GitHub's billing page: **500 MB Free**, **1 GB Pro**, **2 GB Team**, **50 GB Enterprise Cloud**, shared with Packages). A `report.json` is ~5–50 KB (negligible). | Dashboard-controlled (typically 1–10 MB JSON limit). |
| **Retention limits** | Configurable **1–90 days** (public repos) via `retention-days:` input (reported up to **400 days** on private repos is **unverified**; set `retention-days: 7` or `1` to keep Free-plan 500 MB storage near zero). | Stored directly in dashboard DB. |
| **Authentication** | Zero callback credentials needed on the runner; dashboard's GitHub App fetches the ZIP via `GET /actions/runs/{run_id}/artifacts` (`Actions: read`) after `workflow_run.completed`. | **Use the job's GitHub OIDC JWT** (`id-token: write`, `audience: https://<dashboard-host>`) verified by the dashboard against GitHub's JWKS for exact `repository` + `run_id`! Never pass a static callback secret in `workflow_dispatch` inputs (inputs are visible in plaintext). |
| **Latency & reliability** | Slight delay (artifact upload + `workflow_run.completed` webhook + ZIP download); **100% durable** even if the dashboard briefly restarts during the run! | **Sub-second** delivery upon step completion (and can send live step progress), but requires retry logic if the dashboard is temporarily unreachable. |
| **Public repository visibility** | **CRITICAL:** On **public repos**, anyone signed into GitHub can download Actions artifacts! `report.json` MUST contain zero plaintext secrets, private IPs, or personal emails (roadmap 041's sealed-box ciphertext is safe to expose publicly because only GitHub's private key can decrypt it). | Private between runner and dashboard over HTTPS even on public repos. |

### Recommendation for OpsCrew 041
- **Canonical record:** Always upload `report.json` (strictly redacted, with `retention-days: 7`) as a **GitHub Actions Artifact** (`opscrew-report`), so the dashboard can reliably fetch and reconcile any completed run via `Actions: read` with zero lost reports.
- **Optional fast path:** If the dashboard wants sub-second completion updates without waiting for the `workflow_run` webhook, let the workflow optionally `POST report.json` authenticated with the job's **GitHub OIDC JWT** (`id-token: write`, verifying `repository` + `run_id` server-side), falling back to the artifact on any network error.

### Citations (R5)
- GitHub Docs — Storing and sharing data from a workflow (Artifacts): https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/storing-and-sharing-data-from-a-workflow (checked 2026-11-26)
- GitHub Docs — Billing for GitHub Actions (artifact storage quotas: 500 MB Free, 1 GB Pro, 2 GB Team, 50 GB Enterprise): https://docs.github.com/en/billing/managing-billing-for-products/managing-billing-for-github-actions/about-billing-for-github-actions (checked 2026-11-26)
- GitHub REST API — List & download workflow run artifacts: https://docs.github.com/en/rest/actions/artifacts (checked 2026-11-26)

---

## R6. GitHub Actions Costs, Quotas, and Limits

### Monthly included compute & per-minute rates (checked 2026-11-26)
- **Public repositories:** Standard GitHub-hosted runners are **free and unmetered**.
- **Private repositories (included monthly compute pool, standard 2-core Linux rate = `$0.006/min`):**
  - **GitHub Free:** `$12/mo` included (~**2,000** standard Linux minutes) + **500 MB** artifact/package storage.
  - **GitHub Pro:** `$18/mo` included (~**3,000** standard Linux minutes) + **1 GB** storage.
  - **GitHub Team:** `$18/mo` included (~**3,000** standard Linux minutes) + **2 GB** storage.
  - **GitHub Enterprise Cloud:** `$300/mo` included (~**50,000** standard Linux minutes) + **50 GB** storage.
  - *(Windows, macOS, and larger Linux runners draw from the same monthly dollar/compute allowance at higher per-minute rates.)*
- **Self-hosted runners:** **$0/min** from GitHub (note: the status of any previously proposed/postponed self-hosted runner platform fee is **unverified** on the cited billing page). Running post-setup OpsCrew operations on the user's server runner (per roadmap 041) keeps private-repo Actions bills at **$0** for routine operations!

### Execution time & concurrency limits

| Limit | GitHub-hosted runner | Self-hosted runner |
|---|---|---|
| **Max single job execution time** | **6 hours** | **5 days** |
| **Max total workflow run time (incl. waits/approvals)** | **35 days** | **35 days** |
| **Max job queue time** | **24 hours** (**unverified** if shorter on hosted) | **24 hours** |
| **Max queued runs per concurrency group** | **100** | **100** |
| **Max concurrent jobs per account (all repos)** | **Free: 20** (5 macOS) · **Pro: 40** (5 macOS) · **Team: 60** (5 macOS) · **Enterprise: 500** (50 macOS) | Limited by user's registered runners (subject to GitHub API rate limits) |

### Implications for OpsCrew 041
- An OpsCrew plan or apply run typically finishes in 1–5 minutes (well under the 6-hour hosted cap); only huge initial DB copies/moves approach an hour.
- On GitHub Free private repos (~2,000 Linux min/mo), running `plan` + `apply` (~4 min combined) supports ~500 operations/month on hosted runners alone, and becomes unmetered once shifted to the app's self-hosted server runner.
- Concurrency group `opscrew-operate-<app>-<env>` with `cancel-in-progress: false` guarantees two operations never mutate the same environment simultaneously while staying well below the 100-queued-runs cap.

### Citations (R6)
- GitHub Docs — Billing for GitHub Actions (included compute, `$0.006/min` standard Linux, storage, self-hosted runner pricing): https://docs.github.com/en/billing/managing-billing-for-products/managing-billing-for-github-actions/about-billing-for-github-actions (checked 2026-11-26)
- GitHub Docs — Usage limits, billing, and administration (6 h / 5 d / 35 d limits, concurrency caps): https://docs.github.com/en/actions/administering-github-actions/usage-limits-billing-and-administration (checked 2026-11-26)

---

## R7. Codebase Inventory: What Lives in `~/.opscrew` and `.opscrew` (Checked 2026-11-27)

Inspected `packages/core/src/paths.ts`, `packages/agents/src/secrets/files.ts`, `packages/agents/src/secrets/copy.ts`, and `packages/agents/src/secrets/restore.ts`.

### Complete state surface
OpsCrew already encapsulates every stateful file that cannot be rebuilt in the SOPS/age recovery copy (`opscrew/secrets.sops.json`, or `opscrew/environments/<env>/secrets.sops.json`, or under `opscrew/apps/<key>/…`):
- **16 `HOME_FILES`** in `~/.opscrew/projects/<projectId>/`:
  `generated_values.json`, `app_values.json`, `deploy_key`, `deploy_key.pub`, `known_hosts`, `state_passphrase`, `deploy_secrets.json`, `portainer-env.key`, `portainer-webhook`, `portainer_password`, `check_key`, `preview_key`, `preview_key.pub`, `beszel_secrets.json`, `grafana_cloud_token`, `uptime_report_key`.
- **4 `STATE_FILES`** + OpenTofu state in `.opscrew/`:
  `server.json`, `cloudflare.json`, `hosting.json`, `uptime.json`, plus `tfstate/*.tfstate`.
- **Ephemeral per-run files (not persisted between Actions runs):**
  `state.json`, `approvals.jsonl`, `costs.jsonl` (summarized into `report.json`), `plans/*` (saved plans are re-computed deterministically during the apply run and hash-verified).

### Ephemeral runner hydration & first-run bootstrap
1. **Subsequent runs:** The workflow passes the user's age private key via GitHub secret `OPSCREW_RECOVERY_KEY` (read from env, never written unencrypted to the repository). `opscrew secrets restore --from-env` (or automatic runner hydration before the command) decrypts `secrets.sops.json` into `~/.opscrew/projects/<id>/` and `.opscrew/` with `0600` permissions. After the command completes, `refreshRecoveryCopy` re-encrypts updated files using the public `age1…` recipient in `opscrew/.sops.yaml` (no private key needed for encryption) and commits only ciphertext in the run's PR.
2. **First run (no recovery copy yet):** OpsCrew generates a fresh age identity, encrypts `secrets.sops.json` to its public recipient (`age1…`), and **seals the private `AGE-SECRET-KEY-1…`** to the dispatched `secrets_key_id` + `secrets_key` into `report.json`'s `secrets[]` as `{ name: "OPSCREW_RECOVERY_KEY", keyId, encryptedValue, place: { kind: "repo" } }`. On a public repository, the first run still emits only ciphertext in `secrets.sops.json` when explicitly enabled (`--allow-public-recovery-copy`), or fails closed with a clear hint.
3. **GitHub deploy secrets generated or updated during a run:** A workflow's `GITHUB_TOKEN` cannot write repository or environment secrets. Passing `--secrets-key-id <id> --secrets-key <base64>` (and optionally `--env-secrets-key-id <id> --env-secrets-key <base64> --env-secrets-name <githubEnv>`) routes secret writes through libsodium sealed-box encryption (`packages/connectors/github/src/seal.ts`, `sealSecret`) and records each sealed entry in `report.json`'s `secrets[]` (`{ name, keyId, encryptedValue, place }`), so the dashboard stores ciphertext via its GitHub App without ever reading plaintext.

---

## R8. Codebase Audit: Non-Interactive Flags Across All CLI Commands (Checked 2026-11-27)

Inspected all 35 command modules in `packages/cli/src/commands/*.ts` and `packages/cli/src/approval.ts`.

### Existing non-interactive approval primitives
`packages/cli/src/approval.ts` already implements:
- `NonInteractiveApprovalHandler` (`--approve <hash>` repeatable for `iac-apply`, `host-apply`, `stack-apply`, `cloudflare-apply`, `pages-apply`, `hosting-apply`, `promote`, `github-secrets`; `--yes` only for `repo-write`, `github-secrets`, `github-settings`, `git-push`, `pull-request`, never for applies or destroys).
- `FlagConfirmation` (`--confirm <name>` paired with `--approve <hash>` for deletions/replacements).
- `MaintenanceWindowApproval` (`--allow-downtime`), `withServerRepair` (`--confirm <app>` + `--approve <hash>`).
- `CliContext.isInteractive` automatically evaluates to `false` when `CI=true` or non-TTY.

### Command matrix for Feature 041 (`op`)
- **Excluded in Actions (require user's local computer; fail closed with `PHASE_PRECONDITION` when `--report` / Actions mode targets them):**
  - `localhost` (`trust`, `untrust`, and any command whose plan targets `target.provider: localhost` or `target.home: true`),
  - `mcp` (`install`, `uninstall`),
  - `vpn` (local device key generation / local WireGuard client config),
  - `secrets folder` (local desktop backup folder).
- **Read-only / analysis commands (single run, emit `report.json` with `status: "ok"` or `"failed"`):**
  `scan`, `analyze`, `interview --answers <file>`, `design`, `status`, `verify`, `drift`, `advise`, `logs`, `providers`, `values list`, `secrets status`, `env list`, `app list`, `preview list`, `snapshot list`.
- **Two-run plan/apply commands already having `--plan-only`:**
  `provision`, `addon enable|disable`, `portainer enable|disable`.
- **Two-run plan/apply commands currently missing `--plan-only` (must add in 041):**
  - `destroy` (currently has `--approve`, `--confirm`, no `--plan-only` dry preview emitting plan hashes + required `--confirm` phrase into `report.json`),
  - `retarget` (has `--answers`, `--approve`, `--confirm`, `--allow-downtime`, `--yes`, no `--plan-only`),
  - `rollback` (has `--to`, `--approve`, `--confirm`, `--yes`, no `--plan-only`),
  - `restore` (has `--approve`, `--confirm`, `--yes`, no `--plan-only`),
  - `rotate` (has `--approve`, `--confirm`, `--yes`, no `--plan-only`),
  - `promote` (has `--version`, `--approve`, `--yes`, no `--plan-only`),
  - `secure` (has `--approve`, `--yes`, no `--plan-only`),
  - `values set|unset` (currently uses `--yes` + `--from-file`, needs `--plan-only` and `github-secrets` summary in `report.json`).

---

## R9. Codebase Audit: Cost Ledger and Sealed-Box Helpers (Checked 2026-11-27)

- **Cost ledger (`packages/core/src/state.ts`):** `CostLedger` appends JSONL records `{ at, phase, model?, costUsd }` to `paths.files.costs` (`.opscrew/costs.jsonl`). Capturing the entry count before a CLI command runs and slicing new entries appended after it gives the exact per-run AI spend, totalled overall and grouped by `model` (with `unknown` fallback if `model` is omitted), with zero duplicate accounting.
- **Sealed-box encryption (`packages/connectors/github/src/seal.ts`):** `sealSecret(publicKeyBase64, value)` already uses `libsodium-wrappers` `crypto_box_seal` with `ORIGINAL` base64 variant — byte-identical to what GitHub's `PUT /repos/{owner}/{repo}/actions/secrets/{secret_name}` and `PUT /repos/{owner}/{repo}/environments/{env}/secrets/{secret_name}` require.
- **Redaction (`packages/core/src/redact.ts`):** Every string placed in `report.json` (titles, details, failure lines, hints, next steps) MUST pass through `ctx.redactor.redact` before serialization; `secrets[].encryptedValue` is base64 libsodium ciphertext (never plaintext) and each plaintext value is registered with `ctx.redactor.addLiteral` before sealing so it can never leak into any other field.
