# Running OpsCrew in GitHub Actions

OpsCrew can run inside your repository's own GitHub Actions — driven from the hosted OpsCrew
dashboard or your own `workflow_dispatch` workflow — without installing OpsCrew on your computer.
Every safety rule stays enforced inside OpsCrew: infrastructure changes still require an exact
SHA-256 plan hash, destructive changes still require the resource name, and plaintext secrets never
leave GitHub.

## Two-run plan and apply model

A single workflow run never pauses waiting for a human to click Approve (which would either require
GitHub Enterprise on private repositories or burn paid Actions minutes while idle). Instead, every
change runs as two short dispatches:

1. **Plan run (`--plan-only --report opscrew-report.json`):** computes every plan, runs policy
   checks, mutates nothing, and writes a versioned, redacted `report.json` (`schemaVersion: 1`)
   with `status: "needs-approval"`, each plan's SHA-256 `planHash`, cost delta, policy results, and
   whether a typed confirmation name is required (`needsConfirm`, `confirmPhrase`).
2. **Apply run (`--approve <hash>` [and `--confirm <name>`] `--report opscrew-report.json`):**
   re-plans against live state and refuses with `PLAN_HASH_MISMATCH` if anything drifted since the
   plan run.

Supported `--plan-only` commands include `provision`, `destroy`, `promote`, `rollback`, `restore`,
`rotate`, `retarget`, `secure --close-public-ssh|--open-public-ssh`, `addon enable|disable`,
`portainer enable|disable`, and `values set|unset`.

## Global flags for Actions runs

Pass these flags before the subcommand (or set the matching environment variables):

| Flag | Environment variable | Purpose |
|---|---|---|
| `--report <path>` | `OPSCREW_REPORT_PATH` | Atomically write a redacted `report.json` (`schemaVersion: 1`) on every outcome (`ok`, `needs-approval`, `failed`), including per-run AI costs from `.opscrew/costs.jsonl`. |
| `--secrets-key-id <id>` | `OPSCREW_SECRETS_KEY_ID` | Non-secret GitHub Actions repository public key ID. |
| `--secrets-key <base64>` | `OPSCREW_SECRETS_KEY` | Non-secret base64 Curve25519 repository public key. |
| `--env-secrets-key-id <id>` | `OPSCREW_ENV_SECRETS_KEY_ID` | Non-secret GitHub Actions environment public key ID. |
| `--env-secrets-key <base64>` | `OPSCREW_ENV_SECRETS_KEY` | Non-secret base64 Curve25519 environment public key. |
| `--env-secrets-name <name>` | `OPSCREW_ENV_SECRETS_NAME` | Required whenever `--env-secrets-key*` is set: exact GitHub environment name the key belongs to. |

Set `OPSCREW_ACTIONS_RUN=1` in the workflow environment so commands and plans that require your own
computer (`localhost`, home hosting `target.home`, `mcp`, `vpn`, `secrets folder`) fail fast with a
clear next step instead of trying to touch a local machine. Sealed secret key flags require
`--report <path>` (or `OPSCREW_REPORT_PATH`) so sealed secrets are never silently discarded.

## Sealed-box secret handoff

A workflow's `GITHUB_TOKEN` cannot write or delete repository or environment secrets. When
`--secrets-key-id` and `--secrets-key` (plus environment keys and `--env-secrets-name` when using
GitHub Environments) are supplied:

- OpsCrew seals each generated or updated secret locally with libsodium `crypto_box_seal` to
  GitHub's public key and emits **only ciphertext** in `report.json`'s `secrets[]` array:
  `{ name, keyId, encryptedValue, place }`.
- Secret removals (such as `values unset` or `destroy`) are recorded in `deletedSecrets[]`
  (`{ name, place }`) instead of calling GitHub's forbidden `DELETE` endpoint.
- The dashboard's GitHub App applies `secrets[]` and `deletedSecrets[]` only when `status` is
  `"ok"`, without ever seeing a plaintext value.
- On a public repository, uploading `opscrew-report.json` as an Actions artifact remains safe
  because every non-ciphertext field is redacted and only GitHub's private key can open
  `encryptedValue`.

## State across ephemeral runners (`OPSCREW_RECOVERY_KEY`)

GitHub-hosted runners start with an empty `~/.opscrew`. OpsCrew keeps its persistent state
encrypted in the repository's SOPS/age recovery copy (`opscrew/secrets.sops.json`, or per
environment under `opscrew/environments/<env>/secrets.sops.json`):

- **First run:** when `--secrets-key-id` and `--secrets-key` are passed and no recovery copy exists
  yet, OpsCrew generates an age keypair, encrypts `secrets.sops.json` to its public recipient, and
  seals the private key as `OPSCREW_RECOVERY_KEY` in `report.json`'s `secrets[]` without writing a
  plaintext key file to disk.
- **Later runs:** pass the stored `OPSCREW_RECOVERY_KEY` secret in the job environment and hydrate
  before running the requested operation:

```bash
npx opscrew secrets restore --from-env --use-copy --report hydrate-report.json
```

## AI keys and runner costs

- **Anthropic / OpenAI without static keys:** both Anthropic Console and OpenAI support Workload
  Identity Federation (OIDC) with `permissions: { id-token: write }`, scoping short-lived tokens to
  a specific repository and environment or branch. If you use Anthropic WIF, ensure no static
  `ANTHROPIC_API_KEY` is set in the job environment (a static key overrides WIF).
- **AI cost tracking:** every `report.json` includes `costs: { totalUsd, byModel, entries }`
  covering only the model calls made during that run.
- **Zero Actions minutes after initial setup:** once your app server has OpsCrew's self-hosted
  runner (`docs/guide/runners.md`), routine operations run there at $0/min in Actions minutes,
  while initial provisioning and server-destroying operations stay on GitHub-hosted runners.
