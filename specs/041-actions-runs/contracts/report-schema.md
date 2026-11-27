# Contract: `report.json` Schema (v1) and `operate` Job Interface (Feature 041)

**Contract Version:** `schemaVersion: 1`  
**Owners:** Types in `@opscrew/contracts` (`RunReport`, `RUN_REPORT_SCHEMA_VERSION`), Zod schema & writer in `@opscrew/core` (`RunReportSchema`, `writeRunReport`).  
**Audience:** OpsCrew CLI (`packages/cli`) and the hosted OpsCrew dashboard (`opscrew-cloud.yml`).

---

## 1. `operate` Job Inputs (`opscrew-cloud.yml`, Dashboard-Owned)

The dashboard dispatches `opscrew-cloud.yml` via `POST /repos/{owner}/{repo}/actions/workflows/opscrew-cloud.yml/dispatches` with `"return_run_details": true` and inputs:

| Input | Required | Description |
|---|---|---|
| `op` | Yes | OpsCrew subcommand (e.g. `provision`, `destroy`, `scan`, `analyze`, `design`, `adapt`, `status`, `verify`, `drift`, `advise`, `promote`, `rollback`, `rotate`, `restore`, `retarget`, `secure`, `values`, `snapshot`, `addon`, `portainer`). |
| `targets` | No | Target selector passed as `--env <env>` and/or `--app <key>` (default `prod`, first app). |
| `args` | No | Additional non-secret CLI flags (e.g. `--plan-only`, `--yes`, `--to <digest>`, `--allow-downtime`). Never contains plaintext secrets. |
| `hash` | No | One or more comma- or space-separated 64-char SHA-256 plan hashes mapped to repeatable `--approve <hash>`. |
| `confirm` | No | One or more typed resource confirmation names mapped to repeatable `--confirm <name>`. |
| `secrets_key_id` | No | Non-secret GitHub Actions repository public key ID (`GET /repos/{owner}/{repo}/actions/secrets/public-key`). |
| `secrets_key` | No | Non-secret base64 Curve25519 repository public key. |
| `env_secrets_key_id` | No | Non-secret GitHub Actions environment public key ID (when targeting a GitHub Environment). |
| `env_secrets_key` | No | Non-secret base64 Curve25519 environment public key. |
| `env_secrets_name` | No | Required when `env_secrets_key*` is set: exact GitHub Environment name the public key belongs to. |

The workflow sets `OPSCREW_ACTIONS_RUN=1`, hydrates `~/.opscrew` when `secrets.OPSCREW_RECOVERY_KEY` is set (`opscrew secrets restore --from-env --use-copy`), runs `opscrew --report opscrew-report.json ...`, and uploads `opscrew-report.json` as an Actions artifact (`name: opscrew-report`, `retention-days: 7`) with `if: always()`.

---

## 2. `report.json` v1 Shape

```json
{
  "schemaVersion": 1,
  "op": "provision",
  "app": "my-app",
  "environment": "prod",
  "opscrewVersion": "0.2.13",
  "startedAt": "2026-11-27T09:00:00.000Z",
  "finishedAt": "2026-11-27T09:00:42.000Z",
  "status": "needs-approval",
  "summary": "Planned 1 infrastructure change awaiting approval.",
  "plans": [
    {
      "kind": "iac-apply",
      "title": "Create 4 resources on Hetzner Cloud",
      "details": "Create: hcloud_server.app, hcloud_firewall.web, ...",
      "planHash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "allowDestroy": false,
      "needsConfirm": false,
      "costDelta": {
        "amount": 4.5,
        "currency": "EUR"
      },
      "policy": [
        {
          "policyId": "SEC-001",
          "title": "Firewall attached",
          "severity": "high",
          "passed": true,
          "message": "Server has a cloud firewall attached."
        }
      ],
      "approved": false
    }
  ],
  "changes": [],
  "secrets": [
    {
      "name": "OPSCREW_RECOVERY_KEY",
      "keyId": "012345678901234567",
      "encryptedValue": "<base64-libsodium-sealed-box>",
      "place": { "kind": "repo" }
    },
    {
      "name": "OPSCREW_APP_ENV",
      "keyId": "987654321098765432",
      "encryptedValue": "<base64-libsodium-sealed-box>",
      "place": { "kind": "environment", "environment": "production" }
    }
  ],
  "deletedSecrets": [],
  "costs": {
    "totalUsd": 0.0215,
    "byModel": [
      { "model": "claude-sonnet-4-6", "costUsd": 0.0215, "calls": 1 }
    ],
    "entries": [
      {
        "at": "2026-11-27T09:00:12.000Z",
        "phase": "analyze",
        "model": "claude-sonnet-4-6",
        "costUsd": 0.0215
      }
    ]
  },
  "pullRequest": {
    "url": "https://github.com/owner/repo/pull/12",
    "number": 12
  },
  "verify": {
    "passed": true,
    "summary": "HTTPS answered 200 on https://app.example.com/health"
  },
  "nextSteps": [
    "Review the plan above and approve hash 0123456789abcdef... to apply."
  ]
}
```

### Field semantics

- `schemaVersion`: literal `1`. Breaking changes bump to `2`.
- `status`:
  - `"ok"` — command completed cleanly with nothing awaiting approval.
  - `"needs-approval"` — plan(s) computed and awaiting `--approve <hash>` (and `--confirm <name>` if any plan has `needsConfirm: true`).
  - `"failed"` — command stopped with an error; `failure` is populated.
- `plans[]`: every `ApprovalRequest` encountered during the run, in order. `needsConfirm` is `true` iff `confirmPhrase !== undefined` (or `allowDestroy === true`).
- `secrets[]`: sealed-box ciphertexts only (`libsodium` `crypto_box_seal`, original base64). `place` is `{ kind: "repo" }` or `{ kind: "environment", environment: "<github-env-name>" }`. The dashboard writes each entry via GitHub's `PUT .../actions/secrets/{name}` with `{ encrypted_value, key_id }` **only when `status === "ok"`** (never on `"needs-approval"` or `"failed"`).
- `deletedSecrets[]`: secret names and places to remove via GitHub's `DELETE .../actions/secrets/{name}` when `status === "ok"` (for example after `values unset` or `destroy`).
- `costs`: always present (zeroed `{ totalUsd: 0, byModel: [], entries: [] }` when no model ran).
- `failure` (present when `status === "failed"`):
  - `code`: OpsCrew `ErrorCode`, `"CLI_USAGE"`, `"REFUSED"` (command exited 1 via `CliExit`), `"FAILED"` (command exited non-zero via `CliExit`), or `"UNEXPECTED"`.
  - `step`: phase or command name where failure occurred.
  - `firstLine`: single-line redacted error message (never multi-line stack traces).
  - `hint`: optional redacted plain-English recovery instruction.
- `nextSteps[]`: plain-English, redacted next-action lines for the user/dashboard.

### Known limit: staged rotation values across ephemeral runners

Rotations that stage a random next value locally before approval (such as add-on or Portainer credential rotations) bind their plan hash to that staged value. Running Run 1 and Run 2 on two separate ephemeral runners produces a different staged value and hash unless both runs share the same self-hosted runner workspace.

---

## 3. Redaction & Public Repository Guarantee

Before `report.json` is written:
1. Every plaintext secret generated or read during the run is registered with `Redactor`.
2. Every non-ciphertext string in `RunReport` (`summary`, `plans[].title`, `plans[].details`, `plans[].policy[].message`, `changes[]`, `verify.summary`, `failure.firstLine`, `failure.hint`, `nextSteps[]`) passes through `Redactor.redact`.
3. `secrets[].encryptedValue` is validated as base64 ciphertext produced by `sealSecret` and never contains plaintext.
