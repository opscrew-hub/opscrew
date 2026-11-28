# Implementation Plan: Self-Hosted Gitea Provisioning & App Integration (Feature 043 Follow-Up)

**Feature:** `043-gitea-self-hosted` | **Issue:** `#70` | **Base Branch:** `origin/042-git-platforms`

## Constitution Check

- **I. Safety Gate on Every Mutation:** Every server mutation runs through `planGitea` (`HostPlan`) -> `evaluateGiteaPolicies` -> SHA-256 hash-bound `host-apply` approval -> `applyHostPlan`. Destructive volume deletion requires `allowDestroy` + typed confirmation of the app name.
- **II. The User Owns Everything:** Standard `compose.yaml` + edge proxy site files (`Caddyfile`/`nginx.conf`/`vhconf`), standard `gitea/gitea` & `postgres` images, plain `opscrew/plan.yaml`.
- **IV. Secrets Never Leak:** All Gitea secrets (`adminPassword`, `secretKey`, `internalToken`, `jwtSecret`, `lfsJwtSecret`, `postgresPassword`, `webhookSecret`, `appToken`) are generated locally with `0600` permissions, registered with `Redactor`, passed to the host strictly over stdin (`ApplySecrets`), and omitted from plans, compose files, logs, audit entries, and MCP tool output.
- **V. Deterministic First:** Schema validation, template rendering, SecOps policy evaluation, snapshot scripting, host planning, and app integration metadata are 100% deterministic.
- **VI. Contracts-First Boundaries:** All cross-package imports go through package roots (`@opscrew/plan-schema`, `@opscrew/iac-templates`, `@opscrew/secops`, `@opscrew/connector-ssh-host`, `@opscrew/agents`).
- **X. Lean Dependencies:** Zero new npm dependencies.

## Shared-File Changes (Additive Only)

- `packages/core/src/paths.ts`: add optional/standard `giteaSecrets` path under `ProjectFiles` (`gitea_secrets.json` in `projectHomeDir`).
- `packages/core/src/testing/fake-secrets.ts`: add `gitea-webhook-secret` / reuse existing `gitea-token` for secret-free tests if helpful.
- `packages/plan-schema/src/plan.ts` & `packages/plan-schema/schemas/plan.schema.json`: add optional top-level `gitea?: GiteaSettings` (`GiteaSchema`, `GITEA_MEMORY_DEFAULTS`, `GITEA_TOKEN_SCOPES`, `giteaOf(plan)`) and `checkGitea` validation.
- `packages/iac-templates/src/pins.ts`: add `IMAGES.gitea` (`gitea/gitea:28.4.0-rootless@sha256:15ab7fadb44981a2b781f40c712cad07066197f395100ea1c6326e14e5bb073a`).
- `packages/iac-templates/src/edge/nginx.ts` & `openlitespeed.ts`: add optional `upstream` override on `NginxSite` / `OpenLiteSpeedSite` (defaulting to existing `kamal-proxy`, keeping all existing app snapshots byte-for-byte identical!).
- `packages/iac-templates/src/workflow/snapshots.ts`: include `gitea` (and `gitea-db` when `database: "postgres"`) in `snapshotParts`, `partRestore`, `onlineCopy`, `partCommands`, and restore drills.
- `packages/connectors/ssh-host`: add `"gitea"` to `HOST_STEP_IDS` and `ADDON_KINDS`, add `giteaEnv` / `giteaPostgresEnv` / `giteaBootstrapEnv` to `ApplySecrets`, add `planGitea` and step scripts (`gitea` setup, bootstrap, teardown).
- `packages/agents/src/drift/host.ts`: add `"gitea"` to `AREA_TITLES`.

## Module Breakdown

1. **Schema (`packages/plan-schema`)**
   - `src/gitea.ts` + `src/gitea.test.ts`: `GiteaSchema`, `GiteaSettings`, `GiteaTokenScopeSchema`, `GITEA_TOKEN_SCOPES`, `GITEA_MEMORY_DEFAULTS`, `giteaOf(plan)`.
   - Wire optional `gitea: GiteaSchema.optional()` + `checkGitea` into `src/plan.ts`, re-export from `src/index.ts`, regenerate `schemas/plan.schema.json`.

2. **IaC & Runtime Templates (`packages/iac-templates`)**
   - `src/pins.ts`: add `IMAGES.gitea`.
   - `src/gitea/compose.ts`: `renderGiteaCompose(plan, gitea)` — hardened rootless Gitea (`sqlite` or dedicated `postgres`), zero plaintext secrets, `opscrew-edge` network alias `opscrew-gitea`, no public port 3000, optional SSH port, restricted `ALLOWED_HOST_LIST`.
   - `src/gitea/proxy.ts`: `renderGiteaProxySite(plan, gitea, ctx)` — renders edge site file(s) for Caddy, nginx, and OpenLiteSpeed routing `gitea.hostname` -> `opscrew-gitea:3000`.
   - `src/gitea/integration.ts`: `giteaAppIntegration(plan, gitea)` — deterministic secret-free connection contract (`GITEA_URL`, `GITEA_API_URL`, `GITEA_TOKEN`, `GITEA_WEBHOOK_SECRET`, REST v1 endpoints, webhook setup & `X-Gitea-Signature` verification spec) + idempotent admin/token bootstrap script (`giteaBootstrapScript`).
   - `src/gitea/gitea.test.ts`: unit & snapshot tests covering SQLite, Postgres, SSH opt-in, Caddy/nginx/OpenLiteSpeed proxy sites, webhook allowlist, and zero secret leakage.
   - `src/workflow/snapshots.ts` + `src/workflow/gitea-snapshots.test.ts`: extend `snapshotParts`, `partRestore`, `onlineCopy`, and `partCommands` to handle `kind: "gitea"` (stop-only volumes tar of `opscrew-gitea` project) and `kind: "gitea-db"` (online `pg_dump` of `opscrew-gitea`'s `gitea-db` service), including isolated restore-drill support.

3. **SecOps Policies (`packages/secops`)**
   - `src/policies/gitea.ts` + `src/policies/gitea.test.ts`: `evaluateGiteaPolicies(plan, files)` checking all 8 hardening invariants (`gitea-install-lock`, `gitea-registration-disabled`, `gitea-image-pinned`, `gitea-no-public-http-port`, `gitea-no-plaintext-secrets`, `gitea-webhook-host-restricted`, `gitea-ssh-port-safe`, `gitea-proxy-hardened`).
   - Re-export from `src/policies/index.ts` and `src/index.ts`.

4. **Host Adapter (`packages/connectors/ssh-host`)**
   - `src/gitea.ts` + `src/gitea.test.ts`: `planGitea` (enable/update & disable/remove, with `keepData` default true and `deleteData` destroy-grade flag), step scripts for atomic `0600` env-file writes from stdin, `compose.yaml` + edge proxy site installation, edge reload (Caddy/nginx/OpenLiteSpeed), `docker compose -p opscrew-gitea up -d --wait`, and idempotent admin/token bootstrap.
   - Wire `"gitea"` into `constants.ts`, `types.ts`, `steps.ts`, `apply.ts`, `index.ts`.

5. **Agents, CLI & MCP (`packages/agents`, `packages/cli`, `packages/mcp-server`)**
   - `packages/agents/src/gitea/`: `settings.ts`, `secrets.ts`, `run.ts` (`giteaEnable`, `giteaDisable`, `giteaStatus`, `describeGiteaStatus`), `index.ts`, `gitea.test.ts`.
   - Wire `"gitea"` cleanly into `packages/agents/src/addons/` (`addonEnable`, `addonDisable`, `addonStatus`), `packages/cli/src/commands/addon.ts`, and `packages/mcp-server/src/tools/addons.ts` (preserving `TOOL_COUNT = 43` and staying under `40_000` chars).

6. **Documentation (`docs/guide/`)**
   - Add `docs/guide/gitea-self-hosted.md` and link from `docs/guide/gitea.md` and `docs/guide/index.md` with clear, plain-English guides for provisioning, hardening, snapshots/restore drills, and connecting an app via scoped API tokens & `X-Gitea-Signature` webhooks.
