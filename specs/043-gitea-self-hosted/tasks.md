# Tasks: Self-Hosted Gitea Provisioning & App Integration (Feature 043 Follow-Up)

**Feature:** `043-gitea-self-hosted` | **Issue:** `#70` | **Base:** `origin/042-git-platforms`

## Phase 1 — Research & Specification
- [x] T4320 Research official Gitea rootless Docker image, pinned multi-arch digest (`28.4.0-rootless`), SQLite/PostgreSQL config, hardened defaults, CLI admin/token bootstrap, REST v1 & webhook HMAC-SHA256 verification, and snapshot/restore strategy (`specs/043-gitea-self-hosted/research.md`)
- [x] T4321 Write specification (`spec.md`), plan (`plan.md`), and task breakdown (`tasks.md`)

## Phase 2 — Core Paths & Plan Schema
- [x] T4322 Add `giteaSecrets` (`gitea_secrets.json`) to `ProjectFiles` in `@opscrew/core` (`packages/core/src/paths.ts`)
- [x] T4323 Add `GiteaSchema` (`plan.gitea`), `GITEA_MEMORY_DEFAULTS`, `GITEA_TOKEN_SCOPES`, `giteaOf`, cross-field `checkGitea` validation, regenerate `plan.schema.json`, and add unit tests (`packages/plan-schema/src/gitea.ts`, `gitea.test.ts`)

## Phase 3 — IaC Templates, Edge Proxy & Snapshots
- [x] T4324 Pin `IMAGES.gitea` (`gitea/gitea:28.4.0-rootless@sha256:...`) in `packages/iac-templates/src/pins.ts`
- [x] T4325 Add `packages/iac-templates/src/gitea/` (`compose.ts`, `proxy.ts`, `integration.ts`, `index.ts`, `gitea.test.ts`): rootless Gitea Compose (SQLite & Postgres), Caddy/nginx/OpenLiteSpeed reverse-proxy sites, idempotent admin/token bootstrap script, and app integration contract
- [x] T4326 Wire Gitea (`gitea` + optional `gitea-db`) into `snapshotParts`, `snapshot.sh` backup/restore, and isolated restore drills (`packages/iac-templates/src/workflow/snapshots.ts`, `gitea-snapshots.test.ts`)

## Phase 4 — SecOps Policies & Host Plan Adapter
- [x] T4327 Implement deterministic `evaluateGiteaPolicies` in `@opscrew/secops` (`packages/secops/src/policies/gitea.ts`, `gitea.test.ts`)
- [x] T4328 Implement hash-approved `planGitea` host step & stdin secret delivery in `@opscrew/connector-ssh-host` (`packages/connectors/ssh-host/src/gitea.ts`, `gitea.test.ts`, wire into `types.ts`, `steps.ts`, `apply.ts`, `index.ts`)

## Phase 5 — Agents, CLI, MCP & Docs
- [x] T4329 Implement `packages/agents/src/gitea/` (`settings.ts`, `secrets.ts`, `run.ts`, `index.ts`, `gitea.test.ts`), add `"gitea"` to `drift/host.ts` `AREA_TITLES`, and wire into `addons/`
- [x] T4330 Wire `gitea` into CLI (`packages/cli/src/commands/addon.ts`) and MCP (`packages/mcp-server/src/tools/addons.ts`, verifying `tool-list-size.test.ts` stays at 43 tools and <= 40,000 chars) with tests
- [x] T4331 Write `docs/guide/gitea-self-hosted.md` and update `docs/guide/gitea.md` and `docs/guide/index.md`

## Phase 6 — Verification & PR
- [x] T4332 Run `pnpm format`, `pnpm lint`, `pnpm typecheck`, and all affected Vitest suites; commit cleanly, push to `fork/feat/70-gitea-self-hosted`, and open PR against `--base 042-git-platforms` resolving `#70`
