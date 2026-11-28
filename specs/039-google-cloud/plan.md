# Implementation Plan: Feature 039 — Google Cloud (GCP) Managed-Services Target

**Feature:** `039-google-cloud` | **Spec:** [spec.md](spec.md) | **Research:** [research.md](research.md) | **ADR:** [ADR 0040](../../docs/adr/0040-managed-cloud-plugins-and-aws.md)

## Architecture & Waves

1. **Wave 1 (`@opscrew/plan-schema` + exhaustive guards):**
   - Add `"gcp"` to `ManagedCloudProviderSchema` / `DeployProviderSchema`.
   - Define `GcpTargetSchema` (`packages/plan-schema/src/gcp.ts`) with presets (`lean`/`balanced`/`production-ha`), compute (`cloud-run`/`compute-engine`), pins (`region`, `projectId`, `budgetCapUsd`, `noNat`, `noGlobalAlb`, `existingVpcId`, `existingDb`, `keepCloudflareDns`), default-on guardrails (`privateDatabase`, `encryptionAtRest`, `automatedBackups`, `privateStorage`, `leastPrivilegeIam`, `noStaticSaKeys`, `noLegacyVpcConnector`, `noLegacyRedis`, `noGlobalAlbOnLean`), explicit `exceptions[]`, and `observability` (Cloud Logging retention 30–3650 days).
   - Regenerate `schemas/*.schema.json` and update exhaustive provider guards.
2. **Wave 2 (`@opscrew/provider-gcp` + GCP SecOps):**
   - Standalone publish-ready `packages/providers/gcp/` (`contractVersion: 1`, local `StandaloneGcpTargetSchema`, zero runtime `@opscrew/core`/`@opscrew/contracts`/`@opscrew/plan-schema` imports, `LICENSE`, `vitest.config.ts`, `tsup` ESM build).
   - `pricing.ts`, `design.ts`, `overrides.ts`, `hcl/index.ts` (`hashicorp/google ~> 8.0`, callback-escaped `hclString()`, WIF pool + provider with strict CEL `attribute_condition`, separate `deploy`/`runtime` Service Accounts, Cloud Run v2 with Direct VPC Egress & `lifecycle.ignore_changes`, Compute Engine + Compose with cloud-init, private Cloud SQL, `google_memorystore_instance`, uniform private GCS, Secret Manager shells only, Global External ALB + Certificate Manager DNS-01 `acme_validation_records`), `workflow.ts` (`google-github-actions/auth@v2`), and `connector.ts` (injectable REST client with expiring token cache, Cloud Logging, out-of-band Secret Manager version writes, Cloud SQL backups, honest polled private restore drills).
   - Deterministic fail-closed GCP SecOps policies in `packages/secops/src/policies/gcp.ts` wired into `evaluatePlanPolicies`.
3. **Wave 3 (Core phases, companion plugin & guide):**
   - `packages/agents/src/gcp/{loader.ts,design.ts,provision.ts,operations.ts,index.ts,gcp.test.ts}` wired into `interview`, `design`, `provision`, `destroy`, `logs`, `verify` (`allowWorkspaceFallback: false`, `standingApprovalHash` verified by `ApprovalGate`, Cloudflare `_acme-challenge` `proxied: false`).
   - Companion Claude Code plugin `plugin-gcp/` registered in `.claude-plugin/marketplace.json` and user guide `docs/guide/gcp.md` linked from `docs/guide/index.md`.
4. **Wave 4 (Real OpenTofu `hashicorp/google` validation, Opus 5.5 review & full gate):**
   - `packages/providers/gcp/src/google.validate.test.ts` (`OPSCREW_IT=1` `tofu init -backend=false && tofu validate` against `hashicorp/google ~> 8.0`).
   - Standalone Opus 5.5 high-effort review over `origin/038-azure...HEAD`, fix every finding, and pass full-repo merge gate (`gate-039 exit 0`).
