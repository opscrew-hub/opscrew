# Tasks: Feature 039 — Google Cloud (GCP) Managed-Services Target

**Feature:** `039-google-cloud` | **Spec:** [spec.md](spec.md) | **Plan:** [plan.md](plan.md) | **ADR:** [ADR 0040](../../docs/adr/0040-managed-cloud-plugins-and-aws.md)

## Wave 0 — Spec, Plan & Tasks (Lead)

- [x] **T3900 (lead):** Author `specs/039-google-cloud/spec.md`, `plan.md`, and `tasks.md`.

## Wave 1 — GCP Plan Schema (`@opscrew/plan-schema`, Lead)

- [x] **T3901 (lead):** Add `"gcp"` to `DeployProviderSchema` / `ManagedCloudProviderSchema`, define `GcpTargetSchema` (`packages/plan-schema/src/gcp.ts`, `enums.ts`, `plan.ts`), update exhaustive provider guards, regenerate `schemas/*.schema.json`, and add unit tests.

## Wave 2 — `@opscrew/provider-gcp` Package & GCP SecOps Policies (Lead)

- [x] **T3902 (lead):** Scaffold standalone publish-ready `packages/providers/gcp/` (`@opscrew/provider-gcp`, `contractVersion: 1`, zero runtime `@opscrew/*` imports in `dist/index.js`, `LICENSE`, `vitest.config.ts`) with pricing catalog (`src/pricing.ts`), deterministic preset mapper (`src/design.ts`), and `--set` override engine (`src/overrides.ts`) + unit tests.
- [x] **T3903 (lead):** Implement vendored readable `hashicorp/google ~> 8.0` HCL renderer (`src/hcl/index.ts`: callback-escaped `hclString()`, VPC + `existingVpcId` locals + Direct VPC Egress, WIF pool + provider with strict CEL `attribute_condition`, separate `deploy`/`runtime` Service Accounts, Cloud Run v2 + `lifecycle.ignore_changes` + Compute Engine + Compose cloud-init, private Cloud SQL, `google_memorystore_instance`, uniform private GCS, Secret Manager shells only, Global External ALB + Certificate Manager DNS-01 `acme_validation_records`) and YAML-escaped keyless WIF workflow (`src/workflow.ts`) + unit tests.
- [x] **T3904 (lead):** Implement deterministic fail-closed GCP SecOps policies in `packages/secops/src/policies/gcp.ts` (wired into `evaluatePlanPolicies`: WIF strict CEL condition, zero static SA keys, IAM least privilege, private Cloud SQL, no legacy VPC connector, no legacy Redis, private uniform GCS, no Secret Manager version in state, VPC firewall DB/cache/SSH checks) + unit tests.
- [x] **T3905 (lead):** Implement lightweight injectable GCP REST connector (`packages/providers/gcp/src/connector.ts`) with expiring token cache, strict redaction, Cloud Run/GCE status, Cloud Logging query, out-of-band Secret Manager version writes, Cloud SQL backups, and honest polled private restore drills + fake-fetch unit tests.

## Wave 3 — Core Phase Wiring, Companion Plugin & Guide (Lead)

- [x] **T3906 (lead):** Wire GCP core phases (`packages/agents/src/gcp/`: `loader.ts`, `design.ts`, `provision.ts`, `operations.ts`, `index.ts`, `gcp.test.ts`) with fail-closed `allowWorkspaceFallback: false`, SecOps gate, hash-bound apply, out-of-band Secret Manager writes, Cloudflare `_acme-challenge` DNS-only (`proxied: false`) wiring, `standingApprovalHash`-enforced restore drills, typed destroy confirmation, and route `interview`/`design`/`provision`/`destroy`/`logs`/`verify`.
- [x] **T3907 (lead):** Scaffold companion Claude Code plugin `plugin-gcp/` (`opscrew-gcp@opscrew` in `.claude-plugin/marketplace.json`) and author `docs/guide/gcp.md` (linked from `docs/guide/index.md`).

## Wave 4 — Validation, Opus 5.5 Review & Full Gate (Lead)

- [ ] **T3908 (lead):** Add real `hashicorp/google ~> 8.0` OpenTofu validation test (`packages/providers/gcp/src/google.validate.test.ts`), run standalone Opus 5.5 high-effort review over `039-google-cloud` (`origin/038-azure...HEAD`), fix all findings, verify zero `@opscrew/*` runtime imports in `dist/index.js`, and pass full-repo merge gate (`gate-039 exit 0`).
