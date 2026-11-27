# Tasks: Feature 038 — Microsoft Azure Managed-Services Target

**Feature:** `038-azure` | **Spec:** [spec.md](spec.md) | **Plan:** [plan.md](plan.md) | **ADR:** [ADR 0040](../../docs/adr/0040-managed-cloud-plugins-and-aws.md)

## Wave 0 — Spec, Plan & Tasks (Lead)

- [x] **T3800 (lead):** Author `specs/038-azure/spec.md`, `plan.md`, and `tasks.md`.

## Wave 1 — Azure Plan Schema (`@opscrew/plan-schema`, Lead)

- [x] **T3801 (lead):** Add `"azure"` to `DeployProviderSchema` and define `AzureTargetSchema` (`packages/plan-schema/src/azure.ts`, `enums.ts`, `plan.ts`), update exhaustive provider guards, regenerate `schemas/*.schema.json`, and add unit tests.

## Wave 2 — `@opscrew/provider-azure` Package & Azure SecOps Policies (Lead)

- [x] **T3802 (lead):** Scaffold publish-ready `packages/providers/azure/` (`@opscrew/provider-azure`, `contractVersion: 1`, zero runtime `@opscrew/core` imports) with pricing catalog (`src/pricing.ts`), deterministic preset mapper (`src/design.ts`), and `--set` override engine (`src/overrides.ts`) + unit tests.
- [x] **T3803 (lead):** Implement vendored readable `hashicorp/azurerm ~> 5.0` HCL renderer (`src/hcl/index.ts`: escaped `hclString()`, VNet + `existingVnetId` locals, User-Assigned Managed Identity + OIDC `azurerm_federated_identity_credential`, resource-group RBAC, dedicated `container-apps`/`app-service`/`vm-compose` renderers, private Flexible Server, `azurerm_managed_redis`, private TLS 1.2+ Blob Storage, Key Vault shell only, Log Analytics retention, `asuid` TXT output) and YAML-escaped keyless OIDC workflow (`src/workflow.ts`) + unit tests.
- [x] **T3804 (lead):** Implement deterministic Azure SecOps static policies in `packages/secops/src/policies/azure.ts` (wired into `evaluatePlanPolicies`: OIDC strict `sub`/`aud`/issuer fail-closed, RBAC least privilege, no retiring `azurerm_redis_cache`, private/encrypted Flexible Server, private TLS 1.2+ Storage, no Key Vault secret in state, blocking Log Analytics retention, NSG open DB/cache/SSH port checks) + unit tests.
- [x] **T3805 (lead):** Implement lightweight injectable Azure ARM + Key Vault HTTP connector (`packages/providers/azure/src/connector.ts`) with strict redaction, Container Apps status, Log Analytics logs, out-of-band Key Vault secret writes, Flexible Server backups, and honest isolated PITR restore drills + fake-fetch unit tests.

## Wave 3 — Core Phase Wiring, Companion Plugin & Guide (Lead)

- [x] **T3806 (lead):** Wire Azure core phases (`packages/agents/src/azure/`: `loader.ts`, `design.ts`, `provision.ts`, `operations.ts`, `index.ts`, `azure.test.ts`) with fail-closed `allowWorkspaceFallback: false` default, SecOps gate, hash-bound apply, out-of-band Key Vault writes, Cloudflare `asuid` DNS-only (`proxied: false`) wiring, approval-gated restore drills, typed destroy confirmation, and route `interview`/`design`/`provision`/`destroy`/`logs`/`verify`.
- [x] **T3807 (lead):** Scaffold companion Claude Code plugin `plugin-azure/` (`opscrew-azure@opscrew` in `.claude-plugin/marketplace.json`) and author `docs/guide/azure.md` (linked from `docs/guide/index.md`).

## Wave 4 — Validation, Opus 5.5 Review & Full Gate (Lead)

- [ ] **T3808 (lead):** Add `azurerm` OpenTofu validation test (`packages/providers/azure/src/azurerm.validate.test.ts`), run standalone Opus 5.5 high-effort review over `038-azure` (`origin/034-aws...HEAD`), fix all findings, and pass full-repo merge gate (`gate-038 exit 0`).
