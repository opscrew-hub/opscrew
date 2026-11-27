# Implementation Plan: Feature 038 — Microsoft Azure Managed-Services Target

**Feature:** `038-azure` | **Spec:** [spec.md](spec.md) | **Research:** [research.md](research.md) | **ADR:** [ADR 0040](../../docs/adr/0040-managed-cloud-plugins-and-aws.md)

## Waves & Architecture

- **Wave 0 (`T3800`):** Author `specs/038-azure/{spec.md, plan.md, tasks.md}`.
- **Wave 1 (`T3801`):** Add `"azure"` to `DeployProviderSchema`, define `AzureTargetSchema` (`packages/plan-schema/src/azure.ts` — presets `lean`/`balanced`/`production-ha`, compute `container-apps`/`app-service`/`vm-compose`, components, pins, guardrails, explicit `exceptions[]`, observability), update exhaustive provider guards in `iac-templates`/`agents`, regenerate `schemas/*.schema.json`, and add unit tests.
- **Wave 2 (`T3802`–`T3805`):**
  - Scaffold publish-ready `packages/providers/azure/` (`@opscrew/provider-azure`, `contractVersion: 1`, zero runtime `@opscrew/core` imports):
    - `src/pricing.ts`: Azure regions (`eastus`, `westeurope`, `swedencentral`, `westus2`, `southeastasia`), dated `2026-11-26` rates, `estimateAzureMonthlyCost`, cost-trap warnings.
    - `src/design.ts`: deterministic `designAzureTarget` (Container Apps Consumption default, App Service `B1`, VM + Compose, PostgreSQL/MySQL Flexible Server, **Azure Managed Redis**, Key Vault Standard, Blob Storage, zero legacy `azurerm_redis_cache`, zero Front Door / NAT traps on lean).
    - `src/overrides.ts`: `--set <component>.<field>=<value>` override engine syncing top-level `compute` & `components.compute.service`, guardrail validation, and cost delta calculation.
    - `src/hcl/index.ts`: vendored readable `hashicorp/azurerm ~> 5.0` HCL renderer with `hclString()` escaping everywhere, `existingVnetId` unified `locals`, User-Assigned Managed Identity + `azurerm_federated_identity_credential` (`api://AzureADTokenExchange`, exact `environment:` subject, immutable ID support), resource-group-scoped RBAC, dedicated compute renderers (`container-apps`, `app-service`, `vm-compose`), private Flexible Server, `azurerm_managed_redis`, private TLS 1.2+ Blob Storage, Key Vault shell ONLY (zero secret values in state), explicit Log Analytics retention, and `custom_domain_verification_records` (`asuid` TXT) output.
    - `src/workflow.ts`: YAML-escaped keyless GitHub Actions OIDC workflow (`id-token: write`, commit-pinned `azure/login`, ACR push, Container Apps / App Service / VM rollout).
    - `src/connector.ts`: lightweight injectable Azure ARM + Key Vault HTTP connector (`AZURE_ACCESS_TOKEN`, `AZURE_SUBSCRIPTION_ID`, `AZURE_RESOURCE_GROUP`, optional `AZURE_ENDPOINT_URL` for tests), strict redaction, Container Apps status, Log Analytics logs, out-of-band Key Vault secret writes, Flexible Server backups, and honest isolated PITR restore drills (polling `Ready` and confirming deletion).
  - Deterministic Azure SecOps static policies in `packages/secops/src/policies/azure.ts` (wired into `evaluatePlanPolicies`) with fail-closed unknown checks and comprehensive unit tests.
- **Wave 3 (`T3806`–`T3808`):**
  - Core Azure phase orchestration in `packages/agents/src/azure/` (`loader.ts`, `design.ts`, `provision.ts`, `operations.ts`, `index.ts`, `azure.test.ts`), strictly defaulting `allowWorkspaceFallback: false`, and wired into `interview/questions.ts`, `design/run.ts`, `provision/run.ts`, `destroy/run.ts`, `logs/read.ts`, and `verify/run.ts`.
  - Companion Claude Code plugin `plugin-azure/` (`opscrew-azure@opscrew` in `.claude-plugin/marketplace.json`) and user guide `docs/guide/azure.md` linked from `docs/guide/index.md`.
- **Wave 4 (`T3809`–`T3810`):**
  - OpenTofu `tofu init -backend=false && tofu validate` integration test (`packages/providers/azure/src/azurerm.validate.test.ts`, gated by `OPSCREW_DOCKER_TESTS=1` or cached `azurerm` provider) verifying rendered `lean`, `balanced`, and `existingVnetId` HCL modules.
  - Standalone Opus 5.5 high-effort review over `origin/034-aws...HEAD`, fix all findings, and pass full-repo merge gate (`gate-038 exit 0`).
