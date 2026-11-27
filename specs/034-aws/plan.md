# Implementation Plan: Feature 034 — AWS Managed-Services Target & Installable Provider Plugins

**Feature:** `034-aws` | **Spec:** [spec.md](spec.md) | **Research:** [research.md](research.md) | **ADR:** [ADR 0040](../../docs/adr/0040-managed-cloud-plugins-and-aws.md)

## Architecture & Module Ownership

### Wave 0 — ADR, Spec, Plan & Tasks (Lead)
- `docs/adr/0040-managed-cloud-plugins-and-aws.md`
- `specs/034-aws/{spec.md, plan.md, tasks.md}`

### Wave 1 — Managed-Cloud Plugin Contract & Plan Schema (Lead)
1. **`packages/contracts/src/managed-provider.ts`** (`@opscrew/contracts`):
   - `MANAGED_CLOUD_CONTRACT_VERSION = 1`
   - `ManagedCloudProviderId` (`"aws"`, extensible for `"azure"`, `"gcp"`)
   - `ManagedCloudProviderDefinition`: plain-data manifest (`id`, `displayName`, `contractVersion`, `credentials`, `regions`, `presets`, `capabilities`, `design(input)`, `price(plan)`, `renderHcl(plan, ctx)`, `renderWorkflow(plan, ctx)`, `connector(env, deps)`).
   - `ManagedCloudConnector`: read-only `verifyCredentials`, `listRegions`, `readPrices`, `readStatus`, `readLogs`, `readDrift`, plus post-approval `writeSecrets`, `takeSnapshot`, `restoreSnapshot`, `runRestoreDrill`, `rotateSecrets`.
   - `InstalledPluginRecord`, `PluginManifestInfo` types.
2. **`packages/core/src/plugins/`** (`@opscrew/core`):
   - Official allowlist (`OFFICIAL_PLUGINS`: `aws` → `@opscrew/provider-aws`, exact pinned version + expected repo/workflow/tag provenance rules).
   - `installPlugin`, `removePlugin`, `listInstalledPlugins`, `loadManagedProvider` (`npm install --prefix <pluginsDir>/<id> --ignore-scripts --no-audit --no-fund --save-exact`, signature/provenance verification via injectable verifier + `npm audit signatures`, `contractVersion` pre-check before dynamic `import()`, staging-dir atomic swap so failed verification leaves nothing behind).
   - Unit tests with fake installer/verifier/fs covering tampered integrity, wrong provenance repo/workflow, mismatched contract version, and clean install/load/remove.
3. **`packages/plan-schema/src/aws.ts` & `enums.ts` & `plan.ts`** (`@opscrew/plan-schema`):
   - Add `"aws"` to `DeployProviderSchema` (kept distinct from `VpsProviderSchema` / `CloudProviderSchema` so VPS-only code paths never confuse AWS managed targets with single-server VPSes; `ec2-compose` maps explicitly where `retarget` bridges them).
   - `AwsPresetSchema` (`lean`, `balanced`, `production-ha`), `AwsComputeKindSchema` (`ec2-compose`, `lightsail-containers`, `ecs-fargate`, `ecs-ec2`, `lambda-web`, `lambda-event`).
   - `AwsComponentDecisionSchema` (`service`, `why`, `alternatives`, `monthlyCostUsd`, `config`).
   - `AwsPinsSchema` (`region`, `budgetCapUsd`, `noNat`, `existingVpcId`, `existingDb`, `keepCloudflareDns`).
   - `AwsGuardrailsSchema` & `AwsGuardrailExceptionSchema` (`guardrail`, `reason`, `approvedAt`).
   - `AwsObservabilitySchema` (`logsRetentionDays`, `containerInsights`, `alarms`, `managedGrafana`, `openSearch`, `tracing`, `otelCollector`).
   - `AwsTargetSchema` (`provider: "aws"`, `region`, `preset`, `compute`, `components`, `pins`, `guardrails`, `exceptions`, `observability`).
   - Cross-field refinements: refuse Fargate for databases, require explicit `exceptions[]` entry whenever any default guardrail is disabled, refuse `lambda-web` with background workers, require `keepCloudflareDns` alignment with `plan.dns.provider`.
   - Regenerate `schemas/plan.schema.json`.

### Wave 2 — `@opscrew/provider-aws` Package & Core AWS Logic (Lead + Parallel Slices)
1. **`packages/providers/aws/`** (`@opscrew/provider-aws`, built as an installable package implementing `ManagedCloudProviderDefinition`):
   - **Architect & Preset Mapper (`src/design.ts`):** deterministic mapping from `ProjectFacts` + `Requirements` + `preset` + `pins` → `AwsTarget` with per-component `service`, plain-English `why`, `alternatives`, and itemized costs (`src/pricing.ts` — dated `us-east-1` + regional multiplier table + optional AWS Pricing API / Infracost adapter).
   - **Override Engine (`src/overrides.ts`):** parses `--set <component>.<field>=<value>` paths, applies typed overrides, re-validates guardrails, re-prices, and computes before/after cost & resource diff.
   - **Typed AWS Connector (`src/connector.ts`):** lightweight, injectable SigV4 HTTP client (zero heavy SDK bloat, 100% testable with fake `fetch` AND compatible with `floci` at `http://localhost:4566` via `AWS_ENDPOINT_URL`) covering STS `GetCallerIdentity`, ECS/EC2/Lightsail/Lambda status, CloudWatch Logs/Metrics, RDS/ElastiCache snapshots & restore drills, Secrets Manager / SSM Parameter Store writes, and Pricing API reads.
   - **Vendored HCL Renderer (`src/hcl/`):** renders readable, pinned OpenTofu/Terraform files (`providers.tf`, `variables.tf`, `vpc.tf`, `iam-oidc.tf`, `compute.tf`, `database.tf`, `cache.tf`, `storage.tf`, `dns-cdn.tf`, `observability.tf`, `outputs.tf`) using `hashicorp/aws ~> 6.0` and pinned `terraform-aws-modules` patterns; never puts plaintext secrets in HCL or state; supports both Cloudflare DNS (`proxied = false` for ACM DNS-01) and Route 53.
   - **GitHub OIDC Workflow Renderer (`src/workflow.ts`):** renders `.github/workflows/opscrew-deploy*.yml` with `permissions: { id-token: write, contents: read }`, commit-pinned `aws-actions/configure-aws-credentials`, ECR/GHCR push, and compute-specific zero-downtime deploy/rollback (`ecs update-service --force-new-deployment` + stability wait, Lightsail deployment version, Lambda Web revision/endpoint update, or EC2+Compose deploy).
2. **`packages/secops/src/policies/aws.ts` & `rules/secrets.ts`** (`@opscrew/secops`):
   - Deterministic AWS plan & Terraform plan JSON checks:
     - `aws-iam-least-privilege`: rejects `*` actions or `*` resources on deploy/task IAM roles.
     - `aws-oidc-strict-sub`: rejects wildcard `sub` claims in `aws_iam_role.assume_role_policy`.
     - `aws-rds-private`: rejects `publicly_accessible = true` unless recorded in `exceptions[]`.
     - `aws-storage-encrypted-private`: requires S3 Block Public Access + encryption at rest + RDS/ElastiCache encryption.
     - `aws-no-secret-in-state`: rejects plaintext secret values in `aws_secretsmanager_secret_version` / `aws_ssm_parameter`.
     - `aws-cloudwatch-retention`: requires explicit `retention_in_days` on every log group; rejects `aws_acmpca_certificate_authority`.
   - Redactor / secret-scanner rules for `AKIA[0-9A-Z]{16}`, `ASIA[0-9A-Z]{16}`, and AWS secret access keys.

### Wave 3 — Core Phase Wiring, CLI, MCP, Companion Plugin & Docs (Lead + Contributor Slices)
1. **`packages/agents/src/`**:
   - `interview`: offer AWS (and offer `opscrew plugin add aws` if not installed) alongside VPS targets.
   - `design`: route `target.provider === "aws"` through loaded `@opscrew/provider-aws`, support `--set <component>.<field>=<value>`, display itemized monthly cost, cost traps, and guardrail exceptions.
   - `provision`: render AWS HCL + OIDC workflow, run `@opscrew/secops` AWS policies, plan & hash-bound apply through `@opscrew/iac-engine`, write secret values out-of-band to Secrets Manager / SSM via connector (never in `.tfstate`), wire Cloudflare ACM DNS-01 CNAMEs (`proxied = false`) when `keepCloudflareDns: true`.
   - `status`, `logs`, `verify`, `drift`, `snapshot`/`restore`/`drill`, `rotate`, `advise`, `destroy`, `retarget --to aws` (`ec2-compose`).
2. **`packages/cli/src/commands/plugin.ts` & `design.ts`**:
   - `opscrew plugin list|add|remove` CLI commands.
   - `opscrew design --set <component>.<field>=<value>` repeatable flag.
3. **`packages/mcp-server/src/tools/`**:
   - Expose `plugin` status, AWS `design` overrides, and AWS `status`/`logs`/`verify` cleanly through core's single MCP server.
4. **`plugin-aws/` + `.claude-plugin/marketplace.json` + `docs/guide/aws.md`**:
   - Companion Claude Code plugin `opscrew-aws@opscrew` (`dependencies: ["opscrew"]`) + documented cross-plugin MCP spike check.
   - User guide `docs/guide/aws.md` (linked from `docs/guide/index.md`).

### Wave 4 — Real `floci` OpenTofu Integration Tests, Opus 5.5 Review & Full Gate (Lead)
- `packages/providers/aws/src/floci.docker.test.ts` (`OPSCREW_DOCKER_TESTS=1`): spins up `floci/floci` on port `4566`, runs real `tofu init` / `validate` / `plan` / `apply` / `destroy` over generated AWS HCL (VPC, S3 + Block Public Access, IAM OIDC role, Secrets Manager shell, CloudWatch Log Group with retention, RDS/ECS resources) and cleans up containers cleanly.
- Standalone Opus 5.5 high-effort review over the entire `034-aws` diff (strict focus on plugin install/provenance security, IAM/OIDC least privilege, secret-out-of-state, and approval/plan-hash boundaries).
- Full-repo merge gate (`gate exit 0`).
