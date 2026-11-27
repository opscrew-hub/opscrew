# ADR 0040: Installable Managed-Cloud Provider Plugins and AWS Target Design

**Status**: Proposed (2026-11-27, feature 034). Builds on [ADR 0029](0029-cloud-provider-contract.md) (cloud server provider contract) and [026 research R3–R4](../../specs/026-contabo-provider-plugins/research.md) and [034 research R1–R7](../../specs/034-aws/research.md).

## Context

ADR 0029 moved cloud server (VPS) providers behind a plain-data contract (`CloudProviderDefinition`) in `packages/providers/<id>`, built into the core CLI. AWS (feature `034`) introduces two new architectural requirements that VPS providers did not have:

1. **Separately installed provider packages:** AWS (and later Azure `038` and Google Cloud `039`) ships as an official `@opscrew/provider-<id>` package installed on demand (`opscrew plugin add aws`, or offered during `opscrew interview`) rather than bloating the core CLI bundle.
2. **Managed cloud services, not just a single VPS:** An AWS deployment selects managed compute (`ec2-compose`, `lightsail-containers`, `ecs-fargate`, `ecs-ec2`, `lambda-web`), managed databases (RDS, Aurora Serverless v2, ElastiCache Valkey), S3 + CloudFront, SES, Secrets Manager / SSM Parameter Store, EventBridge Scheduler, SQS/SNS, CloudWatch / Managed Grafana, and GitHub Actions OIDC IAM roles — while giving the user explicit, priced, overridable choices per component and strong guardrails by default.

At the same time, **Constitution I and IV remain non-negotiable**: all approval gates, SHA-256 plan-hash verification, policy enforcement, IaC engine execution (`tofu`/`terraform`), and secret redaction stay in OpsCrew's core — never inside an external plugin.

## Decision

### Part 1 — Installable Provider Packages (`opscrew plugin`)

- **D1: Official pinned packages only at first.** `opscrew plugin add <id>` installs an official `@opscrew/provider-<id>` package from the core's allowlist (`aws`, later `azure`, `gcp`) pinned to an exact version (`@<exact>`), into OpsCrew's own data directory (`~/.opscrew/plugins/<id>`), using `npm install --prefix <dir> --ignore-scripts --no-audit --no-fund --save-exact`. No lifecycle scripts ever execute during install. Third-party plugins are out of scope in `034` and require a future explicit opt-in.
- **D2: Integrity & npm provenance verification before load.** Before any installed plugin is imported:
  1. Core verifies the installed package's `package.json` matches the pinned name and exact version, and verifies `npm audit signatures` (registry ECDSA signature + Sigstore provenance attestation) or verifies the attestation bundle directly against `opscrew-hub/opscrew`, its release workflow, and tag ref.
  2. Core checks `opscrewPlugin.contractVersion` in `package.json` before calling `import()` on the resolved file URL.
  3. Failures abort before loading code and remove the staged install folder cleanly.
- **D3: Plain-data managed-cloud contract (`ManagedCloudProviderDefinition`, `contractVersion: 1`).** Exported from `@opscrew/contracts` (type-only for plugins). Only plain data, regular expressions, and pure/injected functions cross the boundary — no zod instances or class prototypes across package boundaries (avoiding duplicate-zod `instanceof` failures). Core validates every plan, component decision, Terraform output, and cost estimate returned by a plugin with core's own zod schemas.
- **D4: Core retains the entire safety boundary.** A plugin may inspect credentials (read-only), propose architecture/component selections, price components, render vendored HCL modules and CI workflow fragments, and run read-only status/logs/drift reads or explicit post-approval secret/snapshot API calls through injected adapters. Core exclusively owns:
  - plan hashing and approval prompts (including destroy confirmations);
  - `@opscrew/secops` static policy checks on the rendered HCL and Terraform plan JSON;
  - `tofu` / `terraform` plan and hash-bound apply;
  - secret registration and redaction.
- **D5: Companion Claude Code / Codex plugin split.** Each separately installed cloud ships a matching thin plugin folder (e.g., `plugin-aws/` listed in `.claude-plugin/marketplace.json` as `opscrew-aws@opscrew` with `"dependencies": ["opscrew"]`). The core plugin (`opscrew`) remains the sole owner of the deterministic MCP server (`opscrew mcp`) so only one MCP server process runs. Before relying on a skill inside `opscrew-aws` calling `mcp__plugin_opscrew_*` tools directly, a documented verification spike confirms Claude Code permits cross-plugin MCP tool invocation; otherwise AWS skills guide the user via `npx opscrew` CLI commands while the core plugin's MCP tools handle AWS plans transparently.

### Part 2 — AWS Managed-Services Design (`@opscrew/provider-aws`)

- **D6: Plan schema (`target.provider: "aws"`) with presets, per-component decisions, pins, and guardrail exceptions.**
  - `target`: `{ provider: "aws", region, preset: "lean" | "balanced" | "production-ha", compute, components, pins, guardrails, exceptions }`.
  - Every managed component records: `service` (concrete AWS service choice), `why` (plain-English rationale), `alternatives` (rejected choices with brief why), `monthlyCostUsd` (itemized estimate, including IPv4 / ALB / NAT line items), and `config` (typed component overrides).
  - User pins (`pins`): `region`, `budgetCapUsd`, `noNat`, `existingVpcId`, `existingDb`, `keepCloudflareDns`.
  - Overrides work identically via interactive `opscrew design`, `opscrew design --set <component>.<field>=<value>`, or hand-editing `opscrew/plan.yaml` (re-validated, re-priced, diff shown before apply).
  - Guardrails are **on by default**: private database subnets (`publicly_accessible = false`), encryption at rest (KMS/AES-256), automated backups + PITR, S3 Block Public Access + CloudFront OAC, least-privilege IAM roles, explicit CloudWatch log retention (`14` or `30` days), and zero ACM Private CA. Relaxing any guardrail requires an explicit `exceptions[]` entry naming the guardrail and a plain-English reason — never silent.
- **D7: Compute chosen per use case (no App Runner default).**
  - `ec2-compose`: EC2 (`t4g.*`) + Docker Compose; plugs into the VPS/Compose seam and enables `opscrew retarget --to aws`.
  - `lightsail-containers`: flat-rate `$7–$10/mo` for lean single-container stateless web apps with built-in HTTPS endpoint and zero ALB/NAT/IPv4 surprises.
  - `ecs-fargate`: default for `balanced` and `production-ha` (web + workers, rolling zero-downtime deploys, private VPC networking, IAM task roles; uses ECS Express Mode where a single stateless web service fits, or standard ECS Service + shared ALB when pairing web + workers).
  - `ecs-ec2`: large steady workloads or GPU instances.
  - `lambda-web`: AWS Lambda Web Functions (October 2026) for spiky/low-traffic stateless Node.js HTTP apps in supported regions (active CPU billing, zero idle CPU wait charge); classic `lambda-event` only for small event/cron jobs.
  - **App Runner is skipped for new designs** because AWS closed it to new customers on `2026-04-30` (research R1).
- **D8: Zero-code-rewrite database mapping.** Managed services are selected only when the app's existing database driver works unchanged:
  - Postgres → RDS (`db.t4g.*`) or Aurora Serverless v2 (`0 ACU` auto-pause for staging/preview; `0.5+ ACU` for prod).
  - MySQL → RDS MySQL or Aurora MySQL.
  - Redis / Valkey → ElastiCache for Valkey (node-based with `maxmemory-policy: noeviction` for queues; Serverless Valkey for caches).
  - MongoDB → MongoDB Atlas on AWS (or DocumentDB only with an explicit compatibility warning).
  - Elasticsearch/OpenSearch → Amazon OpenSearch Service (only for OpenSearch or ES ≤ 7.10 clients), else Elastic Cloud or EC2 container.
  - ClickHouse → ClickHouse Cloud or EC2 container (never Redshift).
  - Neo4j → Neo4j AuraDB or EC2 container (never Neptune).
  - Cassandra → Amazon Keyspaces (CQL).
  - EC2 + EBS container remains an explicit cheaper choice; **Fargate is never used for databases**.
- **D9: Cost-trap avoidance by default.**
  - `lean` preset defaults to **no NAT Gateway** (public Fargate subnets with strict SG or Lightsail/Lambda Web/EC2+Compose), saving `~$36.50/mo` per AZ; whenever NAT is enabled (`production-ha` or user override), free VPC Gateway Endpoints for S3 and DynamoDB are always added.
  - Secrets default to **SSM Parameter Store Standard (`SecureString`, `$0`)** or **one bundled Secrets Manager JSON secret (`$0.40/mo`)** — never 1 Secrets Manager entry per env var (`$0.40 × N`).
  - Public IPv4 charges (`$3.65/mo` each), ALB base (`$16.43/mo`), NAT (`$32.85/mo`/AZ), and CloudWatch log retention are itemized explicitly in `plan.yaml` and design output.
- **D10: Keyless CI via GitHub Actions OIDC & secrets out of Terraform state.**
  - Deploy workflows request `permissions: { id-token: write, contents: read }` and assume a dedicated per-environment IAM role via `aws-actions/configure-aws-credentials` (commit-pinned).
  - Trust policy uses strict `StringEquals` on `aud: sts.amazonaws.com` and exact repository/environment `sub` (supporting GitHub's July 2026 immutable numeric org/repo ID format `repo:<OWNER>@<OWNER_ID>/<REPO>@<REPO_ID>:environment:<ENV>`) — **zero wildcards**.
  - Terraform creates only secret shells (`aws_secretsmanager_secret` / placeholder-free SSM metadata); real secret values are written out-of-band via OpsCrew's typed AWS connector at apply time so plaintext secrets never enter `.tfstate`.
- **D11: Vendored readable HCL + deterministic SecOps + `floci` emulator testing.**
  - Modules follow pinned `terraform-aws-modules` v6/v7/v10 patterns (AWS provider `~> 6.0`, OpenTofu-compatible) vendored into the repository under `infra/` so users can inspect or run `tofu` without OpsCrew (Constitution II).
  - Automated integration tests (including real OpenTofu `plan` and `apply`) run against **`floci`** (`floci/floci`, MIT, zero auth token, port `4566`; research R6) — not LocalStack (Community discontinued `2026-03-23`, token/commercial restrictions).
  - Because `floci` does not enforce runtime IAM authorization, `@opscrew/secops` adds deterministic static AWS policy checks (rejecting wildcard `*` actions/resources on deploy roles, wildcard OIDC `sub`, `publicly_accessible = true` on RDS without exception, unencrypted storage, missing S3 Block Public Access, missing CloudWatch log retention, and secret values embedded in Terraform state).

## Consequences

- Core CLI size stays flat as AWS, Azure (`038`), and Google Cloud (`039`) ship as on-demand `@opscrew/provider-*` packages.
- Every AWS cost trap and guardrail exception is transparent in `opscrew/plan.yaml` before a single AWS dollar is spent.
- Full AWS OpenTofu plan/apply tests run free and token-less in CI and contributor machines using `floci`, leaving only a narrow optional live pass (real OIDC JWT, ACM DNS-01, CloudFront edge TLS) for throwaway-account verification.
- Each separately published `@opscrew/provider-*` package adds one staged npm publish approval for the founder.

