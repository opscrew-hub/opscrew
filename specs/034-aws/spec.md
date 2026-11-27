# Feature Specification: AWS Managed-Services Target & Installable Provider Plugins (Feature 034)

**Feature Branch**: `034-aws`  
**Created**: 2026-11-27  
**Status**: In Progress  
**Research**: [research.md](research.md) | **Plugin Research**: [026 research R3–R4](../026-contabo-provider-plugins/research.md) | **ADR**: [ADR 0040](../../docs/adr/0040-managed-cloud-plugins-and-aws.md)

## Overview

Feature `034` brings OpsCrew's first hyperscaler (**Amazon Web Services**) and establishes OpsCrew's **installable provider plugin system** (`opscrew plugin add aws` → `@opscrew/provider-aws`), which Azure (`038`) and Google Cloud (`039`) will reuse.

Rather than treating AWS as a single EC2 box, OpsCrew maps each detected application capability (web/SSR, background workers, cron, WebSockets, databases, caches, uploads, email, queues, observability) and the user's interview answers (scale, budget, uptime, data criticality, region) to the most suitable AWS managed services — while surfacing every cost trap transparently in `opscrew/plan.yaml`, enforcing security guardrails by default, and keeping every infrastructure change under OpsCrew's core SHA-256 plan-hash approval model.

## User Stories

### US1 — Installable Provider Plugins with Provenance Verification (`opscrew plugin`) (P1)
As a developer deploying to AWS, I want to install the official `@opscrew/provider-aws` plugin with `opscrew plugin add aws` (or accept it when `opscrew interview` offers it), knowing OpsCrew installs an exact pinned version with `--ignore-scripts`, checks its npm registry signature / provenance attestation, and keeps all approvals, policy checks, and redaction in core.

**Acceptance criteria:**
- `opscrew plugin list`, `opscrew plugin add <id>`, and `opscrew plugin remove <id>` manage official provider plugins under `~/.opscrew/plugins/<id>`.
- Installs use exact pinned versions with `--ignore-scripts` and verify registry signatures / npm provenance (`opscrew-hub/opscrew` repo + release workflow + tag ref) before loading code.
- Plugin loading validates `contractVersion` before dynamic `import()` and validates every plugin return value with core's zod schemas (only plain data and functions cross the boundary).
- A failed signature/provenance or contract check aborts cleanly without loading code or leaving partial installs behind.

### US2 — AWS Plan Schema, Presets (`lean` / `balanced` / `production-ha`), Overrides & Guardrails (P1)
As a developer targeting AWS, I want `opscrew design` to generate a clear `opscrew/plan.yaml` recording per component the chosen AWS service, plain-English `why`, rejected `alternatives`, itemized monthly cost (including NAT Gateway, ALB, and public IPv4 line items), user `pins`, and explicit `guardrails` / `exceptions`, and let me override any choice via `opscrew design --set <component>.<field>=<value>` or hand-editing `plan.yaml`.

**Acceptance criteria:**
- `DeployPlanSchema` supports `target.provider: "aws"` with `region`, `preset` (`lean`, `balanced`, `production-ha`), `compute` (`ec2-compose`, `lightsail-containers`, `ecs-fargate`, `ecs-ec2`, `lambda-web`), `components`, `pins` (`region`, `budgetCapUsd`, `noNat`, `existingVpcId`, `existingDb`, `keepCloudflareDns`), `guardrails`, and `exceptions`.
- `opscrew design --set <component>.<field>=<value>` updates the component cleanly, re-validates, re-prices, and prints the cost and guardrail diff.
- Guardrails are enabled by default (private DB, encryption at rest, automated backups, S3 Block Public Access + CloudFront OAC, least-privilege IAM, explicit CloudWatch log retention, no ACM Private CA). Relaxing any guardrail requires an explicit recorded exception with a reason.
- Zero-code-rewrite database mapping selects compatible managed services (RDS/Aurora Postgres/MySQL, ElastiCache Valkey with `noeviction` for queues, MongoDB Atlas / DocumentDB warning, OpenSearch Service, ClickHouse/Neo4j/Keyspaces, or EC2+EBS container; never Fargate for databases).
- App Runner is never recommended for new accounts (closed 2026-04-30); Lambda Web Functions (October 2026) is weighed for spiky/low-traffic Node.js HTTP apps alongside Lightsail Containers, EC2+Compose, and ECS Fargate / Express Mode.

### US3 — Readable Vendored AWS HCL, Keyless GitHub OIDC CI & Secret-Out-of-State Provisioning (P1)
As a developer provisioning on AWS, I want OpsCrew to render readable, pinned OpenTofu/Terraform modules (`hashicorp/aws ~> 6.0`), set up keyless GitHub Actions OIDC (`id-token: write`, strict repo/environment `sub`, zero long-lived AWS keys in GitHub Secrets), keep secret values out of Terraform state, and support keeping DNS at Cloudflare (`proxied = false` for ACM DNS-01 CNAMEs) or moving DNS to Route 53.

**Acceptance criteria:**
- Vendored HCL modules render cleanly for VPC (optional NAT + free S3/DynamoDB Gateway Endpoints), compute (`ec2-compose`, `lightsail-containers`, `ecs-fargate`, `ecs-ec2`, `lambda-web`), RDS / Aurora Serverless v2, ElastiCache Valkey, S3 + CloudFront OAC, ACM (`us-east-1` for CloudFront, regional for ALB), Route 53 (optional), Secrets Manager / SSM shells, EventBridge Scheduler, SQS/SNS, CloudWatch Logs (with explicit retention) + Alarms → SNS, and IAM GitHub OIDC deploy role.
- Terraform never embeds plaintext secret values in `.tfstate`; secret values are written out-of-band via the typed AWS connector after plan-hash approval.
- GitHub OIDC trust policy uses strict `StringEquals` on `aud` and exact repository/environment `sub` (supporting July 2026 immutable numeric org/repo IDs) with zero wildcards.
- `@opscrew/secops` statically validates rendered AWS plans and Terraform plan JSON for IAM least privilege, strict OIDC trust policies, private databases, S3 Block Public Access, encryption at rest, CloudWatch retention, and secret-out-of-state compliance.

### US4 — AWS Observability, Operations (`status`, `logs`, `drift`, `verify`, `snapshot`, `restore`, `rotate`, `destroy`, `retarget`) & `floci` Emulator Testing (P1)
As a developer running an app on AWS, I want `opscrew status`, `opscrew logs`, `opscrew drift`, `opscrew verify`, `opscrew snapshot`/`restore` (including isolated restore drills), `opscrew rotate`, `opscrew advise`, `opscrew destroy`, and `opscrew retarget --to aws` (`ec2-compose`) to work seamlessly through AWS APIs, backed by automated OpenTofu tests against `floci`.

**Acceptance criteria:**
- `opscrew logs` reads CloudWatch Logs (Logs Insights / filter log events); `opscrew status` reads ECS/EC2/Lightsail/Lambda + RDS/ElastiCache + CloudWatch metrics; `opscrew verify` validates endpoints, TLS, and AWS health/alarms.
- CloudWatch alarms → SNS are provisioned by default; Managed Grafana + Managed Prometheus, OpenSearch Service, and X-Ray/Application Signals via ADOT (OpenTelemetry) are opt-in and itemized in `plan.yaml`.
- Automated integration tests exercise OpenTofu `init`/`validate`/`plan`/`apply`/`destroy` against `floci` (`floci/floci`, MIT, port `4566`) with `OPSCREW_DOCKER_TESTS=1`, paired with deterministic `@opscrew/secops` IAM policy tests.
- Companion Claude Code plugin `opscrew-aws@opscrew` (`plugin-aws/`) is packaged and wired into `.claude-plugin/marketplace.json`, with user documentation in `docs/guide/aws.md`.

## Out of Scope / Deferred
- Third-party (non-`@opscrew/*`) provider plugins (future explicit opt-in).
- Multi-region active-active AWS deployments (single-region + Multi-AZ HA in `034`).
- EKS / Kubernetes clusters (ECS Fargate / EC2 cover container workloads without EKS control-plane overhead).
- Mandatory real-AWS CI runs (live pass is optional on a throwaway account, covering only what `floci` cannot emulate: real IAM enforcement, real GitHub OIDC JWT, real ACM/CloudFront edge TLS).

