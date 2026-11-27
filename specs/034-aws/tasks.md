# Tasks: Feature 034 — AWS Managed-Services Target & Installable Provider Plugins

**Feature:** `034-aws` | **Spec:** [spec.md](spec.md) | **Plan:** [plan.md](plan.md) | **ADR:** [ADR 0040](../../docs/adr/0040-managed-cloud-plugins-and-aws.md)

## Wave 0 — ADR, Spec, Plan & Tasks (Lead)

- [x] **T3400 (lead):** Author `docs/adr/0040-managed-cloud-plugins-and-aws.md`, `specs/034-aws/spec.md`, `plan.md`, and `tasks.md`.

## Wave 1 — Plugin Contract, Installer/Provenance & AWS Plan Schema (Lead)

- [x] **T3401 (lead):** Define `ManagedCloudProviderDefinition`, `ManagedCloudConnector`, `MANAGED_CLOUD_CONTRACT_VERSION = 1`, and plugin manifest types in `packages/contracts/src/managed-provider.ts` (re-exported from `@opscrew/contracts`).
- [x] **T3402 (lead):** Implement official plugin installer, provenance/signature verifier, contract version check, and dynamic loader in `packages/core/src/plugins/` (`installPlugin`, `removePlugin`, `listInstalledPlugins`, `loadManagedProvider`) with full unit tests (tampered integrity, bad provenance, contract mismatch, clean rollback).
- [x] **T3403 (lead):** Add AWS target schema (`AwsTargetSchema`, presets `lean`/`balanced`/`production-ha`, compute choices, per-component decisions with `why`/`alternatives`/`monthlyCostUsd`, `pins`, `guardrails`, `exceptions`, `observability`) in `packages/plan-schema/src/aws.ts` & `enums.ts` & `plan.ts`, cross-field refinements, unit tests, and regenerate `schemas/plan.schema.json`.

## Wave 2 — `@opscrew/provider-aws` Package & AWS SecOps Policies

- [ ] **T3404 (lead):** Scaffold `packages/providers/aws/` (`@opscrew/provider-aws`) with AWS pricing catalog & estimator (`src/pricing.ts`), deterministic preset/component Architect mapper (`src/design.ts` covering `ec2-compose`, `lightsail-containers`, `ecs-fargate`, `ecs-ec2`, `lambda-web`, zero-code-rewrite DB mapping, cost-trap avoidance), and `--set` override engine (`src/overrides.ts`) with unit tests.
- [ ] **T3405 (lead):** Implement vendored readable AWS HCL renderer (`packages/providers/aws/src/hcl/`: VPC + optional NAT/Gateway Endpoints, IAM GitHub OIDC with immutable-ID `sub` support, compute modules, RDS/Aurora v2, ElastiCache Valkey, S3 + CloudFront OAC, ACM `us-east-1`/regional, optional Route 53, Secrets Manager/SSM shells with zero secret values in state, EventBridge Scheduler, SQS/SNS, CloudWatch Logs + Alarms → SNS) and keyless OIDC GitHub Actions deploy workflow (`src/workflow.ts`) with unit tests.
- [ ] **T3406 (contributor — Slice A):** Implement deterministic AWS SecOps static policies in `packages/secops/src/policies/aws.ts` (`aws-iam-least-privilege`, `aws-oidc-strict-sub`, `aws-rds-private`, `aws-storage-encrypted-private`, `aws-no-secret-in-state`, `aws-cloudwatch-retention`) and AWS credential redaction/secret-scanner patterns with comprehensive unit tests.
- [ ] **T3407 (contributor — Slice B):** Implement lightweight injectable SigV4 AWS connector in `packages/providers/aws/src/connector.ts` (STS `GetCallerIdentity`, ECS/EC2/Lightsail/Lambda status, CloudWatch Logs/Metrics, RDS/ElastiCache snapshots & restore drills, Secrets Manager / SSM out-of-band secret writes, Pricing API) with fake-fetch unit tests and `AWS_ENDPOINT_URL` (`floci`) support.

## Wave 3 — Core Phase Wiring, CLI, MCP, Companion Plugin & Guide

- [ ] **T3408 (lead):** Wire `interview`, `design` (including `--set <component>.<field>=<value>`), and `provision` (HCL render, AWS SecOps gate, hash-bound apply, out-of-band secret population, Cloudflare ACM DNS-01 `proxied = false` records) in `packages/agents/src/` with unit tests.
- [ ] **T3409 (lead):** Wire `status`, `logs` (CloudWatch), `verify`, `drift`, `snapshot`/`restore`/restore drills, `rotate`, `advise`, `destroy`, and `retarget --to aws` (`ec2-compose`) in `packages/agents/src/` with unit tests.
- [ ] **T3410 (contributor — Slice C):** Add `opscrew plugin list|add|remove` and `design --set` CLI commands in `packages/cli/src/commands/`, expose AWS/plugin support in `packages/mcp-server/src/tools/`, scaffold companion Claude Code plugin `plugin-aws/` in `.claude-plugin/marketplace.json`, and author `docs/guide/aws.md` (linked from `docs/guide/index.md`) with CLI & MCP tests.

## Wave 4 — Real `floci` Emulator Verification, Opus 5.5 Review & Full Gate (Lead)

- [ ] **T3411 (lead):** Add real Docker `floci` (`floci/floci`, MIT, port `4566`) OpenTofu `init`/`validate`/`plan`/`apply`/`destroy` integration test (`packages/providers/aws/src/floci.docker.test.ts`, `OPSCREW_DOCKER_TESTS=1`) and run it cleanly with zero leftover containers.
- [ ] **T3412 (lead):** Standalone Opus 5.5 high-effort review over `034-aws` (plugin install/provenance, IAM/OIDC least privilege, secret-out-of-state, approvals/plan-hash boundaries), fix all findings, and pass full-repo merge gate (`gate exit 0`).
