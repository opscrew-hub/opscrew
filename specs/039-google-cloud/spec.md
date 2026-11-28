# Feature Specification: 039 — Google Cloud (GCP) Managed-Services Target

**Feature:** `039-google-cloud` | **Status:** In Progress | **Research:** [research.md](research.md) | **ADR:** [ADR 0040](../../docs/adr/0040-managed-cloud-plugins-and-aws.md)

## Overview

Adds **Google Cloud (GCP)** as the third official separately installed managed-cloud provider plugin (`@opscrew/provider-gcp`, installed via `opscrew plugin add gcp`), completing ADR 0040's managed-cloud trio (`aws`, `azure`, `gcp`) without growing core OpsCrew.

## User Stories

- **US1 — Installable GCP plugin (`opscrew plugin add gcp`):** Core loads `@opscrew/provider-gcp` only after pinned installation (`--ignore-scripts`) and npm signature + SLSA provenance verification, failing closed when uninstalled (`allowWorkspaceFallback: false`).
- **US2 — Honest GCP presets & `--set` overrides:** Maps `ProjectFacts` + `Requirements` to `gcp-lean`, `gcp-balanced`, and `gcp-production-ha` presets with plain-English `why`, rejected alternatives, USD monthly estimates, and cost-trap avoidance (Direct VPC Egress instead of legacy Serverless VPC Access Connectors, zero Cloud NAT by default, zero Global External ALB on `lean` unless requested, Memorystore for Valkey instead of legacy Redis, single-region co-location).
- **US3 — Readable vendored `hashicorp/google ~> 8.0` HCL & keyless Workload Identity Federation:** Generates readable OpenTofu HCL for Cloud Run v2 (plus Worker Pools/Jobs) and Compute Engine + Compose (`retarget --to gcp`), private Cloud SQL (no public IPv4), Memorystore for Valkey, private uniform-access GCS buckets, Secret Manager shells (zero secret versions in `.tfstate`), separate `deploy` vs `runtime` Service Accounts, and strict WIF CEL `attribute_condition` matching `google-github-actions/auth@v2` `environment:`.
- **US4 — Deterministic fail-closed GCP SecOps gate:** Blocks wildcard/missing WIF `attribute_condition`, static `google_service_account_key`, overly broad IAM roles (`roles/owner`/`roles/editor`), public Cloud SQL IPv4, legacy VPC connectors, legacy `google_redis_instance`, public/non-uniform GCS buckets, `google_secret_manager_secret_version` in state, and open VPC firewall DB/SSH ports before any approval.
- **US5 — Out-of-band secrets, Cloudflare Certificate Manager DNS-01, and Day-2 operations:** Populates Secret Manager versions out-of-band after hash-bound apply, writes Cloudflare `_acme-challenge` DNS-01 CNAME records with `proxied: false`, and supports `status`, `logs` (Cloud Logging), `verify`, `drift`, Cloud SQL backups & approval-gated private clone restore drills, secret rotation, `advise`, `retarget --to gcp`, and typed-confirmation `destroy`.
