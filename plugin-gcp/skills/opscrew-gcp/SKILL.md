---
name: opscrew-gcp
description: Deploy and operate apps on Google Cloud (GCP) managed services with OpsCrew (Cloud Run, GCE + Compose, Cloud SQL, Memorystore Redis, Cloud Storage, Secret Manager, Direct VPC Egress, keyless GitHub WIF).
---

# OpsCrew Google Cloud (GCP) Skill

Use this skill whenever the user wants to deploy, inspect, resize, or destroy an application on **Google Cloud (GCP)** with OpsCrew.

## Install the GCP provider plugin first

Core OpsCrew never bundles GCP provider code by default. Install the signed official plugin:

```bash
opscrew plugin add gcp
```

Check installed plugins with `opscrew plugin list` or the `opscrew_plugins` MCP tool.

## Architecture presets & cost-trap guardrails

OpsCrew picks the right GCP services for the app and explains every component's `why` and monthly USD estimate:

- **`gcp-lean`** (default for small apps / tight budgets): Cloud Run v2 (`min_instance_count: 0`, free tier 2M requests/mo, built-in HTTPS), Direct VPC Egress (zero `google_vpc_access_connector` VM cost), Cloud SQL Enterprise `db-f1-micro` private IP, Memorystore Basic 1 GB Redis, Secret Manager (6 active versions free), Artifact Registry (0.5 GB free + cleanup policies), Cloud Logging (30-day retention). **Zero** Cloud Load Balancer (`$18+/mo` saved) and **zero** Cloud NAT (`$32+/mo` saved).
- **`gcp-balanced`**: Cloud Run v2 (`min_instance_count: 1`, 1 vCPU / 1 GiB), Cloud SQL Enterprise `db-custom-1-3840` private IP, Memorystore Basic 1 GB, uniform private Cloud Storage.
- **`gcp-production-ha`**: Regional Cloud Run v2 (`min_instance_count: 2`, 2 vCPU / 2 GiB), Cloud SQL Enterprise `db-custom-2-7680` Regional HA + 7-day PITR, Memorystore Standard HA 5 GB, 90-day Cloud Logging retention, optional Global HTTPS Load Balancer + Cloud Armor.

Override any component before apply with `--set`:

```bash
opscrew design --option gcp-lean --set compute=compute-engine --set observability.logsRetentionDays=60
```

## Non-negotiable GCP safety rules

1. **Keyless GitHub Workload Identity Federation (`google-github-actions/auth@v2`):** OpsCrew creates a Workload Identity Pool & OIDC Provider with `attribute_condition` pinned strictly to `assertion.repository == '<owner>/<repo>'` and `assertion.environment == '<env>'` (zero downloadable service account JSON keys).
2. **No primitive roles:** Never assigns `roles/owner`, `roles/editor`, or `roles/viewer`; separates deploy CI service account from runtime service account.
3. **Zero secrets in Terraform state:** Terraform creates only `google_secret_manager_secret` containers; secret versions are written out-of-band through OpsCrew's GCP connector after plan-hash approval.
4. **Direct VPC Egress only:** Blocks legacy `google_vpc_access_connector` (`$14–$100/mo` idle VM trap).
5. **Private Cloud SQL & uniform GCS:** Enforces `ipv4_enabled = false`, `ssl_mode = "ENCRYPTED_ONLY"`, `uniform_bucket_level_access = true`, and `public_access_prevention = "enforced"`.
6. **Cloudflare custom domains:** Certificate Manager DNS-01 `_acme-challenge` CNAME records are created DNS-only (`proxied: false`).
7. **Plan-hash approval & typed destroy:** Every `tofu apply`, Secret Manager rotation, PITR clone restore drill, and `destroy` goes through OpsCrew's SHA-256 plan-hash approval gate.
