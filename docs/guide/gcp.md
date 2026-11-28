# Google Cloud (GCP)

OpsCrew can deploy your application onto **Google Cloud managed services** via the official separately installed `@opscrew/provider-gcp` plugin. Core OpsCrew stays lightweight for everyone else — install GCP support only when you need it.

## 1. Install the GCP plugin

```bash
opscrew plugin add gcp
```

OpsCrew installs the pinned official `@opscrew/provider-gcp` package into `~/.opscrew/plugins/gcp` with `--ignore-scripts` and verifies its npm registry signatures and SLSA provenance before loading any code.

If you use Claude Code, you can also install the companion skill plugin `opscrew-gcp@opscrew` from the OpsCrew marketplace.

## 2. Authenticate locally

Set your Google Cloud project and a short-lived OAuth access token (or ADC token) in your environment:

- `GOOGLE_CLOUD_PROJECT` (or `GCP_PROJECT_ID`)
- `GOOGLE_OAUTH_ACCESS_TOKEN` (from `gcloud auth print-access-token`)

Deployments from GitHub Actions never use static service account JSON keys — OpsCrew configures **keyless Workload Identity Federation** (`google-github-actions/auth@v2`) with `attribute_condition` pinned strictly to `assertion.repository == '<owner>/<repo>'` and `assertion.environment == '<env>'`.

## 3. Architecture presets

| Preset | Compute | Database | Cache | Edge | Cost traps avoided |
| --- | --- | --- | --- | --- | --- |
| `gcp-lean` | Cloud Run v2 (`min_instance_count: 0`, 0.5 vCPU / 512 MiB) | Cloud SQL Enterprise `db-f1-micro` (private IP) | Memorystore Basic 1 GB | Cloudflare or Cloud Run HTTPS | No legacy VPC Connector, no Cloud NAT (~$32/mo), no Global LB (~$18+/mo) |
| `gcp-balanced` | Cloud Run v2 (`min_instance_count: 1`, 1 vCPU / 1 GiB) | Cloud SQL Enterprise `db-custom-1-3840` (private IP) | Memorystore Basic 1 GB | Cloudflare or Cloud Run HTTPS | Direct VPC Egress (zero connector VMs), explicit 30-day log retention |
| `gcp-production-ha` | Regional Cloud Run v2 (`min_instance_count: 2`, 2 vCPU / 2 GiB) | Cloud SQL Enterprise `db-custom-2-7680` Regional HA + 7-day PITR | Memorystore Standard HA 5 GB | Global HTTPS LB + Cloud Armor (or Cloudflare if pinned) | Explicit 90-day log retention, Artifact Registry cleanup policies |

You can override any component before provisioning and see the exact monthly cost delta:

```bash
opscrew design --option gcp-lean --set compute=compute-engine
opscrew design --option gcp-balanced --set pins.noNat=true --set observability.logsRetentionDays=60
```

Supported compute kinds: `cloud-run` (default) and `compute-engine` (`e2-small` shielded VM bridge for VPS/Compose apps moving to GCP).

## 4. Guardrails & security checks

Every GCP plan is checked deterministically by `@opscrew/secops` before you are asked to approve it:

- **Strict Workload Identity Federation:** Fails closed if `google_iam_workload_identity_pool_provider` omits `https://token.actions.githubusercontent.com` or lacks a strict `attribute_condition` pinning `assertion.repository`.
- **Zero static SA keys:** Blocks `google_service_account_key` resources completely.
- **No primitive roles:** Refuses `roles/owner`, `roles/editor`, and `roles/viewer` IAM bindings.
- **Direct VPC Egress only:** Blocks legacy `google_vpc_access_connector`.
- **Private Cloud SQL & uniform Cloud Storage:** Enforces `ipv4_enabled = false`, `ssl_mode = "ENCRYPTED_ONLY"`, `uniform_bucket_level_access = true`, and `public_access_prevention = "enforced"`.
- **No secrets in Terraform state:** Blocks `google_secret_manager_secret_version` in HCL; secret values are written out-of-band via OpsCrew's GCP connector after plan-hash approval.
- **Explicit log retention & firewall rules:** Blocks Cloud Logging buckets without `retention_days` between `1` and `3650`, and refuses ingress firewall rules exposing ports `22`, `3306`, `5432`, `6379`, or `27017` to `0.0.0.0/0` or `::/0`.

Guardrails cannot be disabled silently — relaxing one requires an explicit reason under `target.exceptions` in `opscrew/plan.yaml`.

## 5. Custom domains with Cloudflare

When your domain stays on Cloudflare (`dns.provider: cloudflare`), OpsCrew writes the Certificate Manager DNS-01 `_acme-challenge` CNAME record with `proxied: false` (DNS-only) so Google Certificate Manager can validate ownership cleanly.

## 6. Day-2 operations & destroy

- `opscrew status` / `opscrew verify` — checks project auth, compute health, and HTTPS endpoint.
- `opscrew logs` — queries redacted logs from Google Cloud Logging.
- `opscrew drift` — compares rendered HCL and runs a refresh-only OpenTofu plan.
- Backups & PITR restore drills — clones into a private throwaway Cloud SQL instance (`ipv4Enabled: false`), verifies `RUNNABLE`, and confirms deletion after approval.
- `opscrew destroy` — requires SHA-256 plan-hash approval plus typing your app's name (`allowDestroy: true`). Note: Google Cloud soft-deletes Workload Identity Pools for 30 days; if you re-provision the exact same app/environment within 30 days, undelete the pool with `gcloud iam workload-identity-pools undelete <pool-id> --location=global`.
