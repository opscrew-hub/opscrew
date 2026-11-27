# Deploy to Amazon Web Services (AWS)

OpsCrew supports deploying your app to **managed AWS services** (Lambda Web Functions, Lightsail
Containers, ECS Fargate, EC2 + Docker Compose, RDS PostgreSQL/MySQL, ElastiCache Valkey, S3 +
CloudFront, and CloudWatch) via an **optional official provider plugin**.

Keeping AWS in a separate plugin keeps the base `opscrew` CLI small and fast for VPS and
self-hosted users while giving AWS users full managed-services design, OpenTofu HCL generation,
and security policy enforcement.

## 1. Install the AWS provider plugin

Install the official `@opscrew/provider-aws` plugin once on your computer:

```bash
npx opscrew plugin add aws
```

OpsCrew installs only pinned official `@opscrew/provider-*` packages with `--ignore-scripts` and
verifies npm registry signatures and provenance before loading any code. Check installed plugins at
any time:

```bash
npx opscrew plugin list
```

If you use Claude Code, you can also install the companion guidance plugin `opscrew-aws@opscrew`
alongside the core `opscrew` plugin.

## 2. Authenticate to AWS

OpsCrew never asks you to paste keys into chat and never stores long-lived AWS keys in GitHub
Secrets. On your computer, authenticate with short-lived credentials:

- **Recommended:** AWS IAM Identity Center (`aws sso login` + `AWS_PROFILE`)
- Or set `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` (and optional `AWS_SESSION_TOKEN`) plus
  `AWS_REGION` in your terminal environment.

For CI/CD deployments from GitHub Actions, OpsCrew provisions a **keyless GitHub OIDC IAM role**
pinned to your exact repository and branch (`StringEquals` on `sub`, plus immutable GitHub
organization/repository IDs when provided). Zero static AWS keys are stored in GitHub.

## 3. Choose a preset and customize with `--set`

Run `npx opscrew interview` and select **Amazon Web Services (AWS)**, then run:

```bash
npx opscrew design
```

OpsCrew prices three opinionated presets and explains **why** each service was picked alongside
cheaper/higher-availability alternatives:

| Preset | Typical compute | Best for |
| --- | --- | --- |
| `aws-lean` | Lambda Web Functions (for stateless Node/Python web apps) or EC2 + Compose / Lightsail Containers | Side projects, low-traffic apps, tight budgets |
| `aws-balanced` | ECS Fargate (with optional Express Mode) + RDS Single-AZ + S3/CloudFront | Production SaaS with managed upgrades and zero server patching |
| `aws-production-ha` | ECS Fargate multi-task + RDS Multi-AZ / Aurora Serverless v2 + ElastiCache Valkey | High-availability workloads with strict uptime needs |

Override any individual component decision with repeatable `--set` flags:

```bash
npx opscrew design --option aws-balanced --set compute.service=ec2-compose --set pins.noNat=true
```

## 4. Built-in cost traps & security guardrails

Before every apply, OpsCrew runs deterministic AWS SecOps checks (`@opscrew/secops`) against your
OpenTofu plan and blocks unsafe configurations:

- **No wildcard IAM or OIDC trust (`aws-iam-least-privilege`, `aws-oidc-strict-sub`):** refuses `*`
  actions/resources and wildcard `sub` claims.
- **Private encrypted databases (`aws-rds-private`):** refuses `publicly_accessible = true` unless
  you record an explicit guardrail exception in `opscrew/plan.yaml`.
- **Encrypted private storage (`aws-storage-encrypted-private`):** requires S3 Block Public Access
  and server-side encryption on every bucket.
- **Zero secrets in Terraform state (`aws-no-secret-in-state`):** OpenTofu creates only empty
  Secrets Manager / SSM shells; OpsCrew writes secret values out-of-band after your plan-hash
  approval.
- **Explicit CloudWatch log retention (`aws-cloudwatch-retention`):** every log group carries an
  explicit `retention_in_days` (default 30 days) so logs never grow forever.
- **Cost traps avoided by default:** NAT Gateways (~$32/month per AZ before traffic) are avoided on
  `lean` and `balanced` in favor of public subnets with strict security groups + free S3 Gateway
  Endpoints; AWS Private CA ($400/month) is blocked in favor of free public ACM certificates.

## 5. Domains and Cloudflare DNS

If your domain's DNS is on Cloudflare (`pins.keepCloudflareDns: true`), OpsCrew keeps Cloudflare as
your DNS provider and writes ACM DNS-01 validation `CNAME` records with **`proxied: false`** (DNS
only) so AWS Certificate Manager validates cleanly without moving your zone to Route 53.

## 6. Day-2 operations and teardown

- **Status & CloudWatch logs:** `npx opscrew status` and `npx opscrew logs` read live AWS service
  health, CloudWatch alarms, and redacted CloudWatch Logs.
- **Snapshots & restore drills:** `npx opscrew snapshot` manages RDS snapshots and supports
  isolated throwaway restore drills (`PubliclyAccessible=false`, automatically cleaned up).
- **Retargeting from a VPS:** `npx opscrew retarget --to aws` defaults to `ec2-compose` for a
  zero-rewrite move before you opt into managed ECS/RDS services.
- **Teardown:** `npx opscrew destroy` generates an OpenTofu destroy plan and requires your typed
  confirmation of the app name bound to the destroy plan's SHA-256 hash.

