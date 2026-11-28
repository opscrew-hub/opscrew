/**
 * Vendored readable OpenTofu/Terraform HCL renderer for Google Cloud (Feature 039, T3903).
 *
 * Targets `hashicorp/google ~> 8.0` (8.12.0+). Incorporates every GCP security & cost guardrail:
 * - Callback-escaped `hclString()` preserving `$${` and `%%{`
 * - Strict CEL character validation blocking quote/operator injection in WIF `attribute_condition`
 * - Separate `deploy` (GitHub WIF OIDC) and `runtime` (app) Service Accounts; zero SA JSON keys
 * - Regional Google Artifact Registry DOCKER repository with cleanup policy + scoped writer/reader
 * - Cloud Run v2 with Direct VPC Egress (`PRIVATE_RANGES_ONLY`), zero legacy VPC connectors,
 *   explicit `deletion_protection`, `lifecycle { ignore_changes }`, and Secret Manager `secret_key_ref`
 * - Compute Engine + Compose with Caddy HTTPS TLS, IAP SSH (`35.235.240.0/20`), OS Login, and
 *   instance-scoped deploy IAM (zero project-wide `compute.instanceAdmin.v1`)
 * - Private Cloud SQL (`edition = "ENTERPRISE"`, `ipv4_enabled = false`, `ssl_mode = "ENCRYPTED_ONLY"`,
 *   MySQL `binary_log_enabled`, Postgres IAM auth + DB + runtime IAM user)
 * - Memorystore for Valkey (`google_memorystore_instance`) + PSC Service Connection Policy
 * - Single-region uniform private GCS bucket (`public_access_prevention = "enforced"`)
 * - One Secret Manager shell per declared secret key (ZERO `google_secret_manager_secret_version`)
 * - Complete Global External ALB + Certificate Manager map + URL map + HTTPS proxy + global IP
 */
import { createHash } from "node:crypto";
import type { ManagedCloudRenderedFile } from "@opscrew/contracts";
import type { GcpTarget } from "@opscrew/plan-schema";
import { gcpDbInstanceName, gcpServiceName } from "../connector";

export const GCP_PROVIDER_VERSION = "~> 8.0";

const GITHUB_SLUG_RE = /^[A-Za-z0-9_.-]+$/;
const GITHUB_ENV_RE = /^[A-Za-z0-9_. -]+$/;
const GITHUB_BRANCH_RE = /^[A-Za-z0-9_./-]+$/;

export interface RenderGcpHclContext {
  readonly appName: string;
  readonly environment: string;
  readonly target: GcpTarget;
  readonly domain?: string;
  readonly dnsProvider?: string;
  readonly containerPort?: number;
  readonly secretNames?: readonly string[];
  readonly github: {
    readonly owner: string;
    readonly repo: string;
    readonly environmentName?: string;
    readonly branch?: string;
  };
}

export function hclString(value: string): string {
  const escaped = value
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"')
    .replace(/\n/g, "\\n")
    .replace(/\r/g, "\\r")
    .replace(/\t/g, "\\t")
    .replace(/\$\{/g, () => "$${")
    .replace(/%\{/g, () => "%%{");
  return `"${escaped}"`;
}

function shortHash(value: string): string {
  return createHash("sha256").update(value).digest("hex").slice(0, 6);
}

/** Deterministic GCP ID with a 6-char hash suffix clamped to `maxLen` to avoid collisions across envs/re-provisions. */
function hashedGcpId(prefix: string, raw: string, maxLen: number): string {
  const hash = shortHash(`${prefix}:${raw}`);
  const clean = `${prefix}-${raw}`
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");
  const headMax = Math.max(4, maxLen - 7);
  const head = clean.slice(0, headMax).replace(/-+$/g, "");
  return `${head}-${hash}`;
}

function sanitizeSecretId(raw: string): string {
  return raw.replace(/[^a-zA-Z0-9_-]/g, "_");
}

function validateWifGithub(github: RenderGcpHclContext["github"]): {
  owner: string;
  repo: string;
  env?: string;
  branch?: string;
} {
  const owner = github.owner.trim();
  const repo = github.repo.trim();
  if (!GITHUB_SLUG_RE.test(owner) || !GITHUB_SLUG_RE.test(repo)) {
    throw new Error(
      `Invalid GitHub repository "${github.owner}/${github.repo}" for GCP WIF CEL condition: only letters, digits, ".", "_", and "-" are permitted.`,
    );
  }
  const env = github.environmentName?.trim();
  if (env !== undefined && env.length > 0) {
    if (!GITHUB_ENV_RE.test(env)) {
      throw new Error(
        `Invalid GitHub environment "${env}" for GCP WIF CEL condition: unsafe characters rejected.`,
      );
    }
    return { owner, repo, env };
  }
  const branch = (github.branch ?? "main").trim();
  if (!GITHUB_BRANCH_RE.test(branch)) {
    throw new Error(
      `Invalid GitHub branch "${branch}" for GCP WIF CEL condition: unsafe characters rejected.`,
    );
  }
  return { owner, repo, branch };
}

/** Builds a strict CEL attribute_condition pinning GitHub repository and environment/branch. */
export function gcpWifAttributeCondition(github: RenderGcpHclContext["github"]): string {
  const checked = validateWifGithub(github);
  const repoFull = `${checked.owner}/${checked.repo}`;
  if (checked.env !== undefined) {
    return `assertion.repository == '${repoFull}' && assertion.environment == '${checked.env}'`;
  }
  return `assertion.repository == '${repoFull}' && assertion.ref == 'refs/heads/${checked.branch ?? "main"}'`;
}

function wantsActiveAlb(ctx: RenderGcpHclContext): boolean {
  return (
    ctx.target.compute === "cloud-run" &&
    ctx.target.components.edge?.service === "global-alb-cloud-cdn" &&
    Boolean(ctx.domain?.trim())
  );
}

function normalizedSecretEntries(
  ctx: RenderGcpHclContext,
): Array<{ envName: string; secretId: string }> {
  const names = (ctx.secretNames ?? []).filter((n) => n.trim().length > 0);
  const seen = new Map<string, string>();
  const out: Array<{ envName: string; secretId: string }> = [];
  for (const raw of names) {
    const secretId = sanitizeSecretId(raw);
    const existing = seen.get(secretId);
    if (existing !== undefined && existing !== raw) {
      throw new Error(
        `GCP Secret Manager name collision: "${existing}" and "${raw}" both map to "${secretId}".`,
      );
    }
    if (existing === undefined) {
      seen.set(secretId, raw);
      out.push({ envName: raw, secretId });
    }
  }
  return out;
}

function renderVersionsTf(): string {
  return `# Generated by OpsCrew (@opscrew/provider-gcp, Feature 039)
terraform {
  required_version = ">= 1.6.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ${hclString(GCP_PROVIDER_VERSION)}
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}
`;
}

function renderVariablesTf(ctx: RenderGcpHclContext): string {
  const port = ctx.containerPort ?? 3000;
  const projectDefault = ctx.target.pins.projectId ?? "replace-with-gcp-project-id";
  return `variable "project_id" {
  type        = string
  description = "Google Cloud project ID."
  default     = ${hclString(projectDefault)}
}

variable "app_name" {
  type        = string
  description = "Application name."
  default     = ${hclString(ctx.appName)}
}

variable "environment" {
  type        = string
  description = "Deployment environment name."
  default     = ${hclString(ctx.environment)}
}

variable "region" {
  type        = string
  description = "Google Cloud region."
  default     = ${hclString(ctx.target.region)}
}

variable "container_image" {
  type        = string
  description = "Initial bootstrap image; live revisions are deployed from Artifact Registry via keyless GitHub WIF."
  default     = "us-docker.pkg.dev/cloudrun/container/hello"
}

variable "container_port" {
  type        = number
  description = "Application HTTP port inside the container."
  default     = ${port}
}

variable "app_subnet_cidr" {
  type        = string
  description = "Primary VPC subnet CIDR for Direct VPC Egress and private resources."
  default     = "10.44.0.0/24"
}
`;
}

function renderNetworkTf(ctx: RenderGcpHclContext): string {
  const name = gcpServiceName(ctx.appName, ctx.environment);
  const existingVpc = ctx.target.pins.existingVpcId;
  const hasDb = ctx.target.components.database !== undefined;
  const publicDb = ctx.target.guardrails.privateDatabase === false;
  const needsPsa = hasDb && !publicDb;
  const natEnabled = ctx.target.components.network?.config.cloudNat === true;
  const isComputeEngine = ctx.target.compute === "compute-engine";

  const vpcBlock =
    existingVpc !== undefined
      ? `locals {
  existing_vpc_parts = split("/", ${hclString(existingVpc)})
  vpc_name           = local.existing_vpc_parts[length(local.existing_vpc_parts) - 1]
}

data "google_compute_network" "existing" {
  name    = local.vpc_name
  project = var.project_id
}

locals {
  active_vpc_id   = data.google_compute_network.existing.id
  active_vpc_name = data.google_compute_network.existing.name
}
`
      : `resource "google_compute_network" "app" {
  name                    = ${hclString(`vpc-${name}`)}
  auto_create_subnetworks = false
}

locals {
  active_vpc_id   = google_compute_network.app.id
  active_vpc_name = google_compute_network.app.name
}
`;

  const gceFirewalls = isComputeEngine
    ? `
resource "google_compute_firewall" "allow_https" {
  name    = ${hclString(`fw-https-${name}`)}
  network = local.active_vpc_name

  allow {
    protocol = "tcp"
    ports    = ["80", "443"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["opscrew-web"]
}

resource "google_compute_firewall" "allow_iap_ssh" {
  name    = ${hclString(`fw-iap-ssh-${name}`)}
  network = local.active_vpc_name

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  # Google Identity-Aware Proxy (IAP) TCP forwarding CIDR only (never 0.0.0.0/0).
  source_ranges = ["35.235.240.0/20"]
  target_tags   = ["opscrew-web"]
}
`
    : "";

  const psaBlock = needsPsa
    ? `
resource "google_compute_global_address" "private_service_range" {
  name          = ${hclString(`psa-${name}`)}
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 20
  network       = local.active_vpc_id
}

resource "google_service_networking_connection" "private_vpc" {
  network                 = local.active_vpc_id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_service_range.name]
}
`
    : "";

  const natBlock = natEnabled
    ? `
resource "google_compute_router" "app" {
  name    = ${hclString(`cr-${name}`)}
  region  = var.region
  network = local.active_vpc_id
}

resource "google_compute_router_nat" "app" {
  name                               = ${hclString(`nat-${name}`)}
  router                             = google_compute_router.app.name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"
}
`
    : "";

  return `${vpcBlock}
resource "google_compute_subnetwork" "app" {
  name                     = ${hclString(`snet-${name}`)}
  ip_cidr_range            = var.app_subnet_cidr
  region                   = var.region
  network                  = local.active_vpc_id
  private_ip_google_access = true
}
${gceFirewalls}${psaBlock}${natBlock}`;
}

function renderIamTf(ctx: RenderGcpHclContext): string {
  const checked = validateWifGithub(ctx.github);
  const repoFull = `${checked.owner}/${checked.repo}`;
  const rawKey = `${ctx.appName}-${ctx.environment}`;
  const name = gcpServiceName(ctx.appName, ctx.environment);
  const deploySaId = hashedGcpId("deploy", rawKey, 30);
  const runtimeSaId = hashedGcpId("run", rawKey, 30);
  const poolId = hashedGcpId("gh", rawKey, 32);
  const condition = gcpWifAttributeCondition(ctx.github);
  const isEnvMode = checked.env !== undefined;

  const attributeMapping = isEnvMode
    ? `  attribute_mapping = {
    "google.subject"        = "assertion.sub"
    "attribute.actor"       = "assertion.actor"
    "attribute.repository"  = "assertion.repository"
    "attribute.environment" = "assertion.environment"
    "attribute.repo_env"    = "assertion.repository + ':' + assertion.environment"
  }`
    : `  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.actor"      = "assertion.actor"
    "attribute.repository" = "assertion.repository"
    "attribute.ref"        = "assertion.ref"
  }`;

  const principalMember = isEnvMode
    ? `principalSet://iam.googleapis.com/\${google_iam_workload_identity_pool.github.name}/attribute.repo_env/${repoFull}:${checked.env}`
    : `principalSet://iam.googleapis.com/\${google_iam_workload_identity_pool.github.name}/attribute.repository/${repoFull}`;

  const computeDeployIam =
    ctx.target.compute === "compute-engine"
      ? `# Instance-scoped deploy IAM only (no project-wide compute.instanceAdmin.v1 or startup-script takeover).
resource "google_compute_instance_iam_member" "deploy_os_login" {
  project       = var.project_id
  zone          = google_compute_instance.app.zone
  instance_name = google_compute_instance.app.name
  role          = "roles/compute.osAdminLogin"
  member        = "serviceAccount:\${google_service_account.deploy.email}"
}

resource "google_iap_tunnel_instance_iam_member" "deploy_iap" {
  project  = var.project_id
  zone     = google_compute_instance.app.zone
  instance = google_compute_instance.app.name
  role     = "roles/iap.tunnelResourceAccessor"
  member   = "serviceAccount:\${google_service_account.deploy.email}"
}
`
      : `resource "google_project_iam_member" "deploy_role" {
  project = var.project_id
  role    = "roles/run.developer"
  member  = "serviceAccount:\${google_service_account.deploy.email}"
}

resource "google_service_account_iam_member" "deploy_act_as_runtime" {
  service_account_id = google_service_account.runtime.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:\${google_service_account.deploy.email}"
}
`;

  return `# Separate CI/CD deploy SA (no Secret Manager read access) and app runtime SA.
# Zero google_service_account_key resources (keyless Workload Identity Federation only).
resource "google_service_account" "deploy" {
  account_id   = ${hclString(deploySaId)}
  display_name = ${hclString(`OpsCrew Deploy SA (${ctx.appName}/${ctx.environment})`)}
}

resource "google_service_account" "runtime" {
  account_id   = ${hclString(runtimeSaId)}
  display_name = ${hclString(`OpsCrew Runtime SA (${ctx.appName}/${ctx.environment})`)}
}

resource "google_iam_workload_identity_pool" "github" {
  workload_identity_pool_id = ${hclString(poolId)}
  display_name              = "GitHub Actions Pool"
}

resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = "github-actions"

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }

${attributeMapping}

  attribute_condition = ${hclString(condition)}
}

resource "google_service_account_iam_member" "github_wif" {
  service_account_id = google_service_account.deploy.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "${principalMember}"
}

# Regional Artifact Registry repository for Cloud Run / Compute Engine container images.
resource "google_artifact_registry_repository" "app" {
  location      = var.region
  repository_id = ${hclString(name)}
  description   = ${hclString(`OpsCrew container images for ${ctx.appName} (${ctx.environment})`)}
  format        = "DOCKER"

  cleanup_policies {
    id     = "keep-recent"
    action = "KEEP"
    most_recent_versions {
      keep_count = 10
    }
  }
}

resource "google_artifact_registry_repository_iam_member" "deploy_writer" {
  location   = google_artifact_registry_repository.app.location
  repository = google_artifact_registry_repository.app.name
  role       = "roles/artifactregistry.writer"
  member     = "serviceAccount:\${google_service_account.deploy.email}"
}

resource "google_artifact_registry_repository_iam_member" "runtime_reader" {
  location   = google_artifact_registry_repository.app.location
  repository = google_artifact_registry_repository.app.name
  role       = "roles/artifactregistry.reader"
  member     = "serviceAccount:\${google_service_account.runtime.email}"
}

${computeDeployIam}`;
}

function renderComputeTf(ctx: RenderGcpHclContext): string {
  const name = gcpServiceName(ctx.appName, ctx.environment);
  const cfg = ctx.target.components.compute?.config ?? {};
  const secretEntries = normalizedSecretEntries(ctx);

  if (ctx.target.compute === "compute-engine") {
    const machineType = typeof cfg.machineType === "string" ? cfg.machineType : "e2-small";
    const caddySite = ctx.domain?.trim() || ":80";
    const startupScript = `#!/usr/bin/env bash
set -euo pipefail
apt-get update && apt-get install -y docker.io docker-compose-v2
systemctl enable --now docker
mkdir -p /opt/opscrew
cat <<'EOF' >/opt/opscrew/Caddyfile
${caddySite} {
  reverse_proxy app:${ctx.containerPort ?? 3000}
}
EOF
cat <<'EOF' >/opt/opscrew/compose.yml
services:
  caddy:
    image: caddy:2-alpine
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /opt/opscrew/Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy_data:/data
      - caddy_config:/config
    depends_on:
      - app
  app:
    image: \${OPSCREW_IMAGE:-us-docker.pkg.dev/cloudrun/container/hello}
    restart: unless-stopped
    expose:
      - "${ctx.containerPort ?? 3000}"
volumes:
  caddy_data:
  caddy_config:
EOF
docker compose -f /opt/opscrew/compose.yml up -d
`;
    return `resource "google_compute_instance" "app" {
  name         = ${hclString(name)}
  machine_type = ${hclString(machineType)}
  zone         = "\${var.region}-a"
  tags         = ["opscrew-web"]

  metadata = {
    enable-oslogin = "TRUE"
  }

  boot_disk {
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-2404-lts-amd64"
      size  = 30
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.app.id
    access_config {}
  }

  metadata_startup_script = ${hclString(startupScript)}

  service_account {
    email  = google_service_account.runtime.email
    scopes = ["cloud-platform"]
  }
}

locals {
  app_endpoint = google_compute_instance.app.network_interface[0].access_config[0].nat_ip
}
`;
  }

  // Default: Cloud Run v2 with Direct VPC Egress (PRIVATE_RANGES_ONLY)
  const minInstances = typeof cfg.minInstances === "number" ? cfg.minInstances : 0;
  const maxInstances = typeof cfg.maxInstances === "number" ? cfg.maxInstances : 4;
  const cpu = typeof cfg.cpu === "number" ? cfg.cpu : 1;
  const memoryMb = typeof cfg.memoryMb === "number" ? cfg.memoryMb : 512;
  const albActive = wantsActiveAlb(ctx);
  const ingress = albActive ? "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER" : "INGRESS_TRAFFIC_ALL";
  const deletionProtection = ctx.target.preset === "production-ha";

  const secretEnvBlocks = secretEntries
    .map(
      (s) => `      env {
        name = ${hclString(s.envName)}
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.app[${hclString(s.secretId)}].secret_id
            version = "latest"
          }
        }
      }`,
    )
    .join("\n\n");

  return `resource "google_cloud_run_v2_service" "app" {
  name                = ${hclString(name)}
  location            = var.region
  ingress             = ${hclString(ingress)}
  deletion_protection = ${deletionProtection ? "true" : "false"}

  template {
    service_account = google_service_account.runtime.email

    scaling {
      min_instance_count = ${minInstances}
      max_instance_count = ${maxInstances}
    }

    vpc_access {
      egress = "PRIVATE_RANGES_ONLY"
      network_interfaces {
        network    = local.active_vpc_name
        subnetwork = google_compute_subnetwork.app.name
      }
    }

    containers {
      image = var.container_image

      ports {
        container_port = var.container_port
      }

      resources {
        limits = {
          cpu    = ${hclString(String(cpu))}
          memory = ${hclString(`${memoryMb}Mi`)}
        }
      }
${secretEnvBlocks.length > 0 ? `\n${secretEnvBlocks}\n` : ""}    }
  }

  lifecycle {
    ignore_changes = [template[0].containers[0].image]
  }
}

resource "google_cloud_run_v2_service_iam_member" "public_invoker" {
  project  = google_cloud_run_v2_service.app.project
  location = google_cloud_run_v2_service.app.location
  name     = google_cloud_run_v2_service.app.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

locals {
  app_endpoint = google_cloud_run_v2_service.app.uri
}
`;
}

function renderDatabaseTf(ctx: RenderGcpHclContext): string | undefined {
  const db = ctx.target.components.database;
  if (db === undefined) return undefined;
  const instanceName = gcpDbInstanceName(ctx.appName, ctx.environment);
  const dbName = ctx.appName
    .toLowerCase()
    .replace(/[^a-z0-9_]/g, "_")
    .replace(/^[^a-z]/, "a")
    .slice(0, 63);
  const isMysql = db.service === "cloud-sql-mysql";
  const publicAccess = ctx.target.guardrails.privateDatabase === false;
  const regionalHa = db.config.regionalHa === true;
  let tier = typeof db.config.tier === "string" ? db.config.tier : "db-f1-micro";
  if (regionalHa && tier === "db-f1-micro") {
    tier = "db-custom-1-3840";
  }
  const retention =
    typeof db.config.backupRetentionDays === "number" ? db.config.backupRetentionDays : 7;

  const backupPitrBlock = isMysql
    ? `      enabled            = true
      binary_log_enabled = true`
    : `      enabled                        = true
      point_in_time_recovery_enabled = true`;

  const iamAuthFlags = isMysql
    ? `
    database_flags {
      name  = "cloudsql_iam_authentication"
      value = "on"
    }`
    : `
    database_flags {
      name  = "cloudsql.iam_authentication"
      value = "on"
    }`;

  const iamUserNameExpr = isMysql
    ? `split("@", google_service_account.runtime.email)[0]`
    : `trimsuffix(google_service_account.runtime.email, ".gserviceaccount.com")`;

  return `resource "google_sql_database_instance" "app" {
  name                = ${hclString(instanceName)}
  database_version    = ${hclString(isMysql ? "MYSQL_8_0" : "POSTGRES_16")}
  region              = var.region
  deletion_protection = ${ctx.target.preset === "production-ha" ? "true" : "false"}

  settings {
    edition           = "ENTERPRISE"
    tier              = ${hclString(tier)}
    availability_type = ${hclString(regionalHa ? "REGIONAL" : "ZONAL")}
    disk_size         = 10

    ip_configuration {
      ipv4_enabled    = ${publicAccess ? "true" : "false"}
      ssl_mode        = "ENCRYPTED_ONLY"
      ${publicAccess ? "" : "private_network = local.active_vpc_id"}
    }

    backup_configuration {
${backupPitrBlock}
      backup_retention_settings {
        retained_backups = ${retention}
      }
    }${iamAuthFlags}
  }
${publicAccess ? "" : "\n  depends_on = [google_service_networking_connection.private_vpc]\n"}}

resource "google_sql_database" "app" {
  name     = ${hclString(dbName)}
  instance = google_sql_database_instance.app.name
}

resource "google_sql_user" "runtime" {
  name     = ${iamUserNameExpr}
  instance = google_sql_database_instance.app.name
  type     = "CLOUD_IAM_SERVICE_ACCOUNT"
}

resource "google_project_iam_member" "runtime_cloudsql_client" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:\${google_service_account.runtime.email}"
}

resource "google_project_iam_member" "runtime_cloudsql_instance_user" {
  project = var.project_id
  role    = "roles/cloudsql.instanceUser"
  member  = "serviceAccount:\${google_service_account.runtime.email}"
}
`;
}

function renderCacheTf(ctx: RenderGcpHclContext): string | undefined {
  const cache = ctx.target.components.cache;
  if (cache === undefined) return undefined;
  const nodeType =
    typeof cache.config.nodeType === "string" ? cache.config.nodeType : "SHARED_CORE_NANO";
  const replicas = typeof cache.config.replicaCount === "number" ? cache.config.replicaCount : 0;
  const baseName = gcpServiceName(ctx.appName, ctx.environment);
  const name = `valkey-${baseName}`.slice(0, 63);

  return `# Service Connection Policy required for Memorystore for Valkey PSC auto-created endpoints.
resource "google_network_connectivity_service_connection_policy" "memorystore" {
  name          = ${hclString(`scp-${baseName}`.slice(0, 63))}
  location      = var.region
  service_class = "gcp-memorystore"
  network       = local.active_vpc_id

  psc_config {
    subnetworks = [google_compute_subnetwork.app.id]
  }
}

# Memorystore for Valkey (replaces legacy google_redis_instance)
resource "google_memorystore_instance" "app" {
  instance_id                 = ${hclString(name)}
  location                    = var.region
  shard_count                 = 1
  replica_count               = ${replicas}
  node_type                   = ${hclString(nodeType)}
  authorization_mode          = "IAM_AUTH"
  transit_encryption_mode     = "SERVER_AUTHENTICATION"
  deletion_protection_enabled = false

  desired_auto_created_endpoints {
    network    = local.active_vpc_id
    project_id = var.project_id
  }

  depends_on = [google_network_connectivity_service_connection_policy.memorystore]
}
`;
}

function renderStorageTf(ctx: RenderGcpHclContext): string | undefined {
  const storage = ctx.target.components.storage;
  if (storage === undefined) return undefined;
  const bucketName = hashedGcpId("opscrew", `${ctx.appName}-${ctx.environment}-assets`, 63);
  const publicAccess = ctx.target.guardrails.privateStorage === false;

  return `# Single-region GCS bucket co-located with Cloud Run (uniform access + public prevention)
resource "google_storage_bucket" "app" {
  name                        = ${hclString(bucketName)}
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = ${hclString(publicAccess ? "inherited" : "enforced")}
  force_destroy               = false
}

resource "google_storage_bucket_iam_member" "runtime_object_user" {
  bucket = google_storage_bucket.app.name
  role   = "roles/storage.objectUser"
  member = "serviceAccount:\${google_service_account.runtime.email}"
}
`;
}

function renderSecretsTf(ctx: RenderGcpHclContext): string {
  const entries = normalizedSecretEntries(ctx);
  const secretIds =
    entries.length > 0
      ? entries.map((e) => e.secretId)
      : [sanitizeSecretId(`opscrew_${ctx.appName}_${ctx.environment}_app_env`)];
  const setLiteral = secretIds.map((id) => `    ${hclString(id)},`).join("\n");

  return `# Secret Manager shells ONLY — zero secret versions in Terraform state.
# Secret values are populated out-of-band via OpsCrew's GCP connector after plan-hash approval.
locals {
  opscrew_secret_ids = toset([
${setLiteral}
  ])
}

resource "google_secret_manager_secret" "app" {
  for_each  = local.opscrew_secret_ids
  secret_id = each.value

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_iam_member" "runtime_accessor" {
  for_each  = google_secret_manager_secret.app
  secret_id = each.value.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:\${google_service_account.runtime.email}"
}
`;
}

function renderEdgeTf(ctx: RenderGcpHclContext): string | undefined {
  if (!wantsActiveAlb(ctx)) return undefined;
  const domain = ctx.domain?.trim();
  if (!domain) return undefined;
  const name = gcpServiceName(ctx.appName, ctx.environment);

  return `resource "google_certificate_manager_dns_authorization" "app" {
  name        = ${hclString(`dns-auth-${name}`)}
  description = ${hclString(`DNS-01 authorization for ${domain} (keep _acme-challenge CNAME unproxied on Cloudflare)`)}
  domain      = ${hclString(domain)}
}

resource "google_certificate_manager_certificate" "app" {
  name = ${hclString(`cert-${name}`)}

  managed {
    domains            = [${hclString(domain)}]
    dns_authorizations = [google_certificate_manager_dns_authorization.app.id]
  }
}

resource "google_certificate_manager_certificate_map" "app" {
  name        = ${hclString(`cmap-${name}`)}
  description = ${hclString(`Certificate map for ${domain}`)}
}

resource "google_certificate_manager_certificate_map_entry" "app" {
  name         = ${hclString(`cme-${name}`)}
  map          = google_certificate_manager_certificate_map.app.name
  certificates = [google_certificate_manager_certificate.app.id]
  hostname     = ${hclString(domain)}
}

resource "google_compute_region_network_endpoint_group" "cloud_run" {
  name                  = ${hclString(`neg-${name}`)}
  network_endpoint_type = "SERVERLESS"
  region                = var.region

  cloud_run {
    service = google_cloud_run_v2_service.app.name
  }
}

resource "google_compute_backend_service" "app" {
  name                  = ${hclString(`be-${name}`)}
  load_balancing_scheme = "EXTERNAL_MANAGED"
  enable_cdn            = true

  backend {
    group = google_compute_region_network_endpoint_group.cloud_run.id
  }
}

resource "google_compute_url_map" "app" {
  name            = ${hclString(`um-${name}`)}
  default_service = google_compute_backend_service.app.id
}

resource "google_compute_target_https_proxy" "app" {
  name            = ${hclString(`https-${name}`)}
  url_map         = google_compute_url_map.app.id
  certificate_map = "//certificatemanager.googleapis.com/\${google_certificate_manager_certificate_map.app.id}"
}

resource "google_compute_global_address" "alb" {
  name = ${hclString(`ip-${name}`)}
}

resource "google_compute_global_forwarding_rule" "https" {
  name                  = ${hclString(`fr-${name}`)}
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = "443"
  target                = google_compute_target_https_proxy.app.id
  ip_address            = google_compute_global_address.alb.id
}
`;
}

function renderOutputsTf(ctx: RenderGcpHclContext): string {
  const albActive = wantsActiveAlb(ctx);
  const acmeOutput = albActive
    ? `
output "alb_ip" {
  description = "Global External ALB static IPv4 address for the custom domain A record."
  value       = google_compute_global_address.alb.address
}

output "acme_validation_records" {
  description = "Certificate Manager DNS-01 CNAME records (must be written DNS-only / proxied = false on Cloudflare)."
  value = [
    {
      name  = google_certificate_manager_dns_authorization.app.dns_resource_record[0].name
      value = google_certificate_manager_dns_authorization.app.dns_resource_record[0].data
    }
  ]
}
`
    : `
output "acme_validation_records" {
  description = "Certificate Manager DNS-01 CNAME records (empty when Global External ALB is not enabled)."
  value       = []
}
`;

  return `output "wif_provider" {
  value = google_iam_workload_identity_pool_provider.github.name
}

output "deploy_service_account" {
  value = google_service_account.deploy.email
}

output "artifact_registry_repository" {
  value = "\${var.region}-docker.pkg.dev/\${var.project_id}/\${google_artifact_registry_repository.app.repository_id}"
}

output "app_endpoint" {
  value = local.app_endpoint
}
${acmeOutput}`;
}

export function renderGcpHcl(ctx: RenderGcpHclContext): readonly ManagedCloudRenderedFile[] {
  const files: ManagedCloudRenderedFile[] = [
    { path: "versions.tf", content: renderVersionsTf(), kind: "iac" },
    { path: "variables.tf", content: renderVariablesTf(ctx), kind: "iac" },
    { path: "network.tf", content: renderNetworkTf(ctx), kind: "iac" },
    { path: "iam.tf", content: renderIamTf(ctx), kind: "iac" },
    { path: "compute.tf", content: renderComputeTf(ctx), kind: "iac" },
    { path: "secrets.tf", content: renderSecretsTf(ctx), kind: "iac" },
  ];

  const db = renderDatabaseTf(ctx);
  if (db !== undefined) files.push({ path: "database.tf", content: db, kind: "iac" });

  const cache = renderCacheTf(ctx);
  if (cache !== undefined) files.push({ path: "cache.tf", content: cache, kind: "iac" });

  const storage = renderStorageTf(ctx);
  if (storage !== undefined) files.push({ path: "storage.tf", content: storage, kind: "iac" });

  const edge = renderEdgeTf(ctx);
  if (edge !== undefined) files.push({ path: "edge.tf", content: edge, kind: "iac" });

  files.push({ path: "outputs.tf", content: renderOutputsTf(ctx), kind: "iac" });
  return files;
}
