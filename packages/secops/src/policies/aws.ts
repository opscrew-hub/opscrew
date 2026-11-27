/**
 * Deterministic AWS static policy checks on OpenTofu/Terraform plan JSON (Feature 034, T3406,
 * ADR 0040 D11). Because `floci` does not enforce runtime IAM authorization, these checks
 * deterministically enforce least privilege, strict GitHub OIDC trust policies, private databases,
 * S3 Block Public Access + encryption at rest, secrets-out-of-state, CloudWatch log retention, and
 * no ACM Private CA before any apply.
 */
import type { PlannedResourceJson, PolicyResult, Severity } from "@opscrew/contracts";
import { isRecord } from "@opscrew/core";
import type { DeployPlan } from "@opscrew/plan-schema";
import { plannedResources } from "./plan";

function policy(
  policyId: string,
  title: string,
  severity: Severity,
  passed: boolean,
  message: string,
  resource?: string,
): PolicyResult {
  return { policyId, title, severity, passed, message, ...(resource ? { resource } : {}) };
}

function parseJsonDoc(raw: unknown): Record<string, unknown> | undefined {
  if (typeof raw !== "string") return undefined;
  try {
    const parsed: unknown = JSON.parse(raw);
    return isRecord(parsed) ? parsed : undefined;
  } catch {
    return undefined;
  }
}

function statementsOf(doc: Record<string, unknown> | undefined): Record<string, unknown>[] {
  if (doc === undefined) return [];
  const raw = doc.Statement;
  if (Array.isArray(raw)) return raw.filter(isRecord);
  if (isRecord(raw)) return [raw];
  return [];
}

function stringList(value: unknown): string[] {
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.filter((v): v is string => typeof v === "string");
  return [];
}

/** Checks IAM inline policies for wildcard `*` actions or unconstrained `*` resource combos. */
function checkIamLeastPrivilege(resources: readonly PlannedResourceJson[]): PolicyResult[] {
  const out: PolicyResult[] = [];
  for (const r of resources) {
    if (r.type !== "aws_iam_role_policy" && r.type !== "aws_iam_policy") continue;
    const doc = parseJsonDoc(r.values.policy);
    let wildcardViolation: string | undefined;
    for (const stmt of statementsOf(doc)) {
      if (stmt.Effect !== "Allow") continue;
      const actions = stringList(stmt.Action);
      const res = stringList(stmt.Resource);
      const hasStarAction = actions.some((a) => a === "*" || a.endsWith(":*"));
      const hasStarResource = res.includes("*");
      // `ecr:GetAuthorizationToken` requires Resource: "*" per AWS IAM design.
      const onlyEcrAuth =
        actions.length === 1 && actions[0] === "ecr:GetAuthorizationToken" && hasStarResource;
      if (hasStarAction || (hasStarResource && !onlyEcrAuth)) {
        wildcardViolation = `Statement "${String(stmt.Sid ?? "unnamed")}" allows broad wildcard Action/Resource (${actions.join(", ")} on ${res.join(", ")}).`;
        break;
      }
    }
    out.push(
      policy(
        "aws-iam-least-privilege",
        "AWS IAM deploy/task policy follows least privilege",
        "high",
        wildcardViolation === undefined,
        wildcardViolation ?? `${r.address} scopes actions and resources without wildcards.`,
        r.address,
      ),
    );
  }
  return out;
}

/** Checks GitHub Actions OIDC assume-role trust policies for strict `StringEquals` and zero wildcards. */
function checkOidcTrust(resources: readonly PlannedResourceJson[]): PolicyResult[] {
  const out: PolicyResult[] = [];
  for (const r of resources) {
    if (r.type !== "aws_iam_role") continue;
    const doc = parseJsonDoc(r.values.assume_role_policy);
    const oidcStmts = statementsOf(doc).filter((s) => s.Action === "sts:AssumeRoleWithWebIdentity");
    if (oidcStmts.length === 0) continue;

    let violation: string | undefined;
    for (const stmt of oidcStmts) {
      const cond = isRecord(stmt.Condition) ? stmt.Condition : undefined;
      if (cond !== undefined && "StringLike" in cond) {
        violation = "OIDC trust policy uses StringLike instead of strict StringEquals.";
        break;
      }
      const eq = cond !== undefined && isRecord(cond.StringEquals) ? cond.StringEquals : undefined;
      const aud = eq?.["token.actions.githubusercontent.com:aud"];
      const sub = eq?.["token.actions.githubusercontent.com:sub"];
      if (aud !== "sts.amazonaws.com") {
        violation =
          'OIDC trust policy must constrain token.actions.githubusercontent.com:aud to "sts.amazonaws.com".';
        break;
      }
      if (typeof sub !== "string" || !sub.startsWith("repo:") || sub.includes("*")) {
        violation = `OIDC trust policy must pin token.actions.githubusercontent.com:sub to one repo/environment without wildcards (got ${String(sub)}).`;
        break;
      }
    }
    out.push(
      policy(
        "aws-oidc-strict-sub",
        "GitHub Actions OIDC role pins aud and exact sub without wildcards",
        "critical",
        violation === undefined,
        violation ??
          `${r.address} pins aud=sts.amazonaws.com and an exact wildcard-free sub claim.`,
        r.address,
      ),
    );
  }
  return out;
}

/** Checks RDS/Aurora instances for private subnet placement and encryption at rest. */
function checkDatabases(
  resources: readonly PlannedResourceJson[],
  deployPlan: DeployPlan,
): PolicyResult[] {
  const out: PolicyResult[] = [];
  const allowPublic =
    deployPlan.target.provider === "aws" && deployPlan.target.guardrails.privateDatabase === false;
  const allowUnencrypted =
    deployPlan.target.provider === "aws" && deployPlan.target.guardrails.encryptionAtRest === false;

  for (const r of resources) {
    if (r.type !== "aws_db_instance" && r.type !== "aws_rds_cluster") continue;
    if (r.type === "aws_db_instance") {
      const isPublic = r.values.publicly_accessible === true;
      out.push(
        policy(
          "aws-rds-private",
          "RDS instance is not publicly accessible",
          "critical",
          !isPublic || allowPublic,
          !isPublic
            ? `${r.address} sets publicly_accessible = false.`
            : allowPublic
              ? `${r.address} is publicly accessible under a recorded guardrail exception.`
              : `${r.address} sets publicly_accessible = true without a recorded guardrail exception.`,
          r.address,
        ),
      );
    }
    const encrypted = r.values.storage_encrypted === true;
    out.push(
      policy(
        "aws-storage-encrypted-private",
        "Database storage is encrypted at rest",
        "high",
        encrypted || allowUnencrypted,
        encrypted
          ? `${r.address} enables storage_encrypted = true.`
          : allowUnencrypted
            ? `${r.address} disables storage encryption under a recorded guardrail exception.`
            : `${r.address} does not enable storage_encrypted = true.`,
        r.address,
      ),
    );
  }
  return out;
}

/** Checks S3 buckets have matching Block Public Access and rejects plaintext secrets in state. */
function checkStorageAndSecrets(resources: readonly PlannedResourceJson[]): PolicyResult[] {
  const out: PolicyResult[] = [];
  const buckets = resources.filter((r) => r.type === "aws_s3_bucket");
  const blocks = resources.filter((r) => r.type === "aws_s3_bucket_public_access_block");

  for (const bucket of buckets) {
    const matching = blocks.find(
      (b) =>
        b.values.block_public_acls === true &&
        b.values.block_public_policy === true &&
        b.values.ignore_public_acls === true &&
        b.values.restrict_public_buckets === true,
    );
    out.push(
      policy(
        "aws-storage-encrypted-private",
        "S3 bucket enables all four Block Public Access controls",
        "critical",
        matching !== undefined,
        matching !== undefined
          ? `${bucket.address} is protected by ${matching.address} with all four Block Public Access flags enabled.`
          : `${bucket.address} lacks an aws_s3_bucket_public_access_block enabling all four public-access blocks.`,
        bucket.address,
      ),
    );
  }

  for (const r of resources) {
    if (r.type === "aws_secretsmanager_secret_version") {
      out.push(
        policy(
          "aws-no-secret-in-state",
          "No plaintext secret values stored in Terraform state",
          "critical",
          false,
          `${r.address} writes a Secrets Manager value via Terraform, which persists plaintext in .tfstate; populate secret values out-of-band via OpsCrew's AWS connector.`,
          r.address,
        ),
      );
    }
    if (
      r.type === "aws_ssm_parameter" &&
      r.values.type === "SecureString" &&
      typeof r.values.value === "string" &&
      r.values.value.length > 0
    ) {
      out.push(
        policy(
          "aws-no-secret-in-state",
          "No plaintext SecureString values stored in Terraform state",
          "critical",
          false,
          `${r.address} embeds a SecureString value in Terraform, which persists plaintext in .tfstate; write values out-of-band via OpsCrew's AWS connector.`,
          r.address,
        ),
      );
    }
    if (r.type === "aws_cloudwatch_log_group") {
      const days = typeof r.values.retention_in_days === "number" ? r.values.retention_in_days : 0;
      out.push(
        policy(
          "aws-cloudwatch-retention",
          "CloudWatch Log Group sets explicit retention_in_days",
          "medium",
          days > 0,
          days > 0
            ? `${r.address} sets retention_in_days = ${days}.`
            : `${r.address} omits retention_in_days (Never Expire accumulates unbounded log storage costs).`,
          r.address,
        ),
      );
    }
    if (r.type === "aws_acmpca_certificate_authority") {
      out.push(
        policy(
          "aws-no-private-ca",
          "No unintended ACM Private CA ($400/mo)",
          "high",
          false,
          `${r.address} provisions an ACM Private CA (~$400/mo); use free public ACM certificates instead.`,
          r.address,
        ),
      );
    }
  }
  return out;
}

/** Evaluates all deterministic AWS SecOps policies against Terraform/OpenTofu plan JSON. */
export function evaluateAwsPlanPolicies(planJson: unknown, deployPlan: DeployPlan): PolicyResult[] {
  const resources = plannedResources(planJson);
  return [
    ...checkIamLeastPrivilege(resources),
    ...checkOidcTrust(resources),
    ...checkDatabases(resources, deployPlan),
    ...checkStorageAndSecrets(resources),
  ];
}
