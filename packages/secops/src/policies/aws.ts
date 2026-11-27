/**
 * Deterministic AWS static policy checks on OpenTofu/Terraform plan JSON (Feature 034, T3406,
 * ADR 0040 D11). Because `floci` does not enforce runtime IAM authorization, these checks
 * deterministically enforce least privilege, strict GitHub OIDC trust policies, private databases,
 * per-bucket S3 Block Public Access + encryption at rest, secrets-out-of-state, CloudWatch log
 * retention (blocking), open-port security group rules, and no ACM Private CA before any apply.
 *
 * Fail-closed rule (Blocker #4): when `policy` or `assume_role_policy` is marked unknown in
 * `after_unknown` (`r.unknown`), we never silently pass — we inspect `configuration` references if
 * present or fail closed so an unknown policy cannot smuggle wildcards past the gate.
 */
import type { PlannedResourceJson, PolicyResult, Severity } from "@opscrew/contracts";
import { isRecord } from "@opscrew/core";
import type { DeployPlan } from "@opscrew/plan-schema";
import { plannedResources } from "./plan";

const DANGEROUS_MANAGED_POLICIES = [
  "AdministratorAccess",
  "PowerUserAccess",
  "IAMFullAccess",
  "FullAccess",
];

const SENSITIVE_DB_AND_SSH_PORTS = new Set([22, 3306, 5432, 6379, 27017]);
const OPEN_CIDRS = new Set(["0.0.0.0/0", "::/0"]);

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

/** Extracts `configuration.root_module.resources` map keyed by `address` when present in plan JSON. */
function configResourceExpressions(
  planJson: unknown,
): ReadonlyMap<string, Record<string, unknown>> {
  const map = new Map<string, Record<string, unknown>>();
  if (!isRecord(planJson) || !isRecord(planJson.configuration)) return map;
  const root = planJson.configuration.root_module;
  const walk = (mod: unknown, prefix: string) => {
    if (!isRecord(mod)) return;
    if (Array.isArray(mod.resources)) {
      for (const res of mod.resources) {
        if (!isRecord(res) || typeof res.address !== "string") continue;
        const addr = prefix === "" ? res.address : `${prefix}.${res.address}`;
        if (isRecord(res.expressions)) map.set(addr, res.expressions);
      }
    }
    if (isRecord(mod.module_calls)) {
      for (const [name, call] of Object.entries(mod.module_calls)) {
        if (isRecord(call) && isRecord(call.module)) {
          walk(call.module, prefix === "" ? `module.${name}` : `${prefix}.module.${name}`);
        }
      }
    }
  };
  walk(root, "");
  return map;
}

function checkPolicyStatementsForWildcards(doc: Record<string, unknown>): string | undefined {
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
      return `Statement "${String(stmt.Sid ?? "unnamed")}" allows broad wildcard Action/Resource (${actions.join(", ")} on ${res.join(", ")}).`;
    }
  }
  return undefined;
}

/** Checks IAM inline policies, standalone policies, inline_policy blocks, and managed policy attachments. */
function checkIamLeastPrivilege(resources: readonly PlannedResourceJson[]): PolicyResult[] {
  const out: PolicyResult[] = [];
  for (const r of resources) {
    if (r.type === "aws_iam_role_policy" || r.type === "aws_iam_policy") {
      const isUnknown = r.unknown?.policy === true;
      const doc = parseJsonDoc(r.values.policy);
      if (isUnknown || doc === undefined) {
        out.push(
          policy(
            "aws-iam-least-privilege",
            "AWS IAM deploy/task policy follows least privilege",
            "high",
            false,
            `${r.address} has an unknown or unparseable IAM policy at plan time (fail-closed: cannot verify zero wildcards before apply).`,
            r.address,
          ),
        );
        continue;
      }
      const wildcardViolation = checkPolicyStatementsForWildcards(doc);
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

    if (r.type === "aws_iam_role" && Array.isArray(r.values.inline_policy)) {
      for (const inline of r.values.inline_policy) {
        if (!isRecord(inline)) continue;
        const doc = parseJsonDoc(inline.policy);
        if (doc === undefined) {
          out.push(
            policy(
              "aws-iam-least-privilege",
              "AWS IAM inline role policy follows least privilege",
              "high",
              false,
              `${r.address} has an unknown or unparseable inline_policy "${String(inline.name ?? "unnamed")}".`,
              r.address,
            ),
          );
          continue;
        }
        const violation = checkPolicyStatementsForWildcards(doc);
        out.push(
          policy(
            "aws-iam-least-privilege",
            "AWS IAM inline role policy follows least privilege",
            "high",
            violation === undefined,
            violation ??
              `${r.address} inline_policy scopes actions and resources without wildcards.`,
            r.address,
          ),
        );
      }
    }

    if (r.type === "aws_iam_role_policy_attachment") {
      const arn = typeof r.values.policy_arn === "string" ? r.values.policy_arn : "";
      const isUnknown = r.unknown?.policy_arn === true;
      const dangerous = DANGEROUS_MANAGED_POLICIES.find(
        (suffix) => arn.endsWith(`/${suffix}`) || arn.includes(suffix),
      );
      if (isUnknown || dangerous !== undefined) {
        out.push(
          policy(
            "aws-iam-least-privilege",
            "AWS IAM role does not attach overly broad managed policies",
            "critical",
            false,
            isUnknown
              ? `${r.address} attaches an unknown policy_arn at plan time (fail-closed).`
              : `${r.address} attaches broad managed policy "${arn}" (${dangerous}); replace with a least-privilege custom policy.`,
            r.address,
          ),
        );
      }
    }
  }
  return out;
}

/** Checks GitHub Actions OIDC assume-role trust policies for strict `StringEquals` and zero wildcards. */
function checkOidcTrust(resources: readonly PlannedResourceJson[]): PolicyResult[] {
  const out: PolicyResult[] = [];
  for (const r of resources) {
    if (r.type !== "aws_iam_role") continue;
    const isUnknown = r.unknown?.assume_role_policy === true;
    const doc = parseJsonDoc(r.values.assume_role_policy);
    if (isUnknown || (r.values.assume_role_policy !== undefined && doc === undefined)) {
      out.push(
        policy(
          "aws-oidc-strict-sub",
          "GitHub Actions OIDC role pins aud and exact sub without wildcards",
          "critical",
          false,
          `${r.address} has an unknown or unparseable assume_role_policy at plan time (fail-closed: cannot verify OIDC StringEquals/sub before apply).`,
          r.address,
        ),
      );
      continue;
    }
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

/** Checks RDS/Aurora instances and cluster instances for private placement and encryption at rest. */
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
    if (
      r.type !== "aws_db_instance" &&
      r.type !== "aws_rds_cluster" &&
      r.type !== "aws_rds_cluster_instance"
    ) {
      continue;
    }
    if (r.type === "aws_db_instance" || r.type === "aws_rds_cluster_instance") {
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
    if (r.type === "aws_db_instance" || r.type === "aws_rds_cluster") {
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
  }
  return out;
}

/** Checks whether a companion S3 resource (BPA or SSE) targets `bucket`. */
function targetsBucket(
  companion: PlannedResourceJson,
  bucket: PlannedResourceJson,
  configExprs: ReadonlyMap<string, Record<string, unknown>>,
): boolean {
  // 1. Direct bucket name/id match when known in planned values.
  const bucketVal = typeof bucket.values.bucket === "string" ? bucket.values.bucket : undefined;
  const bucketId = typeof bucket.values.id === "string" ? bucket.values.id : undefined;
  const refBucket =
    typeof companion.values.bucket === "string" ? companion.values.bucket : undefined;
  if (refBucket !== undefined && (refBucket === bucketVal || refBucket === bucketId)) {
    return true;
  }
  // 2. Terraform configuration reference match (`bucket = aws_s3_bucket.<name>.id`).
  const expr = configExprs.get(companion.address);
  const bucketExpr = expr !== undefined && isRecord(expr.bucket) ? expr.bucket : undefined;
  const refs = Array.isArray(bucketExpr?.references) ? bucketExpr.references : [];
  if (
    refs.some(
      (ref) =>
        typeof ref === "string" && (ref === bucket.address || ref.startsWith(`${bucket.address}.`)),
    )
  ) {
    return true;
  }
  // 3. Matching resource label fallback (`aws_s3_bucket.<name>` <-> `aws_s3_bucket_* .<name>`).
  const bucketName = bucket.address.split(".").pop();
  const compName = companion.address.split(".").pop();
  return (
    bucketName !== undefined &&
    compName !== undefined &&
    bucketName === compName &&
    refBucket === undefined
  );
}

/** Checks per-bucket S3 BPA + encryption, secrets-out-of-state, CloudWatch retention (high), and no Private CA. */
function checkStorageAndSecrets(
  resources: readonly PlannedResourceJson[],
  configExprs: ReadonlyMap<string, Record<string, unknown>>,
  deployPlan: DeployPlan,
): PolicyResult[] {
  const out: PolicyResult[] = [];
  const buckets = resources.filter((r) => r.type === "aws_s3_bucket");
  const blocks = resources.filter((r) => r.type === "aws_s3_bucket_public_access_block");
  const encryptions = resources.filter(
    (r) => r.type === "aws_s3_bucket_server_side_encryption_configuration",
  );
  const allowUnencrypted =
    deployPlan.target.provider === "aws" && deployPlan.target.guardrails.encryptionAtRest === false;

  for (const bucket of buckets) {
    const matchingBpa = blocks.find(
      (b) =>
        targetsBucket(b, bucket, configExprs) &&
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
        matchingBpa !== undefined,
        matchingBpa !== undefined
          ? `${bucket.address} is protected by ${matchingBpa.address} with all four Block Public Access flags enabled.`
          : `${bucket.address} lacks a matching aws_s3_bucket_public_access_block enabling all four public-access blocks.`,
        bucket.address,
      ),
    );

    const matchingSse = encryptions.find((e) => targetsBucket(e, bucket, configExprs));
    out.push(
      policy(
        "aws-storage-encrypted-private",
        "S3 bucket enables server-side encryption at rest",
        "high",
        matchingSse !== undefined || allowUnencrypted,
        matchingSse !== undefined
          ? `${bucket.address} enables server-side encryption via ${matchingSse.address}.`
          : allowUnencrypted
            ? `${bucket.address} disables S3 encryption under a recorded guardrail exception.`
            : `${bucket.address} lacks a matching aws_s3_bucket_server_side_encryption_configuration.`,
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
          "high",
          days > 0,
          days > 0
            ? `${r.address} sets retention_in_days = ${days}.`
            : `${r.address} omits retention_in_days (Never Expire accumulates unbounded log storage costs; ADR 0040 D6 requires explicit retention).`,
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

/** Checks AWS security groups for publicly exposed DB/cache/SSH ports (`0.0.0.0/0` or `::/0`). */
function checkSecurityGroups(resources: readonly PlannedResourceJson[]): PolicyResult[] {
  const out: PolicyResult[] = [];
  const portHitsSensitive = (fromPort: number, toPort: number): number | undefined => {
    for (const p of SENSITIVE_DB_AND_SSH_PORTS) {
      if (fromPort <= p && p <= toPort) return p;
    }
    return undefined;
  };

  for (const r of resources) {
    if (r.type === "aws_security_group" && Array.isArray(r.values.ingress)) {
      for (const rule of r.values.ingress) {
        if (!isRecord(rule)) continue;
        const cidrs = [...stringList(rule.cidr_blocks), ...stringList(rule.ipv6_cidr_blocks)];
        if (!cidrs.some((c) => OPEN_CIDRS.has(c))) continue;
        const fromPort = typeof rule.from_port === "number" ? rule.from_port : 0;
        const toPort = typeof rule.to_port === "number" ? rule.to_port : 65535;
        const exposed = rule.protocol === "-1" ? 5432 : portHitsSensitive(fromPort, toPort);
        if (exposed !== undefined) {
          out.push(
            policy(
              "aws-sg-no-open-sensitive-ports",
              "AWS security group does not expose database/cache/SSH ports to the internet",
              "critical",
              false,
              `${r.address} exposes port ${exposed} (range ${fromPort}-${toPort}) to ${cidrs.filter((c) => OPEN_CIDRS.has(c)).join(", ")}.`,
              r.address,
            ),
          );
        }
      }
    }
    if (
      (r.type === "aws_security_group_rule" && r.values.type === "ingress") ||
      r.type === "aws_vpc_security_group_ingress_rule"
    ) {
      const cidrs = [
        ...stringList(r.values.cidr_blocks),
        ...stringList(r.values.ipv6_cidr_blocks),
        ...(typeof r.values.cidr_ipv4 === "string" ? [r.values.cidr_ipv4] : []),
        ...(typeof r.values.cidr_ipv6 === "string" ? [r.values.cidr_ipv6] : []),
      ];
      if (!cidrs.some((c) => OPEN_CIDRS.has(c))) continue;
      const fromPort = typeof r.values.from_port === "number" ? r.values.from_port : 0;
      const toPort = typeof r.values.to_port === "number" ? r.values.to_port : 65535;
      const proto = r.values.protocol ?? r.values.ip_protocol;
      const exposed = proto === "-1" ? 5432 : portHitsSensitive(fromPort, toPort);
      if (exposed !== undefined) {
        out.push(
          policy(
            "aws-sg-no-open-sensitive-ports",
            "AWS security group rule does not expose database/cache/SSH ports to the internet",
            "critical",
            false,
            `${r.address} exposes port ${exposed} (range ${fromPort}-${toPort}) to ${cidrs.filter((c) => OPEN_CIDRS.has(c)).join(", ")}.`,
            r.address,
          ),
        );
      }
    }
  }
  return out;
}

/** Evaluates all deterministic AWS SecOps policies against Terraform/OpenTofu plan JSON. */
export function evaluateAwsPlanPolicies(planJson: unknown, deployPlan: DeployPlan): PolicyResult[] {
  const resources = plannedResources(planJson);
  const configExprs = configResourceExpressions(planJson);
  return [
    ...checkIamLeastPrivilege(resources),
    ...checkOidcTrust(resources),
    ...checkDatabases(resources, deployPlan),
    ...checkStorageAndSecrets(resources, configExprs, deployPlan),
    ...checkSecurityGroups(resources),
  ];
}
