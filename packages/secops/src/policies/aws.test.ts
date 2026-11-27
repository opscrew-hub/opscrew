import type { DeployPlan } from "@opscrew/plan-schema";
import { describe, expect, it } from "vitest";
import { evaluateAwsPlanPolicies } from "./aws";
import { blockingPolicyFailures } from "./plan";

function awsPlan(overrides: { privateDatabase?: boolean } = {}): DeployPlan {
  return {
    target: {
      provider: "aws",
      mode: "aws-managed",
      region: "us-east-1",
      preset: "balanced",
      compute: "ecs-fargate",
      components: {},
      pins: {},
      guardrails: {
        privateDatabase: overrides.privateDatabase ?? true,
        encryptionAtRest: true,
        automatedBackups: true,
        s3BlockPublicAccess: true,
        leastPrivilegeIam: true,
        logRetention: true,
        noPrivateCa: true,
      },
      exceptions: [],
      observability: {
        logsRetentionDays: 30,
        containerInsights: false,
        alarms: true,
        managedGrafana: false,
        openSearch: false,
        tracing: "none",
        otelCollector: false,
      },
    },
  } as unknown as DeployPlan;
}

function makePlanJson(
  resources: Array<{
    address: string;
    type: string;
    values: Record<string, unknown>;
    afterUnknown?: Record<string, unknown>;
  }>,
) {
  return {
    planned_values: {
      root_module: {
        resources: resources.map((r) => ({
          address: r.address,
          type: r.type,
          name: r.address,
          mode: "managed",
          values: r.values,
        })),
      },
    },
    resource_changes: resources
      .filter((r) => r.afterUnknown !== undefined)
      .map((r) => ({
        address: r.address,
        type: r.type,
        change: { actions: ["create"], after_unknown: r.afterUnknown },
      })),
  };
}

describe("034 AWS SecOps static policies (T3406)", () => {
  it("passes a clean least-privilege AWS plan with strict OIDC, private RDS, per-bucket S3 BPA + SSE, and log retention", () => {
    const planJson = makePlanJson([
      {
        address: "aws_iam_role.github_deploy",
        type: "aws_iam_role",
        values: {
          assume_role_policy: JSON.stringify({
            Version: "2012-10-17",
            Statement: [
              {
                Effect: "Allow",
                Action: "sts:AssumeRoleWithWebIdentity",
                Condition: {
                  StringEquals: {
                    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                    "token.actions.githubusercontent.com:sub": "repo:acme/shop:environment:prod",
                  },
                },
              },
            ],
          }),
        },
      },
      {
        address: "aws_iam_role_policy.deploy",
        type: "aws_iam_role_policy",
        values: {
          policy: JSON.stringify({
            Version: "2012-10-17",
            Statement: [
              {
                Sid: "EcrAuth",
                Effect: "Allow",
                Action: ["ecr:GetAuthorizationToken"],
                Resource: "*",
              },
              {
                Sid: "Push",
                Effect: "Allow",
                Action: ["ecr:PutImage"],
                Resource: "arn:aws:ecr:us-east-1:123:repository/app",
              },
            ],
          }),
        },
      },
      {
        address: "aws_db_instance.app",
        type: "aws_db_instance",
        values: { publicly_accessible: false, storage_encrypted: true },
      },
      {
        address: "aws_s3_bucket.uploads",
        type: "aws_s3_bucket",
        values: { bucket: "opscrew-shop-uploads" },
      },
      {
        address: "aws_s3_bucket_public_access_block.uploads",
        type: "aws_s3_bucket_public_access_block",
        values: {
          bucket: "opscrew-shop-uploads",
          block_public_acls: true,
          block_public_policy: true,
          ignore_public_acls: true,
          restrict_public_buckets: true,
        },
      },
      {
        address: "aws_s3_bucket_server_side_encryption_configuration.uploads",
        type: "aws_s3_bucket_server_side_encryption_configuration",
        values: { bucket: "opscrew-shop-uploads" },
      },
      {
        address: "aws_cloudwatch_log_group.app",
        type: "aws_cloudwatch_log_group",
        values: { retention_in_days: 30 },
      },
    ]);

    const results = evaluateAwsPlanPolicies(planJson, awsPlan());
    expect(results.length).toBeGreaterThanOrEqual(7);
    expect(results.every((r) => r.passed)).toBe(true);
  });

  it("blocks wildcard IAM/OIDC, AdministratorAccess attachments, public RDS/Aurora, per-bucket missing S3 BPA/SSE, open DB SG ports, secrets in state, unbounded logs (blocking), and Private CA", () => {
    const planJson = makePlanJson([
      {
        address: "aws_iam_role.bad_oidc",
        type: "aws_iam_role",
        values: {
          assume_role_policy: JSON.stringify({
            Statement: [
              {
                Effect: "Allow",
                Action: "sts:AssumeRoleWithWebIdentity",
                Condition: {
                  StringLike: {
                    "token.actions.githubusercontent.com:sub": "repo:acme/*",
                  },
                },
              },
            ],
          }),
        },
      },
      {
        address: "aws_iam_role_policy.admin",
        type: "aws_iam_role_policy",
        values: {
          policy: JSON.stringify({
            Statement: [{ Sid: "TooWide", Effect: "Allow", Action: "*", Resource: "*" }],
          }),
        },
      },
      {
        address: "aws_iam_role_policy_attachment.admin_attach",
        type: "aws_iam_role_policy_attachment",
        values: { policy_arn: "arn:aws:iam::aws:policy/AdministratorAccess" },
      },
      {
        address: "aws_db_instance.public",
        type: "aws_db_instance",
        values: { publicly_accessible: true, storage_encrypted: false },
      },
      {
        address: "aws_rds_cluster_instance.public_aurora",
        type: "aws_rds_cluster_instance",
        values: { publicly_accessible: true },
      },
      {
        address: "aws_s3_bucket.safe",
        type: "aws_s3_bucket",
        values: { bucket: "safe-bucket" },
      },
      {
        address: "aws_s3_bucket_public_access_block.safe",
        type: "aws_s3_bucket_public_access_block",
        values: {
          bucket: "safe-bucket",
          block_public_acls: true,
          block_public_policy: true,
          ignore_public_acls: true,
          restrict_public_buckets: true,
        },
      },
      {
        address: "aws_s3_bucket.exposed",
        type: "aws_s3_bucket",
        values: { bucket: "exposed-bucket" },
      },
      {
        address: "aws_security_group.db_open",
        type: "aws_security_group",
        values: {
          ingress: [
            { from_port: 5432, to_port: 5432, protocol: "tcp", cidr_blocks: ["0.0.0.0/0"] },
          ],
        },
      },
      {
        address: "aws_secretsmanager_secret_version.leaked",
        type: "aws_secretsmanager_secret_version",
        values: { secret_id: "x" },
      },
      {
        address: "aws_cloudwatch_log_group.unbounded",
        type: "aws_cloudwatch_log_group",
        values: {},
      },
      {
        address: "aws_acmpca_certificate_authority.expensive",
        type: "aws_acmpca_certificate_authority",
        values: {},
      },
    ]);

    const results = evaluateAwsPlanPolicies(planJson, awsPlan());
    const blockingIds = blockingPolicyFailures(results).map((r) => r.policyId);
    expect(blockingIds).toEqual(
      expect.arrayContaining([
        "aws-oidc-strict-sub",
        "aws-iam-least-privilege",
        "aws-rds-private",
        "aws-storage-encrypted-private",
        "aws-sg-no-open-sensitive-ports",
        "aws-no-secret-in-state",
        "aws-cloudwatch-retention",
        "aws-no-private-ca",
      ]),
    );
    // Bucket `exposed` must fail BPA even though `safe` has BPA enabled!
    expect(
      results.some(
        (r) =>
          !r.passed &&
          r.resource === "aws_s3_bucket.exposed" &&
          r.policyId === "aws-storage-encrypted-private",
      ),
    ).toBe(true);
  });

  it("fails closed when IAM policy or OIDC assume_role_policy is in after_unknown (Blocker #4)", () => {
    const planJson = makePlanJson([
      {
        address: "aws_iam_role.unknown_oidc",
        type: "aws_iam_role",
        values: {},
        afterUnknown: { assume_role_policy: true },
      },
      {
        address: "aws_iam_role_policy.unknown_policy",
        type: "aws_iam_role_policy",
        values: {},
        afterUnknown: { policy: true },
      },
    ]);

    const results = evaluateAwsPlanPolicies(planJson, awsPlan());
    const blocking = blockingPolicyFailures(results);
    expect(blocking.map((b) => b.policyId)).toEqual(
      expect.arrayContaining(["aws-oidc-strict-sub", "aws-iam-least-privilege"]),
    );
  });
});
