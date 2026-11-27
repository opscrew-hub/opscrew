import type { DeployPlan } from "@opscrew/plan-schema";
import { describe, expect, it } from "vitest";
import { evaluateAwsPlanPolicies } from "./aws";

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
  resources: Array<{ address: string; type: string; values: Record<string, unknown> }>,
) {
  return {
    planned_values: {
      root_module: {
        resources: resources.map((r) => ({ ...r, name: r.address, mode: "managed" })),
      },
    },
    resource_changes: [],
  };
}

describe("034 AWS SecOps static policies (T3406)", () => {
  it("passes a clean least-privilege AWS plan with strict OIDC, private RDS, S3 BPA, and log retention", () => {
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
          block_public_acls: true,
          block_public_policy: true,
          ignore_public_acls: true,
          restrict_public_buckets: true,
        },
      },
      {
        address: "aws_cloudwatch_log_group.app",
        type: "aws_cloudwatch_log_group",
        values: { retention_in_days: 30 },
      },
    ]);

    const results = evaluateAwsPlanPolicies(planJson, awsPlan());
    expect(results.length).toBeGreaterThanOrEqual(6);
    expect(results.every((r) => r.passed)).toBe(true);
  });

  it("blocks wildcard IAM/OIDC, public RDS without exception, missing S3 BPA, secrets in state, unbounded logs, and Private CA", () => {
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
        address: "aws_db_instance.public",
        type: "aws_db_instance",
        values: { publicly_accessible: true, storage_encrypted: false },
      },
      {
        address: "aws_s3_bucket.exposed",
        type: "aws_s3_bucket",
        values: { bucket: "exposed" },
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
    const failedIds = results.filter((r) => !r.passed).map((r) => r.policyId);
    expect(failedIds).toEqual(
      expect.arrayContaining([
        "aws-oidc-strict-sub",
        "aws-iam-least-privilege",
        "aws-rds-private",
        "aws-storage-encrypted-private",
        "aws-no-secret-in-state",
        "aws-cloudwatch-retention",
        "aws-no-private-ca",
      ]),
    );
  });
});
