// biome-ignore-all lint/suspicious/noTemplateCurlyInString: GitHub Actions expressions, not JS templates.
import { MANAGED_CLOUD_CONTRACT_VERSION } from "@opscrew/contracts";
import { describe, expect, it } from "vitest";
import {
  AWS_MANAGED_PROVIDER,
  applyAwsOverrides,
  designAwsTarget,
  githubOidcSubject,
  renderAwsDeployWorkflow,
  renderAwsHcl,
} from "./index";

describe("034 @opscrew/provider-aws design, pricing, and overrides (T3404)", () => {
  it("exports a contractVersion 1 ManagedCloudProviderDefinition", () => {
    expect(AWS_MANAGED_PROVIDER.contractVersion).toBe(MANAGED_CLOUD_CONTRACT_VERSION);
    expect(AWS_MANAGED_PROVIDER.id).toBe("aws");
    expect(AWS_MANAGED_PROVIDER.presets).toEqual(["lean", "balanced", "production-ha"]);
  });

  it("picks Lambda Web Functions (Oct 2026) for lean low-traffic Node.js HTTP apps with no NAT trap", () => {
    const out = designAwsTarget({
      facts: {
        appKind: "api",
        languages: ["typescript"],
        services: [{ kind: "postgres", evidence: ["pg"] }],
        cronJobs: [],
      },
      requirements: {
        region: "us-east",
        expectedMonthlyUsers: "<1k",
        uptime: "best-effort",
        dataCriticality: "none",
        budgetMonthly: { amount: 20, currency: "USD" },
      },
      preset: "lean",
    });

    expect(out.target.compute).toBe("lambda-web");
    expect(out.target.components.network?.config.natGateway).toBe(false);
    expect(out.target.components.database?.service).toBe("rds-postgres");
    expect(out.target.components.secrets?.service).toBe("ssm-parameter-store-standard");
    expect(out.target.components.edge?.service).toBe("cloudflare-dns-acm");
    expect(out.totalMonthlyUsd).toBeLessThan(20);
  });

  it("picks ECS Fargate + Aurora Serverless v2 + Valkey noeviction + NAT for production-ha with workers", () => {
    const out = designAwsTarget({
      facts: {
        appKind: "fullstack",
        languages: ["typescript"],
        services: [
          { kind: "postgres", evidence: ["pg"] },
          { kind: "redis", evidence: ["bullmq"] },
          { kind: "s3", evidence: ["@aws-sdk/client-s3"] },
        ],
        workers: [{ name: "jobs" }],
        cronJobs: [
          {
            schedule: "0 * * * *",
            route: "/api/cron/cleanup",
            source: "vercel.json",
          },
        ],
      },
      requirements: {
        region: "eu-central",
        expectedMonthlyUsers: "10k-100k",
        uptime: "high",
        dataCriticality: "critical",
        budgetMonthly: { amount: 300, currency: "USD" },
      },
      preset: "production-ha",
    });

    expect(out.target.region).toBe("eu-central-1");
    expect(out.target.compute).toBe("ecs-fargate");
    expect(out.target.components.database?.service).toBe("aurora-postgres-serverless-v2");
    expect(out.target.components.cache?.service).toBe("elasticache-valkey-node");
    expect(out.target.components.cache?.config.maxmemoryPolicy).toBe("noeviction");
    expect(out.target.components.storage?.service).toBe("s3-cloudfront-oac");
    expect(out.target.components.cron?.service).toBe("eventbridge-scheduler");
    expect(out.target.components.network?.config.natGateway).toBe(true);
    expect(out.warnings.some((w) => w.includes("NAT Gateway"))).toBe(true);
  });

  it("never picks App Runner and respects pins.noNat and --set overrides with cost deltas", () => {
    const out = designAwsTarget({
      facts: {
        appKind: "ssr",
        languages: ["python"],
        services: [{ kind: "postgres", evidence: ["psycopg"] }],
        cronJobs: [],
      },
      requirements: {
        region: "us-east",
        expectedMonthlyUsers: "1k-10k",
        uptime: "standard",
        dataCriticality: "important",
        budgetMonthly: { amount: 60, currency: "USD" },
      },
      preset: "balanced",
      pins: { noNat: true },
    });

    expect(out.target.compute).toBe("ecs-fargate");
    expect(out.target.components.compute?.service).not.toContain("apprunner");

    const updated = applyAwsOverrides(out.target, [
      "database.multiAz=true",
      "observability.logsRetentionDays=90",
    ]);
    expect(updated.target.components.database?.config.multiAz).toBe(true);
    expect(updated.target.observability.logsRetentionDays).toBe(90);
    expect(updated.deltaMonthlyUsd).toBeGreaterThan(0);
    expect(updated.changes).toEqual([
      "database.multiAz: false → true",
      "observability.logsRetentionDays: 30 → 90",
    ]);

    // Attempting to silently disable a guardrail is refused.
    expect(() => applyAwsOverrides(out.target, ["guardrails.privateDatabase=false"])).toThrow(
      /cannot be disabled silently/,
    );
  });
});

describe("034 AWS HCL renderer & keyless OIDC workflow (T3405)", () => {
  it("renders readable HCL with strict immutable-ID OIDC, private DB, S3 Block Public Access, explicit log retention, and zero secrets in state", () => {
    const designed = designAwsTarget({
      facts: {
        appKind: "fullstack",
        languages: ["typescript"],
        services: [
          { kind: "postgres", evidence: ["pg"] },
          { kind: "s3", evidence: ["s3"] },
        ],
        cronJobs: [],
      },
      requirements: {
        region: "us-east",
        expectedMonthlyUsers: "1k-10k",
        uptime: "standard",
        dataCriticality: "important",
        budgetMonthly: { amount: 80, currency: "USD" },
      },
      preset: "balanced",
    });

    const files = renderAwsHcl({
      appName: "shop",
      environment: "prod",
      infraDir: "infra",
      target: designed.target,
      github: {
        owner: "acme",
        repo: "shop",
        ownerId: 12345,
        repoId: 67890,
        environmentName: "prod",
      },
    });

    const byPath = new Map(files.map((f) => [f.path, f.content]));
    expect(
      githubOidcSubject({
        owner: "acme",
        repo: "shop",
        ownerId: 12345,
        repoId: 67890,
        environmentName: "prod",
      }),
    ).toBe("repo:acme@12345/shop@67890:environment:prod");

    const iam = byPath.get("infra/iam-oidc.tf") ?? "";
    expect(iam).toContain("StringEquals = {");
    expect(iam).toContain("repo:acme@12345/shop@67890:environment:prod");
    expect(iam).not.toContain("repo:acme/*");

    const db = byPath.get("infra/database.tf") ?? "";
    expect(db).toContain("publicly_accessible         = false");
    expect(db).toContain("storage_encrypted           = true");

    const storage = byPath.get("infra/storage.tf") ?? "";
    expect(storage).toContain("block_public_acls       = true");
    expect(storage).toContain("restrict_public_buckets = true");

    const secrets = byPath.get("infra/secrets.tf") ?? "";
    expect(secrets).not.toContain("aws_secretsmanager_secret_version");
    expect(secrets).not.toContain("aws_ssm_parameter");

    const obs = byPath.get("infra/observability.tf") ?? "";
    expect(obs).toContain("retention_in_days = 30");
    expect(obs).not.toContain("aws_acmpca_certificate_authority");
  });

  it("renders a keyless GitHub Actions OIDC workflow with zero stored AWS access keys", () => {
    const designed = designAwsTarget({
      facts: {
        appKind: "api",
        languages: ["typescript"],
        services: [],
        cronJobs: [],
      },
      requirements: {
        region: "us-east",
        expectedMonthlyUsers: "1k-10k",
        uptime: "standard",
        dataCriticality: "none",
        budgetMonthly: { amount: 50, currency: "USD" },
      },
      preset: "balanced",
    });

    const wf = renderAwsDeployWorkflow({
      appName: "shop",
      environment: "prod",
      workflowPath: ".github/workflows/opscrew-deploy.yml",
      branch: "main",
      target: designed.target,
    });

    expect(wf.content).toContain("id-token: write");
    expect(wf.content).toContain("aws-actions/configure-aws-credentials@");
    expect(wf.content).toContain("role-to-assume: ${{ vars.OPSCREW_AWS_DEPLOY_ROLE_ARN }}");
    expect(wf.content).toContain("aws ecs register-task-definition");
    expect(wf.content).not.toContain("AWS_SECRET_ACCESS_KEY");
    expect(wf.content).not.toContain("AWS_ACCESS_KEY_ID");
  });

  it("escapes HCL injection payloads, renders existingVpcId locals, app egress + DB ingress, ACM output, and per-compute renderers", () => {
    const designed = designAwsTarget({
      facts: {
        appKind: "fullstack",
        languages: ["typescript"],
        services: [{ kind: "postgres", evidence: ["pg"] }],
        cronJobs: [],
      },
      requirements: {
        region: "us-east",
        expectedMonthlyUsers: "1k-10k",
        uptime: "standard",
        dataCriticality: "important",
        budgetMonthly: { amount: 60, currency: "USD" },
      },
      preset: "balanced",
      pins: { existingVpcId: "vpc-0123456789abcdef0", noNat: true },
    });

    const files = renderAwsHcl({
      appName: 'shop-${file("~/.aws/credentials")}',
      environment: "prod",
      infraDir: "infra",
      domain: "shop.example.com",
      target: designed.target,
      github: { owner: "acme", repo: "shop", environmentName: "prod" },
    });
    const byPath = new Map(files.map((f) => [f.path, f.content]));

    // Medium #7: HCL interpolation & quotes must be escaped!
    const varsTf = byPath.get("infra/variables.tf") ?? "";
    expect(varsTf).toContain('$${file(\\"~/.aws/credentials\\")}');

    // Medium #8: existingVpcId emits unified locals so compute/database never reference missing aws_vpc.main!
    const vpcTf = byPath.get("infra/vpc.tf") ?? "";
    expect(vpcTf).toContain('data "aws_vpc" "main"');
    expect(vpcTf).toContain("vpc_id             = data.aws_vpc.main.id");

    // Medium #9: app SG has egress, DB SG allows app SG ingress, lean/noNat uses public subnets!
    const computeTf = byPath.get("infra/compute.tf") ?? "";
    expect(computeTf).toContain("egress {");
    expect(computeTf).toContain("local.public_subnet_ids");
    expect(computeTf).toContain("assign_public_ip = true");

    const dbTf = byPath.get("infra/database.tf") ?? "";
    expect(dbTf).toContain("security_groups = [aws_security_group.app.id]");
    expect(dbTf).toContain("from_port       = 5432");

    // Medium #10 & Low #19: scoped iam:PassRole and data lookup for existing GitHub OIDC provider by default!
    const iamTf = byPath.get("infra/iam-oidc.tf") ?? "";
    expect(iamTf).toContain('data "aws_iam_openid_connect_provider" "github"');
    expect(iamTf).toContain('"iam:PassRole"');
    expect(iamTf).toContain('image_tag_mutability = "MUTABLE"');

    // Medium #16: ACM certificate and acm_validation_records output rendered when domain is set!
    expect(byPath.get("infra/acm.tf")).toContain('resource "aws_acm_certificate" "app"');
    expect(byPath.get("infra/outputs.tf")).toContain('output "acm_validation_records"');

    // Medium #11: dedicated ec2-compose and lambda-web renderers (never silently falling through to Fargate)!
    const ec2 = applyAwsOverrides(designed.target, ["compute.service=ec2-compose"]).target;
    const ec2Compute =
      renderAwsHcl({
        appName: "shop",
        environment: "prod",
        infraDir: "infra",
        target: ec2,
        github: { owner: "acme", repo: "shop", environmentName: "prod" },
      }).find((f) => f.path === "infra/compute.tf")?.content ?? "";
    expect(ec2Compute).toContain('resource "aws_instance" "app"');
    expect(ec2Compute).not.toContain("aws_ecs_service");

    const lambda = applyAwsOverrides(designed.target, ["compute.service=lambda-web"]).target;
    const lambdaCompute =
      renderAwsHcl({
        appName: "shop",
        environment: "prod",
        infraDir: "infra",
        target: lambda,
        github: { owner: "acme", repo: "shop", environmentName: "prod" },
      }).find((f) => f.path === "infra/compute.tf")?.content ?? "";
    expect(lambdaCompute).toContain('resource "aws_lambda_function" "app"');
    expect(lambdaCompute).toContain('resource "aws_cloudwatch_log_group" "lambda"');
    expect(lambdaCompute).toContain("retention_in_days = 30");
  });
});
