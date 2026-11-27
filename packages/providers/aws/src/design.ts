/**
 * Deterministic AWS Architect & preset mapper (Feature 034, ADR 0040 D6–D9).
 *
 * Maps detected `ProjectFacts` + user `Requirements` + `preset` (`lean`, `balanced`,
 * `production-ha`) + user `pins` into a validated `AwsTarget` with per-component `service`,
 * plain-English `why`, rejected `alternatives`, itemized `monthlyCostUsd`, default-on guardrails,
 * and cost-trap avoidance.
 */
import {
  type AwsComponentDecision,
  type AwsComputeKind,
  type AwsPins,
  type AwsPreset,
  type AwsTarget,
  AwsTargetSchema,
  type ProjectFacts,
  type Requirements,
} from "@opscrew/plan-schema";
import {
  AWS_REGIONS,
  AWS_UNIT_RATES_USD,
  awsRegionFor,
  estimateAwsMonthlyCost,
  regionalUsd,
  roundUsd,
} from "./pricing";

export interface DesignAwsInput {
  readonly facts: Pick<ProjectFacts, "appKind" | "languages" | "services" | "cronJobs"> & {
    readonly workers?: readonly { readonly name: string }[];
  };
  readonly requirements: Pick<
    Requirements,
    "region" | "expectedMonthlyUsers" | "uptime" | "dataCriticality" | "budgetMonthly"
  >;
  readonly preset?: AwsPreset;
  readonly pins?: AwsPins;
  readonly computeOverride?: AwsComputeKind;
}

export interface DesignAwsResult {
  readonly target: AwsTarget;
  readonly totalMonthlyUsd: number;
  readonly warnings: readonly string[];
}

/** Chooses the default AWS preset from interview requirements when the user didn't pick one explicitly. */
export function defaultAwsPreset(
  req: Pick<Requirements, "expectedMonthlyUsers" | "uptime" | "budgetMonthly">,
): AwsPreset {
  if (req.uptime === "high" || req.expectedMonthlyUsers === ">100k") return "production-ha";
  if (req.budgetMonthly.amount <= 25 && req.expectedMonthlyUsers === "<1k") return "lean";
  return "balanced";
}

/**
 * Selects the best AWS compute primitive for the app's shape and preset (ADR 0040 D7).
 * Never selects App Runner (closed to new customers on 2026-04-30).
 */
function selectCompute(
  input: DesignAwsInput,
  preset: AwsPreset,
  region: string,
  hasWorkers: boolean,
  hasWebsockets: boolean,
): { compute: AwsComputeKind; decision: AwsComponentDecision } {
  const regionInfo = AWS_REGIONS.find((r) => r.id === region);
  const isNodeHttp =
    (input.facts.languages.includes("typescript") ||
      input.facts.languages.includes("javascript")) &&
    !hasWorkers &&
    !hasWebsockets &&
    (input.facts.appKind === "api" ||
      input.facts.appKind === "ssr" ||
      input.facts.appKind === "fullstack");

  const chosen: AwsComputeKind =
    input.computeOverride ??
    (preset === "lean"
      ? hasWorkers
        ? "ec2-compose"
        : isNodeHttp &&
            regionInfo?.supportsLambdaWeb === true &&
            input.requirements.expectedMonthlyUsers === "<1k"
          ? "lambda-web"
          : "lightsail-containers"
      : "ecs-fargate");

  const albCost = regionalUsd(AWS_UNIT_RATES_USD.albBaseMonthly, region);
  const ipv4 = AWS_UNIT_RATES_USD.publicIpv4Monthly;

  switch (chosen) {
    case "lambda-web":
      return {
        compute: "lambda-web",
        decision: {
          service: "lambda-web",
          why: "AWS Lambda Web Functions (Oct 2026) run standard Node.js HTTP servers with active-CPU-only billing and zero ALB/IPv4 idle floor for low or spiky traffic.",
          alternatives: [
            {
              service: "lightsail-containers",
              monthlyCostUsd: AWS_UNIT_RATES_USD.lightsailNanoMonthly,
              whyNot: "Flat $7/mo always-on container; slightly higher floor for sporadic traffic.",
            },
            {
              service: "ecs-fargate",
              monthlyCostUsd: roundUsd(
                regionalUsd(AWS_UNIT_RATES_USD.fargateQuarterMonthly, region) + albCost + ipv4,
              ),
              whyNot: "ALB ($18/mo) + Fargate + IPv4 adds ~$29/mo base before serving any traffic.",
            },
          ],
          monthlyCostUsd: regionalUsd(AWS_UNIT_RATES_USD.lambdaWebBaselineMonthly, region),
          config: { memoryMb: 512, architecture: "arm64", runtime: "nodejs22.x" },
        },
      };

    case "lightsail-containers":
      return {
        compute: "lightsail-containers",
        decision: {
          service: "lightsail-containers",
          why: "Flat-rate predictable container hosting with built-in HTTPS endpoint, 500 GB transfer, and zero ALB/NAT/IPv4 cost surprises.",
          alternatives: [
            {
              service: "ecs-fargate",
              monthlyCostUsd: roundUsd(
                regionalUsd(AWS_UNIT_RATES_USD.fargateQuarterMonthly, region) + albCost + ipv4,
              ),
              whyNot: "Requires ALB (~$18/mo) and public IPv4 charges (~$3.65/mo each).",
            },
            {
              service: "ec2-compose",
              monthlyCostUsd: regionalUsd(AWS_UNIT_RATES_USD.ec2MicroComposeMonthly, region),
              whyNot:
                "Requires managing an EC2 host OS instead of a flat-rate managed container endpoint.",
            },
          ],
          monthlyCostUsd: AWS_UNIT_RATES_USD.lightsailNanoMonthly,
          config: { power: "nano", scale: 1 },
        },
      };

    case "ec2-compose":
      return {
        compute: "ec2-compose",
        decision: {
          service: "ec2-compose",
          why: "Single Graviton EC2 instance running Docker Compose (includes web + workers + Caddy HTTPS, zero ALB fee, supports `opscrew retarget --to aws`).",
          alternatives: [
            {
              service: "ecs-fargate",
              monthlyCostUsd: roundUsd(
                regionalUsd(AWS_UNIT_RATES_USD.fargateHalfMonthly, region) + albCost + ipv4,
              ),
              whyNot:
                "Higher baseline cost for small steady apps with workers due to ALB + per-task billing.",
            },
          ],
          monthlyCostUsd: regionalUsd(
            hasWorkers
              ? AWS_UNIT_RATES_USD.ec2SmallComposeMonthly
              : AWS_UNIT_RATES_USD.ec2MicroComposeMonthly,
            region,
          ),
          config: {
            instanceType: hasWorkers ? "t4g.small" : "t4g.micro",
            volumeGb: 20,
            ipv4: true,
          },
        },
      };

    case "ecs-ec2":
      return {
        compute: "ecs-ec2",
        decision: {
          service: "ecs-ec2",
          why: "Amazon ECS on EC2 capacity providers for large steady compute or GPU workloads behind an Application Load Balancer.",
          alternatives: [
            {
              service: "ecs-fargate",
              monthlyCostUsd: roundUsd(
                regionalUsd(AWS_UNIT_RATES_USD.fargateOneMonthly * 2, region) + albCost,
              ),
              whyNot: "Higher per-vCPU cost at sustained high utilization and no GPU instances.",
            },
          ],
          monthlyCostUsd: roundUsd(
            regionalUsd(AWS_UNIT_RATES_USD.ec2SmallComposeMonthly * 2, region) + albCost,
          ),
          config: { instanceType: "t4g.medium", desiredCount: 2, alb: true },
        },
      };

    case "lambda-event":
      return {
        compute: "lambda-event",
        decision: {
          service: "lambda-event",
          why: "Event-driven AWS Lambda Event Functions for lightweight scheduled or queue jobs.",
          alternatives: [],
          monthlyCostUsd: regionalUsd(1.0, region),
          config: { memoryMb: 256, architecture: "arm64" },
        },
      };

    default: {
      const replicas = preset === "production-ha" ? 2 : 1;
      const taskUnit =
        preset === "production-ha"
          ? AWS_UNIT_RATES_USD.fargateHalfMonthly
          : AWS_UNIT_RATES_USD.fargateQuarterMonthly;
      const workerTasks = hasWorkers ? 1 : 0;
      const computeUsd = regionalUsd(taskUnit * (replicas + workerTasks), region);
      const expressMode = !hasWorkers && preset === "balanced";
      const totalUsd = roundUsd(computeUsd + albCost + ipv4 * (replicas + 1));
      return {
        compute: "ecs-fargate",
        decision: {
          service: expressMode ? "ecs-fargate-express" : "ecs-fargate",
          why: expressMode
            ? "Amazon ECS on Fargate (Express Mode — AWS's replacement for App Runner) with zero-downtime rolling deploys, private DB networking, and IAM task roles."
            : `Amazon ECS on Fargate (${replicas} web task${replicas > 1 ? "s" : ""}${hasWorkers ? " + worker service" : ""}) behind an ALB with zero-downtime rolling deploys and least-privilege IAM task roles.`,
          alternatives: [
            {
              service: "lightsail-containers",
              monthlyCostUsd: AWS_UNIT_RATES_USD.lightsailMicroMonthly,
              whyNot:
                "Cheaper ($10/mo), but lacks private VPC security groups, sidecars, and fine-grained IAM task roles.",
            },
            {
              service: "ec2-compose",
              monthlyCostUsd: regionalUsd(AWS_UNIT_RATES_USD.ec2SmallComposeMonthly, region),
              whyNot: "Single-server scaling ceiling without multi-AZ task failover.",
            },
          ],
          monthlyCostUsd: totalUsd,
          config: {
            cpu: preset === "production-ha" ? 512 : 256,
            memoryMb: preset === "production-ha" ? 1024 : 512,
            desiredCount: replicas,
            architecture: "arm64",
            expressMode,
            alb: true,
          },
        },
      };
    }
  }
}

/** Maps detected database needs to zero-code-rewrite AWS managed services (ADR 0040 D8). */
function selectDatabase(
  services: readonly string[],
  preset: AwsPreset,
  region: string,
  pins: AwsPins,
): AwsComponentDecision | undefined {
  if (pins.existingDb !== undefined) {
    return {
      service: "existing-database",
      why: `Pinned to existing database (${pins.existingDb}); OpsCrew will not provision a new database.`,
      alternatives: [],
      monthlyCostUsd: 0,
      config: { existingDb: pins.existingDb },
    };
  }
  const multiAz = preset === "production-ha";
  if (services.includes("postgres")) {
    const useAurora = preset === "production-ha";
    const cost = useAurora
      ? regionalUsd(AWS_UNIT_RATES_USD.auroraServerlessHalfAcuMonthly, region)
      : regionalUsd(AWS_UNIT_RATES_USD.rdsMicroSingleAzMonthly * (multiAz ? 2 : 1), region);
    return {
      service: useAurora ? "aurora-postgres-serverless-v2" : "rds-postgres",
      why: useAurora
        ? "Amazon Aurora PostgreSQL Serverless v2 for automatic Multi-AZ HA, PITR backups, and zero code changes for standard PostgreSQL drivers."
        : "Amazon RDS PostgreSQL (db.t4g.micro Graviton) with automated daily backups, encryption at rest, and zero driver changes.",
      alternatives: [
        {
          service: useAurora ? "rds-postgres" : "aurora-postgres-serverless-v2",
          monthlyCostUsd: useAurora
            ? regionalUsd(AWS_UNIT_RATES_USD.rdsSmallSingleAzMonthly * 2, region)
            : regionalUsd(AWS_UNIT_RATES_USD.auroraServerlessHalfAcuMonthly, region),
          whyNot: useAurora
            ? "Fixed instance sizing instead of elastic ACU scaling."
            : "Higher continuous 0.5 ACU floor (~$44/mo) than db.t4g.micro (~$14/mo) for always-on prod.",
        },
        {
          service: "ec2-ebs-postgres",
          monthlyCostUsd: regionalUsd(AWS_UNIT_RATES_USD.ec2MicroComposeMonthly, region),
          whyNot: "Self-managed backups and patching instead of managed RDS automated snapshots.",
        },
      ],
      monthlyCostUsd: cost,
      config: useAurora
        ? { engine: "aurora-postgresql", minAcu: 0.5, maxAcu: 4, multiAz: true, encrypted: true }
        : {
            engine: "postgres",
            instanceClass: "db.t4g.micro",
            storageGb: 20,
            multiAz,
            encrypted: true,
          },
    };
  }
  if (services.includes("mysql") || services.includes("mariadb")) {
    const cost = regionalUsd(
      AWS_UNIT_RATES_USD.rdsMicroSingleAzMonthly * (multiAz ? 2 : 1),
      region,
    );
    return {
      service: "rds-mysql",
      why: "Amazon RDS MySQL (db.t4g.micro) with automated daily backups, private subnet placement, and unchanged MySQL driver compatibility.",
      alternatives: [],
      monthlyCostUsd: cost,
      config: {
        engine: "mysql",
        instanceClass: "db.t4g.micro",
        storageGb: 20,
        multiAz,
        encrypted: true,
      },
    };
  }
  if (services.includes("mongodb")) {
    return {
      service: "mongodb-atlas-aws",
      why: "MongoDB Atlas on AWS preserves 100% MongoDB driver and query compatibility with zero code rewrites.",
      alternatives: [
        {
          service: "documentdb",
          monthlyCostUsd: regionalUsd(190, region),
          whyNot:
            "High instance floor and partial MongoDB API compatibility requiring driver/query checks.",
        },
      ],
      monthlyCostUsd: 0,
      config: { externalManaged: true },
    };
  }
  if (services.includes("cassandra")) {
    return {
      service: "amazon-keyspaces",
      why: "Amazon Keyspaces (for Apache Cassandra) runs existing CQL drivers serverless with zero server management.",
      alternatives: [],
      monthlyCostUsd: regionalUsd(5, region),
      config: { capacityMode: "PAY_PER_REQUEST" },
    };
  }
  if (services.includes("clickhouse") || services.includes("neo4j")) {
    const engine = services.includes("clickhouse") ? "clickhouse" : "neo4j";
    return {
      service: `ec2-ebs-${engine}`,
      why: `Runs ${engine} on dedicated EC2 + EBS so existing ${engine} drivers work unchanged (Redshift/Neptune are incompatible).`,
      alternatives: [],
      monthlyCostUsd: regionalUsd(AWS_UNIT_RATES_USD.ec2SmallComposeMonthly, region),
      config: { instanceType: "t4g.small", volumeGb: 50 },
    };
  }
  return undefined;
}

/** Builds a complete, validated AWS managed-services target from facts, requirements, preset, and pins. */
export function designAwsTarget(input: DesignAwsInput): DesignAwsResult {
  const preset = input.preset ?? defaultAwsPreset(input.requirements);
  const pins: AwsPins = input.pins ?? {};
  const region = pins.region ?? awsRegionFor(input.requirements.region ?? "us-east").id;
  const detectedServices = input.facts.services.map((s) => s.kind);
  const hasWorkers = (input.facts.workers?.length ?? 0) > 0;
  const hasCron = (input.facts.cronJobs?.length ?? 0) > 0 || detectedServices.includes("cron");
  const hasWebsockets = detectedServices.includes("websocket");
  const hasQueue = detectedServices.includes("queue") || hasWorkers;

  const { compute, decision: computeDecision } = selectCompute(
    input,
    preset,
    region,
    hasWorkers,
    hasWebsockets,
  );

  const components: Record<string, AwsComponentDecision> = {
    compute: computeDecision,
  };

  // Network: lean & balanced avoid NAT Gateway ($36.50/AZ/mo) by default; production-ha uses NAT + free S3/DynamoDB Gateway Endpoints unless pins.noNat.
  const useNat = preset === "production-ha" && pins.noNat !== true;
  const natAzs = useNat ? 2 : 0;
  components.network = {
    service: pins.existingVpcId
      ? "existing-vpc"
      : useNat
        ? "vpc-private-nat-endpoints"
        : "vpc-public-strict-sg",
    why: pins.existingVpcId
      ? `Reuses pinned VPC ${pins.existingVpcId}.`
      : useNat
        ? "Multi-AZ private subnets with NAT Gateways and free S3/DynamoDB VPC Gateway Endpoints for production HA."
        : "Avoids $36.50/AZ/mo NAT Gateway cost trap: compute uses strict security groups while databases stay in private subnets with zero public IP.",
    alternatives: useNat
      ? [
          {
            service: "vpc-public-strict-sg",
            monthlyCostUsd: 0,
            whyNot:
              "Saves ~$73/mo by omitting NAT Gateways; available via `--set network.natGateway=false` or `pins.noNat: true`.",
          },
        ]
      : [
          {
            service: "vpc-private-nat-endpoints",
            monthlyCostUsd: regionalUsd(AWS_UNIT_RATES_USD.natGatewayPerAzMonthly, region),
            whyNot: "NAT Gateway adds ~$36.50/mo per AZ plus $0.045/GB processed.",
          },
        ],
    monthlyCostUsd: useNat
      ? regionalUsd(AWS_UNIT_RATES_USD.natGatewayPerAzMonthly * natAzs, region)
      : 0,
    config: {
      natGateway: useNat,
      natAzs,
      s3GatewayEndpoint: true,
      ...(pins.existingVpcId !== undefined ? { existingVpcId: pins.existingVpcId } : {}),
    },
  };

  const database = selectDatabase(detectedServices, preset, region, pins);
  if (database !== undefined) components.database = database;

  if (detectedServices.includes("redis") || hasQueue) {
    const useNodeValkey = hasQueue;
    components.cache = {
      service: useNodeValkey ? "elasticache-valkey-node" : "elasticache-valkey-serverless",
      why: useNodeValkey
        ? "ElastiCache for Valkey (20% cheaper than Redis OSS) with `maxmemory-policy: noeviction` so queued background jobs are never dropped."
        : "ElastiCache Serverless for Valkey (33% cheaper than Redis OSS serverless) with automatic Multi-AZ scaling and zero node management.",
      alternatives: [
        {
          service: useNodeValkey ? "elasticache-valkey-serverless" : "elasticache-valkey-node",
          monthlyCostUsd: regionalUsd(
            useNodeValkey
              ? AWS_UNIT_RATES_USD.valkeyServerlessFloorMonthly
              : AWS_UNIT_RATES_USD.valkeyNodeMicroMonthly,
            region,
          ),
          whyNot: useNodeValkey
            ? "Node-based parameter groups guarantee explicit `noeviction` for job queues."
            : "Node-based requires sizing and patching a single node.",
        },
      ],
      monthlyCostUsd: regionalUsd(
        useNodeValkey
          ? AWS_UNIT_RATES_USD.valkeyNodeMicroMonthly
          : AWS_UNIT_RATES_USD.valkeyServerlessFloorMonthly,
        region,
      ),
      config: {
        engine: "valkey",
        maxmemoryPolicy: useNodeValkey ? "noeviction" : "volatile-lru",
        transitEncryption: true,
      },
    };
  }

  if (detectedServices.includes("s3") || input.facts.appKind === "static-spa") {
    components.storage = {
      service: "s3-cloudfront-oac",
      why: "Private Amazon S3 bucket (Block Public Access enabled) fronted by Amazon CloudFront via Origin Access Control (OAC) with $0 S3-to-CloudFront transfer.",
      alternatives: [],
      monthlyCostUsd: 0.5,
      config: { blockPublicAccess: true, cloudFrontOac: true, versioning: true },
    };
  }

  const useSecretsManager = preset === "production-ha";
  components.secrets = {
    service: useSecretsManager ? "secrets-manager-bundle" : "ssm-parameter-store-standard",
    why: useSecretsManager
      ? "One bundled AWS Secrets Manager JSON secret ($0.40/mo instead of $0.40 per env var) supporting rotation; values are written out-of-band, never in Terraform state."
      : "AWS SSM Parameter Store Standard (`SecureString`, $0/mo up to 10,000 params) encrypted with KMS; values are written out-of-band, never in Terraform state.",
    alternatives: [
      {
        service: useSecretsManager ? "ssm-parameter-store-standard" : "secrets-manager-bundle",
        monthlyCostUsd: useSecretsManager ? 0 : AWS_UNIT_RATES_USD.secretsManagerSingleMonthly,
        whyNot: useSecretsManager
          ? "No built-in Secrets Manager rotation hooks."
          : "SSM Parameter Store Standard is free for lean/balanced apps without managed rotation.",
      },
    ],
    monthlyCostUsd: useSecretsManager ? AWS_UNIT_RATES_USD.secretsManagerSingleMonthly : 0,
    config: { bundledJson: true, secretsOutOfState: true },
  };

  if (detectedServices.includes("email")) {
    components.email = {
      service: "amazon-ses",
      why: "Amazon SES ($0.10 per 1,000 emails) with DKIM/SPF records for transactional email.",
      alternatives: [],
      monthlyCostUsd: 0.1,
      config: { dkim: true },
    };
  }

  if (hasCron) {
    components.cron = {
      service: "eventbridge-scheduler",
      why: "Amazon EventBridge Scheduler (14M free invocations/month) triggers scheduled tasks cleanly without duplicating cron across replicas.",
      alternatives: [],
      monthlyCostUsd: 0,
      config: { flexibleTimeWindow: "OFF" },
    };
  }

  const keepCloudflareDns = pins.keepCloudflareDns ?? true;
  components.edge = {
    service: keepCloudflareDns ? "cloudflare-dns-acm" : "route53-acm",
    why: keepCloudflareDns
      ? "Keeps DNS at Cloudflare ($0 Route 53 cost) with free AWS ACM certificates validated via DNS-only (`proxied = false`) CNAMEs."
      : "Amazon Route 53 hosted zone ($0.50/mo) with automated free AWS ACM DNS-01 TLS validation.",
    alternatives: [],
    monthlyCostUsd: keepCloudflareDns ? 0 : AWS_UNIT_RATES_USD.route53ZoneMonthly,
    config: { keepCloudflareDns, acmFreePublicCert: true },
  };

  const target = AwsTargetSchema.parse({
    provider: "aws",
    mode: "aws-managed",
    region,
    preset,
    compute,
    components,
    pins,
    observability: {
      logsRetentionDays: preset === "lean" ? 14 : 30,
      containerInsights: preset === "production-ha",
      alarms: true,
      managedGrafana: false,
      openSearch: false,
      tracing: "none",
      otelCollector: false,
    },
  });

  const estimate = estimateAwsMonthlyCost(target);
  return {
    target,
    totalMonthlyUsd: estimate.totalMonthlyUsd,
    warnings: estimate.warnings,
  };
}
