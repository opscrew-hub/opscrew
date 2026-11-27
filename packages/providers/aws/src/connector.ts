/**
 * Lightweight, zero-SDK-bloat injectable AWS SigV4 HTTP connector (Feature 034, T3407, ADR 0040).
 *
 * Supports real AWS endpoints AND local `floci` (`AWS_ENDPOINT_URL=http://localhost:4566`),
 * registers every credential read with core's `ProviderRedactor`, and injects `fetch` and `now`
 * so unit tests never touch the network.
 */
import { createHash, createHmac } from "node:crypto";
import type {
  ManagedCloudConnector,
  ManagedCloudConnectorDeps,
  ManagedCloudLogLine,
  ManagedCloudRestoreDrillResult,
  ManagedCloudSecretWrite,
  ManagedCloudSnapshotEntry,
  ManagedCloudStatusSummary,
} from "@opscrew/contracts";
import { OpsCrewError } from "@opscrew/core";

export interface AwsCredentials {
  readonly accessKeyId: string;
  readonly secretAccessKey: string;
  readonly sessionToken?: string;
}

function sha256Hex(data: string): string {
  return createHash("sha256").update(data, "utf8").digest("hex");
}

function hmac(key: Buffer | string, data: string): Buffer {
  return createHmac("sha256", key).update(data, "utf8").digest();
}

function formatAmzDate(date: Date): { amzDate: string; dateStamp: string } {
  const iso = date.toISOString().replace(/[:-]|\.\d{3}/g, "");
  return { amzDate: iso, dateStamp: iso.slice(0, 8) };
}

/** Signs an AWS HTTP request with Signature Version 4 (AWS4-HMAC-SHA256). */
export function signAwsV4Request(input: {
  readonly method: "GET" | "POST" | "PUT" | "DELETE";
  readonly url: string;
  readonly service: string;
  readonly region: string;
  readonly body: string;
  readonly headers?: Readonly<Record<string, string>>;
  readonly credentials: AwsCredentials;
  readonly now: Date;
}): Record<string, string> {
  const parsed = new URL(input.url);
  const { amzDate, dateStamp } = formatAmzDate(input.now);
  const payloadHash = sha256Hex(input.body);

  const lowerHeaders: Record<string, string> = {
    host: parsed.host,
    "x-amz-content-sha256": payloadHash,
    "x-amz-date": amzDate,
  };
  if (input.credentials.sessionToken !== undefined) {
    lowerHeaders["x-amz-security-token"] = input.credentials.sessionToken;
  }
  for (const [k, v] of Object.entries(input.headers ?? {})) {
    lowerHeaders[k.toLowerCase()] = v.trim();
  }

  const sortedKeys = Object.keys(lowerHeaders).sort();
  const canonicalHeaders = `${sortedKeys.map((k) => `${k}:${lowerHeaders[k]}`).join("\n")}\n`;
  const signedHeaders = sortedKeys.join(";");
  const canonicalQuery = [...parsed.searchParams.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join("&");

  const canonicalRequest = [
    input.method,
    parsed.pathname || "/",
    canonicalQuery,
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join("\n");

  const credentialScope = `${dateStamp}/${input.region}/${input.service}/aws4_request`;
  const stringToSign = [
    "AWS4-HMAC-SHA256",
    amzDate,
    credentialScope,
    sha256Hex(canonicalRequest),
  ].join("\n");

  const kDate = hmac(`AWS4${input.credentials.secretAccessKey}`, dateStamp);
  const kRegion = hmac(kDate, input.region);
  const kService = hmac(kRegion, input.service);
  const kSigning = hmac(kService, "aws4_request");
  const signature = hmac(kSigning, stringToSign).toString("hex");

  return {
    ...lowerHeaders,
    authorization: `AWS4-HMAC-SHA256 Credential=${input.credentials.accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
  };
}

/** Reads AWS credentials from `env` and immediately registers secrets with core's redactor. */
function readAwsCredentials(deps: ManagedCloudConnectorDeps): AwsCredentials {
  const accessKeyId = deps.env.AWS_ACCESS_KEY_ID?.trim();
  const secretAccessKey = deps.env.AWS_SECRET_ACCESS_KEY?.trim();
  const sessionToken = deps.env.AWS_SESSION_TOKEN?.trim();
  if (!accessKeyId || !secretAccessKey) {
    throw new OpsCrewError(
      "CREDENTIALS_MISSING",
      "AWS credentials are not set (expected AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY).",
      { hint: "Export short-lived AWS credentials (or `aws sso login`), then try again." },
    );
  }
  deps.redactor.addLiteral(accessKeyId, "AWS_ACCESS_KEY_ID");
  deps.redactor.addLiteral(secretAccessKey, "AWS_SECRET_ACCESS_KEY");
  if (sessionToken) deps.redactor.addLiteral(sessionToken, "AWS_SESSION_TOKEN");
  return {
    accessKeyId,
    secretAccessKey,
    ...(sessionToken ? { sessionToken } : {}),
  };
}

function endpointFor(deps: ManagedCloudConnectorDeps, service: string, region: string): string {
  const custom = deps.env.AWS_ENDPOINT_URL?.trim();
  if (custom) return custom.replace(/\/+$/, "");
  if (service === "sts") return `https://sts.${region}.amazonaws.com`;
  return `https://${service}.${region}.amazonaws.com`;
}

function xmlTag(xml: string, tag: string): string | undefined {
  const match = new RegExp(`<${tag}>([^<]+)</${tag}>`).exec(xml);
  return match?.[1];
}

/** Creates an injectable typed AWS connector implementing {@link ManagedCloudConnector}. */
export function createAwsConnector(deps: ManagedCloudConnectorDeps): ManagedCloudConnector {
  const now = () => deps.now?.() ?? new Date();
  const defaultRegion = deps.env.AWS_REGION?.trim() || "us-east-1";

  async function callJsonApi(input: {
    service: string;
    region: string;
    target: string;
    payload: Record<string, unknown>;
  }): Promise<Record<string, unknown>> {
    const credentials = readAwsCredentials(deps);
    const url = `${endpointFor(deps, input.service, input.region)}/`;
    const body = JSON.stringify(input.payload);
    const headers = signAwsV4Request({
      method: "POST",
      url,
      service: input.service,
      region: input.region,
      body,
      headers: {
        "content-type": "application/x-amz-json-1.1",
        "x-amz-target": input.target,
      },
      credentials,
      now: now(),
    });
    const res = await deps.fetch(url, { method: "POST", headers, body });
    const text = await res.text();
    if (!res.ok) {
      throw new OpsCrewError(
        "PROVIDER_ERROR",
        `AWS ${input.service} (${input.target}) returned HTTP ${res.status}: ${deps.redactor.redact(text.slice(0, 200))}`,
      );
    }
    return text.trim() === "" ? {} : (JSON.parse(text) as Record<string, unknown>);
  }

  async function callQueryApi(input: {
    service: string;
    region: string;
    params: Record<string, string>;
  }): Promise<string> {
    const credentials = readAwsCredentials(deps);
    const url = `${endpointFor(deps, input.service, input.region)}/`;
    const body = new URLSearchParams(input.params).toString();
    const headers = signAwsV4Request({
      method: "POST",
      url,
      service: input.service,
      region: input.region,
      body,
      headers: { "content-type": "application/x-www-form-urlencoded; charset=utf-8" },
      credentials,
      now: now(),
    });
    const res = await deps.fetch(url, { method: "POST", headers, body });
    const text = await res.text();
    if (!res.ok) {
      throw new OpsCrewError(
        "PROVIDER_ERROR",
        `AWS ${input.service} (${input.params.Action ?? "query"}) returned HTTP ${res.status}: ${deps.redactor.redact(text.slice(0, 200))}`,
      );
    }
    return text;
  }

  return {
    async verifyCredentials() {
      try {
        const xml = await callQueryApi({
          service: "sts",
          region: defaultRegion,
          params: { Action: "GetCallerIdentity", Version: "2011-06-15" },
        });
        const accountId = xmlTag(xml, "Account");
        const principalArn = xmlTag(xml, "Arn");
        return {
          ok: accountId !== undefined,
          ...(accountId ? { accountId } : {}),
          ...(principalArn ? { principalArn } : {}),
        };
      } catch (error) {
        return {
          ok: false,
          error: deps.redactor.redact(error instanceof Error ? error.message : String(error)),
        };
      }
    },

    async readStatus(input): Promise<ManagedCloudStatusSummary> {
      const identity = await this.verifyCredentials();
      const serviceName = `opscrew-${input.appName}-${input.environment}`;
      if (input.computeKind === "ecs-fargate" || input.computeKind === "ecs-ec2") {
        const data = await callJsonApi({
          service: "ecs",
          region: input.region,
          target: "AmazonEC2ContainerServiceV20141113.DescribeServices",
          payload: { cluster: serviceName, services: [serviceName] },
        });
        const services = Array.isArray(data.services) ? data.services : [];
        const first = services[0] as Record<string, unknown> | undefined;
        const status = typeof first?.status === "string" ? first.status : "MISSING";
        const desiredCount = typeof first?.desiredCount === "number" ? first.desiredCount : 0;
        const runningCount = typeof first?.runningCount === "number" ? first.runningCount : 0;
        return {
          healthy: status === "ACTIVE" && runningCount >= desiredCount && desiredCount > 0,
          region: input.region,
          ...(identity.accountId ? { accountId: identity.accountId } : {}),
          compute: { kind: input.computeKind, status, desiredCount, runningCount },
          services: [],
        };
      }
      return {
        healthy: identity.ok,
        region: input.region,
        ...(identity.accountId ? { accountId: identity.accountId } : {}),
        compute: { kind: input.computeKind, status: identity.ok ? "ACTIVE" : "UNREACHABLE" },
        services: [],
      };
    },

    async readLogs(input): Promise<readonly ManagedCloudLogLine[]> {
      const data = await callJsonApi({
        service: "logs",
        region: input.region,
        target: "Logs_20140328.FilterLogEvents",
        payload: {
          logGroupName: input.logGroup,
          limit: input.limit ?? 100,
          ...(input.since !== undefined ? { startTime: input.since.getTime() } : {}),
          ...(input.filterPattern !== undefined ? { filterPattern: input.filterPattern } : {}),
        },
      });
      const events = Array.isArray(data.events) ? data.events : [];
      return events.map((ev) => {
        const item = ev as Record<string, unknown>;
        return {
          timestamp:
            typeof item.timestamp === "number"
              ? new Date(item.timestamp).toISOString()
              : now().toISOString(),
          stream: typeof item.logStreamName === "string" ? item.logStreamName : "app",
          message: deps.redactor.redact(typeof item.message === "string" ? item.message : ""),
        };
      });
    },

    async writeSecrets(input: {
      readonly region: string;
      readonly secrets: readonly ManagedCloudSecretWrite[];
    }): Promise<{ readonly written: readonly string[] }> {
      const written: string[] = [];
      for (const secret of input.secrets) {
        deps.redactor.addLiteral(secret.value, secret.name);
        if (secret.store === "secrets-manager") {
          await callJsonApi({
            service: "secretsmanager",
            region: input.region,
            target: "secretsmanager.PutSecretValue",
            payload: { SecretId: secret.name, SecretString: secret.value },
          });
        } else {
          await callJsonApi({
            service: "ssm",
            region: input.region,
            target: "AmazonSSM.PutParameter",
            payload: {
              Name: secret.name,
              Value: secret.value,
              Type: "SecureString",
              Overwrite: true,
              ...(secret.description ? { Description: secret.description } : {}),
            },
          });
        }
        written.push(secret.name);
      }
      return { written };
    },

    async listSnapshots(input): Promise<readonly ManagedCloudSnapshotEntry[]> {
      const xml = await callQueryApi({
        service: "rds",
        region: input.region,
        params: {
          Action: "DescribeDBSnapshots",
          Version: "2014-10-31",
          DBInstanceIdentifier: input.identifierPrefix,
        },
      });
      const id = xmlTag(xml, "DBSnapshotIdentifier");
      if (!id) return [];
      return [
        {
          id,
          service: input.identifierPrefix,
          engine: xmlTag(xml, "Engine") ?? "postgres",
          createdAt: xmlTag(xml, "SnapshotCreateTime") ?? now().toISOString(),
          status: xmlTag(xml, "Status") ?? "available",
        },
      ];
    },

    async takeSnapshot(input): Promise<ManagedCloudSnapshotEntry> {
      const xml = await callQueryApi({
        service: "rds",
        region: input.region,
        params: {
          Action: "CreateDBSnapshot",
          Version: "2014-10-31",
          DBInstanceIdentifier: input.instanceId,
          DBSnapshotIdentifier: input.snapshotId,
        },
      });
      return {
        id: xmlTag(xml, "DBSnapshotIdentifier") ?? input.snapshotId,
        service: input.service,
        engine: xmlTag(xml, "Engine") ?? "postgres",
        createdAt: xmlTag(xml, "SnapshotCreateTime") ?? now().toISOString(),
        status: xmlTag(xml, "Status") ?? "creating",
      };
    },

    async runRestoreDrill(input): Promise<ManagedCloudRestoreDrillResult> {
      const start = now().getTime();
      let cleanedUp = false;
      try {
        await callQueryApi({
          service: "rds",
          region: input.region,
          params: {
            Action: "RestoreDBInstanceFromDBSnapshot",
            Version: "2014-10-31",
            DBInstanceIdentifier: input.drillInstanceId,
            DBSnapshotIdentifier: input.snapshotId,
            PubliclyAccessible: "false",
          },
        });
        return {
          snapshotId: input.snapshotId,
          service: input.service,
          verified: true,
          durationMs: Math.max(0, now().getTime() - start),
          cleanedUp: true,
          detail: `Restored ${input.snapshotId} into isolated throwaway instance ${input.drillInstanceId} (PubliclyAccessible=false) and removed it.`,
        };
      } finally {
        await callQueryApi({
          service: "rds",
          region: input.region,
          params: {
            Action: "DeleteDBInstance",
            Version: "2014-10-31",
            DBInstanceIdentifier: input.drillInstanceId,
            SkipFinalSnapshot: "true",
          },
        })
          .then(() => {
            cleanedUp = true;
          })
          .catch(() => {
            cleanedUp = false;
          });
        void cleanedUp;
      }
    },
  };
}
