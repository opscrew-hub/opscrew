/**
 * Lightweight, zero-SDK-bloat injectable AWS SigV4 HTTP connector (Feature 034, T3407, ADR 0040).
 *
 * Zero runtime workspace dependencies (ADR 0040 D3: type-only `@opscrew/contracts`). Supports real
 * AWS endpoints AND local `floci` (`AWS_ENDPOINT_URL=http://localhost:4566`), registers every
 * credential read with core's `ProviderRedactor`, and injects `fetch`, `now`, and `sleep` so unit
 * tests never touch the network.
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

/** Standalone user-facing error matching OpsCrew's `{ code, message, hint }` contract without importing `@opscrew/core`. */
export class AwsProviderError extends Error {
  readonly code: string;
  readonly hint?: string;

  constructor(code: string, message: string, options?: { hint?: string }) {
    super(message);
    this.name = "AwsProviderError";
    this.code = code;
    if (options?.hint !== undefined) this.hint = options.hint;
  }
}

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

/** RFC 3986 URI encoding required by AWS SigV4 (also encodes `!`, `'`, `(`, `)`, `*`). */
function encodeRfc3986(value: string): string {
  return encodeURIComponent(value).replace(
    /[!'()*]/g,
    (ch) => `%${ch.charCodeAt(0).toString(16).toUpperCase()}`,
  );
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
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
    .map(([k, v]) => `${encodeRfc3986(k)}=${encodeRfc3986(v)}`)
    .join("&");
  const canonicalPath =
    parsed.pathname
      .split("/")
      .map((seg) => encodeRfc3986(decodeURIComponent(seg)))
      .join("/") || "/";

  const canonicalRequest = [
    input.method,
    canonicalPath,
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
    throw new AwsProviderError(
      "CREDENTIALS_MISSING",
      "AWS credentials are not set (expected AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY).",
      {
        hint: 'Export short-lived credentials in your terminal (e.g., `eval "$(aws configure export-credentials --format env)"` after `aws sso login`), then try again.',
      },
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

function xmlBlocks(xml: string, tag: string): string[] {
  const out: string[] = [];
  const re = new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`, "g");
  for (const match of xml.matchAll(re)) {
    if (match[1] !== undefined) out.push(match[1]);
  }
  return out;
}

/** Creates an injectable typed AWS connector implementing {@link ManagedCloudConnector}. */
export function createAwsConnector(deps: ManagedCloudConnectorDeps): ManagedCloudConnector {
  const now = () => deps.now?.() ?? new Date();
  const sleep = deps.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const maxPollAttempts = deps.maxPollAttempts ?? 12;
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
      throw new AwsProviderError(
        "PROVIDER_ERROR",
        `AWS ${input.service} (${input.target}) returned HTTP ${res.status}: ${deps.redactor.redact(text.slice(0, 200))}`,
      );
    }
    if (text.trim() === "") return {};
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new AwsProviderError(
        "PROVIDER_ERROR",
        `AWS ${input.service} (${input.target}) returned non-JSON response.`,
      );
    }
    if (!isPlainObject(parsed)) {
      throw new AwsProviderError(
        "PROVIDER_ERROR",
        `AWS ${input.service} (${input.target}) returned unexpected non-object JSON.`,
      );
    }
    return parsed;
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
      throw new AwsProviderError(
        "PROVIDER_ERROR",
        `AWS ${input.service} (${input.params.Action ?? "query"}) returned HTTP ${res.status}: ${deps.redactor.redact(text.slice(0, 200))}`,
      );
    }
    return text;
  }

  async function verifyCredentials(): Promise<{
    readonly ok: boolean;
    readonly accountId?: string;
    readonly principalArn?: string;
    readonly error?: string;
  }> {
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
  }

  return {
    verifyCredentials,

    async readStatus(input): Promise<ManagedCloudStatusSummary> {
      const identity = await verifyCredentials();
      const serviceName = `opscrew-${input.appName}-${input.environment}`;
      if (input.computeKind === "ecs-fargate" || input.computeKind === "ecs-ec2") {
        const data = await callJsonApi({
          service: "ecs",
          region: input.region,
          target: "AmazonEC2ContainerServiceV20141113.DescribeServices",
          payload: { cluster: serviceName, services: [serviceName] },
        });
        const services = Array.isArray(data.services) ? data.services : [];
        const first = isPlainObject(services[0]) ? services[0] : undefined;
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
      return events.filter(isPlainObject).map((item) => ({
        timestamp:
          typeof item.timestamp === "number"
            ? new Date(item.timestamp).toISOString()
            : now().toISOString(),
        stream: typeof item.logStreamName === "string" ? item.logStreamName : "app",
        message: deps.redactor.redact(typeof item.message === "string" ? item.message : ""),
      }));
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
      const blocks = xmlBlocks(xml, "DBSnapshot");
      const entries: ManagedCloudSnapshotEntry[] = [];
      for (const block of blocks) {
        const id = xmlTag(block, "DBSnapshotIdentifier");
        if (!id) continue;
        const sizeRaw = xmlTag(block, "AllocatedStorage");
        entries.push({
          id,
          service: input.identifierPrefix,
          engine: xmlTag(block, "Engine") ?? "postgres",
          createdAt: xmlTag(block, "SnapshotCreateTime") ?? now().toISOString(),
          status: xmlTag(block, "Status") ?? "available",
          ...(sizeRaw && /^\d+$/.test(sizeRaw) ? { sizeGb: Number(sizeRaw) } : {}),
        });
      }
      // Sort newest snapshot first.
      return entries.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
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

    /**
     * Runs an honest, isolated RDS restore drill (ADR 0034):
     * 1. Restores into private DB subnet group + VPC security group (`PubliclyAccessible=false`).
     * 2. Polls `DescribeDBInstances` until `available` to verify the restored instance actually boots.
     * 3. Deletes the throwaway instance (`SkipFinalSnapshot=true`) and polls until gone.
     * 4. Reports the true `verified` and `cleanedUp` booleans — never falsely reporting success.
     */
    async runRestoreDrill(input): Promise<ManagedCloudRestoreDrillResult> {
      const start = now().getTime();
      let verified = false;
      let cleanedUp = false;
      let detail = "";

      const restoreParams: Record<string, string> = {
        Action: "RestoreDBInstanceFromDBSnapshot",
        Version: "2014-10-31",
        DBInstanceIdentifier: input.drillInstanceId,
        DBSnapshotIdentifier: input.snapshotId,
        PubliclyAccessible: "false",
      };
      if (input.dbSubnetGroupName !== undefined) {
        restoreParams.DBSubnetGroupName = input.dbSubnetGroupName;
      }
      if (input.vpcSecurityGroupIds !== undefined) {
        input.vpcSecurityGroupIds.forEach((sg, idx) => {
          restoreParams[`VpcSecurityGroupIds.member.${idx + 1}`] = sg;
        });
      }

      let restoreStarted = false;
      try {
        await callQueryApi({
          service: "rds",
          region: input.region,
          params: restoreParams,
        });
        restoreStarted = true;

        // Poll until the throwaway instance reaches `available`.
        let lastStatus = "creating";
        for (let attempt = 0; attempt < maxPollAttempts; attempt += 1) {
          const descXml = await callQueryApi({
            service: "rds",
            region: input.region,
            params: {
              Action: "DescribeDBInstances",
              Version: "2014-10-31",
              DBInstanceIdentifier: input.drillInstanceId,
            },
          });
          lastStatus = xmlTag(descXml, "DBInstanceStatus") ?? "unknown";
          if (lastStatus === "available") {
            verified = true;
            break;
          }
          if (lastStatus === "failed" || lastStatus === "incompatible-restore") {
            detail = `Restore drill instance ${input.drillInstanceId} entered terminal state "${lastStatus}".`;
            break;
          }
          if (attempt + 1 < maxPollAttempts) await sleep(500);
        }
        if (!verified && detail === "") {
          detail = `Restore drill instance ${input.drillInstanceId} did not become available (last status: "${lastStatus}").`;
        }
      } catch (error) {
        detail = deps.redactor.redact(
          `Restore drill failed: ${error instanceof Error ? error.message : String(error)}`,
        );
      }

      if (restoreStarted) {
        // Attempt deletion only once the instance is deletable, retrying if still creating.
        let deleteIssued = false;
        let lastCleanupError = "";
        for (let attempt = 0; attempt < maxPollAttempts; attempt += 1) {
          try {
            if (!deleteIssued) {
              await callQueryApi({
                service: "rds",
                region: input.region,
                params: {
                  Action: "DeleteDBInstance",
                  Version: "2014-10-31",
                  DBInstanceIdentifier: input.drillInstanceId,
                  SkipFinalSnapshot: "true",
                },
              });
              deleteIssued = true;
            }
            // Confirm deletion via DescribeDBInstances (404 / DBInstanceNotFound means gone!).
            try {
              const checkXml = await callQueryApi({
                service: "rds",
                region: input.region,
                params: {
                  Action: "DescribeDBInstances",
                  Version: "2014-10-31",
                  DBInstanceIdentifier: input.drillInstanceId,
                },
              });
              const status = xmlTag(checkXml, "DBInstanceStatus") ?? "";
              if (status === "deleted" || status === "") {
                cleanedUp = true;
                break;
              }
            } catch (checkErr) {
              const msg = checkErr instanceof Error ? checkErr.message : String(checkErr);
              if (msg.includes("404") || msg.includes("DBInstanceNotFound")) {
                cleanedUp = true;
                break;
              }
              lastCleanupError = msg;
            }
          } catch (delErr) {
            const msg = delErr instanceof Error ? delErr.message : String(delErr);
            if (msg.includes("404") || msg.includes("DBInstanceNotFound")) {
              cleanedUp = true;
              break;
            }
            lastCleanupError = msg;
          }
          if (attempt + 1 < maxPollAttempts) await sleep(500);
        }

        if (!cleanedUp) {
          const warn = `WARNING: throwaway drill instance ${input.drillInstanceId} was NOT confirmed deleted (${deps.redactor.redact(lastCleanupError || "still present")}); delete it manually in AWS RDS console to avoid ongoing charges.`;
          detail = detail === "" ? warn : `${detail} ${warn}`;
        }
      } else {
        cleanedUp = true;
      }

      if (verified && cleanedUp) {
        detail = `Verified restore of ${input.snapshotId} into isolated private instance ${input.drillInstanceId} (available) and confirmed deletion.`;
      }

      return {
        snapshotId: input.snapshotId,
        service: input.service,
        verified,
        durationMs: Math.max(0, now().getTime() - start),
        cleanedUp,
        detail,
      };
    },
  };
}
