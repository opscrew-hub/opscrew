import type { FetchLike, ProviderRedactor } from "@opscrew/contracts";
import { describe, expect, it } from "vitest";
import { createAwsConnector, signAwsV4Request } from "./connector";

function makeFakeRedactor(): ProviderRedactor & { literals: string[] } {
  const literals: string[] = [];
  return {
    literals,
    addLiteral(value: string) {
      literals.push(value);
    },
    redact(text: string) {
      let out = text;
      for (const lit of literals) out = out.replaceAll(lit, "[REDACTED]");
      return out;
    },
    redactDeep<T>(value: T): T {
      return value;
    },
  };
}

describe("034 AWS SigV4 connector (T3407)", () => {
  it("computes deterministic AWS4-HMAC-SHA256 Authorization headers with RFC 3986 encoding", () => {
    const headers = signAwsV4Request({
      method: "POST",
      url: "https://sts.us-east-1.amazonaws.com/?Filter=a!b'c(d)e*f",
      service: "sts",
      region: "us-east-1",
      body: "Action=GetCallerIdentity&Version=2011-06-15",
      credentials: { accessKeyId: "test-key", secretAccessKey: "test-secret" },
      now: new Date("2026-11-27T12:00:00.000Z"),
    });
    expect(headers["x-amz-date"]).toBe("20261127T120000Z");
    expect(headers.authorization).toMatch(
      /^AWS4-HMAC-SHA256 Credential=test-key\/20261127\/us-east-1\/sts\/aws4_request, SignedHeaders=.*, Signature=[0-9a-f]{64}$/,
    );
  });

  it("verifies credentials, reads ECS status & redacted CloudWatch logs, lists sorted snapshots, writes secrets out-of-band, and runs honest isolated restore drills", async () => {
    const calls: Array<{ url: string; target?: string; body: string }> = [];
    let drillDeleted = false;
    const fetch: FetchLike = async (url, init) => {
      const headers = (init?.headers ?? {}) as Record<string, string>;
      const body = String(init?.body ?? "");
      calls.push({ url: String(url), target: headers["x-amz-target"], body });

      if (body.includes("Action=GetCallerIdentity")) {
        return new Response(
          "<GetCallerIdentityResponse><GetCallerIdentityResult><Account>123456789012</Account><Arn>arn:aws:iam::123456789012:role/deploy</Arn></GetCallerIdentityResult></GetCallerIdentityResponse>",
          { status: 200 },
        );
      }
      if (body.includes("Action=DescribeDBSnapshots")) {
        return new Response(
          `<DescribeDBSnapshotsResponse><DescribeDBSnapshotsResult><DBSnapshots>
            <DBSnapshot><DBSnapshotIdentifier>snap-old</DBSnapshotIdentifier><Engine>postgres</Engine><SnapshotCreateTime>2026-11-25T10:00:00Z</SnapshotCreateTime><Status>available</Status></DBSnapshot>
            <DBSnapshot><DBSnapshotIdentifier>snap-new</DBSnapshotIdentifier><Engine>postgres</Engine><SnapshotCreateTime>2026-11-27T10:00:00Z</SnapshotCreateTime><Status>available</Status></DBSnapshot>
          </DBSnapshots></DescribeDBSnapshotsResult></DescribeDBSnapshotsResponse>`,
          { status: 200 },
        );
      }
      if (body.includes("Action=DeleteDBInstance")) {
        drillDeleted = true;
        return new Response("<DeleteDBInstanceResponse/>", { status: 200 });
      }
      if (body.includes("Action=DescribeDBInstances")) {
        if (drillDeleted) {
          return new Response("<Error><Code>DBInstanceNotFound</Code></Error>", { status: 404 });
        }
        return new Response(
          "<DescribeDBInstancesResponse><DBInstance><DBInstanceStatus>available</DBInstanceStatus></DBInstance></DescribeDBInstancesResponse>",
          { status: 200 },
        );
      }
      if (headers["x-amz-target"]?.includes("DescribeServices")) {
        return new Response(
          JSON.stringify({ services: [{ status: "ACTIVE", desiredCount: 2, runningCount: 2 }] }),
          { status: 200 },
        );
      }
      if (headers["x-amz-target"]?.includes("FilterLogEvents")) {
        return new Response(
          JSON.stringify({
            events: [
              {
                timestamp: 1795780800000,
                logStreamName: "app/web/1",
                message: "Connected with secret-token-value-12345",
              },
            ],
          }),
          { status: 200 },
        );
      }
      if (headers["x-amz-target"] !== undefined) {
        return new Response("{}", { status: 200 });
      }
      return new Response("<ok/>", { status: 200 });
    };

    const redactor = makeFakeRedactor();
    const connector = createAwsConnector({
      fetch,
      env: {
        AWS_ACCESS_KEY_ID: "test-access-key",
        AWS_SECRET_ACCESS_KEY: "test-secret-key",
        AWS_ENDPOINT_URL: "http://localhost:4566",
      },
      redactor,
      now: () => new Date("2026-11-27T12:00:00.000Z"),
      sleep: async () => undefined,
      maxPollAttempts: 3,
    });

    // Destructured verifyCredentials must still work (no `this` binding issue).
    const { verifyCredentials } = connector;
    const id = await verifyCredentials();
    expect(id).toEqual({
      ok: true,
      accountId: "123456789012",
      principalArn: "arn:aws:iam::123456789012:role/deploy",
    });
    expect(calls[0]?.url).toBe("http://localhost:4566/");

    const snaps = await connector.listSnapshots({
      region: "us-east-1",
      identifierPrefix: "opscrew-shop-prod",
    });
    expect(snaps.map((s) => s.id)).toEqual(["snap-new", "snap-old"]);

    const status = await connector.readStatus({
      appName: "shop",
      environment: "prod",
      region: "us-east-1",
      computeKind: "ecs-fargate",
    });
    expect(status.healthy).toBe(true);
    expect(status.compute.runningCount).toBe(2);

    await connector.writeSecrets({
      region: "us-east-1",
      secrets: [
        {
          store: "secrets-manager",
          name: "opscrew/shop/prod/app-env",
          value: "secret-token-value-12345",
        },
        { store: "ssm-parameter", name: "/opscrew/shop/prod/app-env", value: "another-secret-val" },
      ],
    });
    expect(redactor.literals).toContain("secret-token-value-12345");

    const logs = await connector.readLogs({
      logGroup: "/opscrew/shop/prod/app",
      region: "us-east-1",
    });
    expect(logs[0]?.message).toBe("Connected with [REDACTED]");

    const drill = await connector.runRestoreDrill({
      region: "us-east-1",
      snapshotId: "snap-new",
      service: "db",
      drillInstanceId: "opscrew-drill-1",
      dbSubnetGroupName: "opscrew-shop-prod-db",
      vpcSecurityGroupIds: ["sg-private-db"],
    });
    expect(drill.verified).toBe(true);
    expect(drill.cleanedUp).toBe(true);
    expect(
      calls.some(
        (c) =>
          c.body.includes("Action=RestoreDBInstanceFromDBSnapshot") &&
          c.body.includes("PubliclyAccessible=false") &&
          c.body.includes("DBSubnetGroupName=opscrew-shop-prod-db"),
      ),
    ).toBe(true);
    expect(
      calls.some(
        (c) =>
          c.body.includes("Action=DeleteDBInstance") && c.body.includes("SkipFinalSnapshot=true"),
      ),
    ).toBe(true);
  });

  it("reports verified=false and cleanedUp=false honestly when drill instance stays stuck in creating and delete fails (Blocker #6)", async () => {
    const fetch: FetchLike = async (_url, init) => {
      const body = String(init?.body ?? "");
      if (body.includes("Action=RestoreDBInstanceFromDBSnapshot")) {
        return new Response("<RestoreDBInstanceFromDBSnapshotResponse/>", { status: 200 });
      }
      if (body.includes("Action=DescribeDBInstances")) {
        return new Response(
          "<DescribeDBInstancesResponse><DBInstance><DBInstanceStatus>creating</DBInstanceStatus></DBInstance></DescribeDBInstancesResponse>",
          { status: 200 },
        );
      }
      if (body.includes("Action=DeleteDBInstance")) {
        return new Response("<Error><Code>InvalidDBInstanceState</Code></Error>", { status: 400 });
      }
      return new Response("<ok/>", { status: 200 });
    };

    const connector = createAwsConnector({
      fetch,
      env: { AWS_ACCESS_KEY_ID: "k", AWS_SECRET_ACCESS_KEY: "s" },
      redactor: makeFakeRedactor(),
      now: () => new Date("2026-11-27T12:00:00.000Z"),
      sleep: async () => undefined,
      maxPollAttempts: 2,
    });

    const drill = await connector.runRestoreDrill({
      region: "us-east-1",
      snapshotId: "snap-1",
      service: "db",
      drillInstanceId: "opscrew-drill-stuck",
    });
    expect(drill.verified).toBe(false);
    expect(drill.cleanedUp).toBe(false);
    expect(drill.detail).toContain("NOT confirmed deleted");
  });
});
