// Feature 033 (T3311 & T3312): provision deploy secrets, WireGuard network filter rules, status
// component reporting, drift expectations, verify checks, and multi-copy secret rotation.
import {
  APP_COPY_PROXY_PORT,
  APP_KAMAL_PROXY_SERVICE,
  copyServerEnvSecrets,
  publishedOnNetwork,
} from "@opscrew/iac-templates";
import { APP_SERVER, DeployPlanSchema, writeArtifact } from "@opscrew/plan-schema";
import { describe, expect, it } from "vitest";
import { pgBouncerScaling } from "../design/scaling";
import { networkFilterRules } from "../network";
import { databaseStep } from "../rollback/database";
import { serverRuns, serviceSteps } from "../rotate/plan";
import { assembleAppEnv, copyServerAppEnv } from "../shared";
import { restoreSnapshot } from "../snapshot/restore";
import { componentStatus, componentStatusLines } from "../status/components";
import { serviceWords } from "../status/network";
import { createTestPhaseDeps, testPlan } from "../testing";
import { deploySecretNames, deploySecrets } from "./secrets";

const WG_KEY = (n: number) => `${String(n).repeat(42)}A=`;

function scaledPlan(options: { withHybridCache?: boolean; withPooler?: boolean } = {}) {
  const base = testPlan({ deployed: true });
  return DeployPlanSchema.parse({
    ...base,
    app: { ...base.app, servers: ["web-2"] },
    servers: [
      {
        name: "web-2",
        target: {
          provider: "hetzner",
          mode: "vps-compose",
          location: "nbg1",
          serverType: "cx23",
          backups: true,
        },
      },
      {
        name: "worker-1",
        target: {
          provider: "own",
          mode: "vps-compose",
          arch: "amd64",
        },
      },
    ],
    services: [
      {
        name: "db",
        kind: "postgres",
        version: "17",
        enabled: true,
        memoryMb: 512,
        reason: "Primary database",
        licence: "PostgreSQL",
        options: options.withPooler
          ? { logins: "separate" as const, pooler: "pgbouncer" as const }
          : {},
      },
      ...(options.withHybridCache
        ? [
            {
              name: "cache",
              kind: "valkey" as const,
              version: "8",
              enabled: true,
              memoryMb: 128,
              reason: "Session cache",
              licence: "BSD-3-Clause",
              options: { mode: "cache" as const },
              server: "web-2",
            },
          ]
        : []),
    ],
    processes: {
      workers: [
        {
          name: "jobs",
          command: "node worker.js",
          source: "procfile" as const,
          enabled: true,
          count: 1,
          single: false,
          stopGraceSeconds: 30,
          memoryMb: 256,
          servers: ["worker-1"],
        },
      ],
      cron: [],
    },
    network: {
      range: "10.200.4.0/24",
      members: [
        { name: APP_SERVER, address: "10.200.4.1", port: 51820, publicKey: WG_KEY(1) },
        { name: "web-2", address: "10.200.4.2", port: 51820, publicKey: WG_KEY(2) },
        { name: "worker-1", address: "10.200.4.3", port: 51820, publicKey: WG_KEY(3) },
      ],
      devices: [
        {
          name: "laptop",
          address: "10.200.4.10",
          publicKey: WG_KEY(9),
          addedAt: "2026-10-01T00:00:00Z",
        },
      ],
      grants: [{ device: "laptop", service: "db", access: "read-only" }],
    },
  });
}

describe("033 provision deploy secrets & WireGuard network filter (T3311)", () => {
  it("renders per-copy-server app.env and worker.db.env with WireGuard addresses and Docker DNS for local services", async () => {
    const plan = scaledPlan({ withPooler: true, withHybridCache: true });
    const env = await assembleAppEnv({
      plan,
      dotenvText: "STRIPE_SECRET_KEY=test-val\n",
      password: () => "generated-pw-1234",
    });

    // Primary server reaches local db-pooler over Docker DNS and remote cache over web-2's WG IP.
    expect(env.appEnv).toContain("@db-pooler:6432/");
    expect(env.appEnv).toContain("@10.200.4.2:6379");

    // web-2 reaches APP_SERVER's db-pooler over APP_SERVER's WG IP and local cache over Docker DNS.
    const web2Env = copyServerAppEnv(plan, env, "web-2");
    expect(web2Env).toContain("@10.200.4.1:6432/");
    expect(web2Env).toContain("@cache:6379");

    // worker-1 reaches both db-pooler (APP_SERVER) and cache (web-2) over WG IPs.
    const worker1Env = copyServerAppEnv(plan, env, "worker-1");
    expect(worker1Env).toContain("@10.200.4.1:6432/");
    expect(worker1Env).toContain("@10.200.4.2:6379");

    const secrets = deploySecrets({
      plan,
      host: "198.51.100.1",
      privateKey: "key",
      knownHosts: "known",
      environment: env,
    });
    expect(secrets[copyServerEnvSecrets("web-2").appEnv]).toBe(web2Env);
    expect(secrets[copyServerEnvSecrets("web-2").workerDbEnv]).toBeUndefined();
    expect(secrets[copyServerEnvSecrets("worker-1").appEnv]).toBe(worker1Env);
    expect(secrets[copyServerEnvSecrets("worker-1").workerDbEnv]).toContain("@10.200.4.1:5432/");

    // destroy cleanup lists copy-server env secrets too.
    const allNames = deploySecretNames(plan);
    expect(allNames).toContain(copyServerEnvSecrets("web-2").appEnv);
    expect(allNames).toContain(copyServerEnvSecrets("worker-1").workerDbEnv);
  });

  it("admits copy servers to backing services and admits only APP_SERVER to copy app-proxy:18090", () => {
    const plan = scaledPlan({ withPooler: true });

    const appPublished = publishedOnNetwork(plan, APP_SERVER);
    expect(appPublished.map((p) => `${p.service}:${p.port}`)).toEqual([
      "db:5432",
      "db-pooler:6432",
    ]);
    const appRules = networkFilterRules(plan, APP_SERVER, appPublished);
    const dbRule = appRules.find((r) => r.port === 5432);
    // APP_SERVER + copy servers web-2 & worker-1 + granted device laptop.
    expect(dbRule?.sources).toEqual(["10.200.4.1", "10.200.4.2", "10.200.4.3", "10.200.4.10"]);
    const poolerRule = appRules.find((r) => r.port === 6432);
    expect(poolerRule?.sources).toEqual(["10.200.4.1", "10.200.4.2", "10.200.4.3"]);

    const web2Published = publishedOnNetwork(plan, "web-2");
    expect(web2Published).toEqual([
      { service: APP_KAMAL_PROXY_SERVICE, port: APP_COPY_PROXY_PORT, address: "10.200.4.2" },
    ]);
    const web2Rules = networkFilterRules(plan, "web-2", web2Published);
    // Only APP_SERVER (10.200.4.1) may reach web-2's app-proxy:18090 — never devices or worker-1.
    expect(web2Rules).toEqual([{ port: APP_COPY_PROXY_PORT, sources: ["10.200.4.1"] }]);
  });
});

describe("033 status, verify & multi-copy rotation (T3312)", () => {
  it("reports web copy + app-proxy health on web-2 and worker copy on worker-1", () => {
    const plan = scaledPlan();
    expect(serviceWords(plan, APP_KAMAL_PROXY_SERVICE)).toBe("The app proxy");

    const healthyWeb2 = componentStatus(
      plan,
      [
        { service: "app", running: true, networks: ["shop_internal"] },
        { service: APP_KAMAL_PROXY_SERVICE, running: true, networks: ["shop_internal"] },
      ],
      "web-2",
    );
    expect(healthyWeb2.components).toEqual([
      { service: "app", what: "the web process", containers: 1, running: 1 },
    ]);
    expect(healthyWeb2.others).toEqual([]);
    expect(healthyWeb2.missingAppProxy).toBeUndefined();

    const missingProxyWeb2 = componentStatus(
      plan,
      [{ service: "app", running: true, networks: ["shop_internal"] }],
      "web-2",
    );
    expect(missingProxyWeb2.missingAppProxy).toBe(true);
    expect(componentStatusLines(plan, missingProxyWeb2, "web-2").join("\n")).toContain(
      "Proxy (app-proxy): not running",
    );

    const healthyWorker1 = componentStatus(
      plan,
      [{ service: "jobs", running: true, networks: ["shop_internal"] }],
      "worker-1",
    );
    expect(healthyWorker1.components).toEqual([
      { service: "jobs", what: "the worker", containers: 1, running: 1 },
    ]);
    expect(healthyWorker1.others).toEqual([]);
    expect(healthyWorker1.missingAppProxy).toBeUndefined();
  });

  it("includes copy servers in rotate serverRuns with split begin/switch/finish scripts", () => {
    const plan = scaledPlan({ withPooler: true, withHybridCache: true });
    const steps = serviceSteps(plan, plan.services);
    const runs = serverRuns(plan, steps);
    expect(runs.map((r) => r.server)).toEqual([APP_SERVER, "web-2", "worker-1"]);
    expect(runs[0]?.script).toContain("begin | finish)");
    expect(runs[1]?.script).toContain("begin | switch | finish)");
    expect(runs[2]?.script).toContain("begin | finish)");
  });

  it("enables PgBouncer on PostgreSQL for worker-only remote copies too (033)", () => {
    const base = scaledPlan();
    const { servers: _webServers, ...appWithoutServers } = base.app;
    const workerOnly = DeployPlanSchema.parse({
      ...base,
      app: appWithoutServers,
      servers: (base.servers ?? []).filter((s) => s.name === "worker-1"),
      network: {
        range: base.network?.range ?? "10.200.4.0/24",
        members: (base.network?.members ?? []).filter((m) => m.name !== "web-2"),
      },
    });
    const out = pgBouncerScaling(workerOnly);
    expect(out.plan.services[0]?.options).toMatchObject({
      logins: "separate",
      pooler: "pgbouncer",
    });
    expect(out.lines[0]).toContain("2 app/worker servers");
  });

  it("refuses in-place snapshot restores and database-mutating rollbacks while remote copies run (033)", async () => {
    const deps = await createTestPhaseDeps();
    const base = scaledPlan();
    const plan = DeployPlanSchema.parse({
      ...base,
      deploy: { ...base.deploy, snapshots: true },
    });
    await writeArtifact("plan", deps.paths.files.plan, plan);

    await expect(restoreSnapshot(deps, "20261127T120000Z")).rejects.toThrow(
      /runs app copies on web-2 and worker-1, which would keep serving and writing to the database/,
    );

    const run = {
      deps,
      plan,
      environment: "prod",
      flags: "",
      command: "opscrew rollback",
      options: { database: "snapshot" as const },
      services: {},
    };
    await expect(
      databaseStep(run, {
        current:
          "ghcr.io/a/b@sha256:1111111111111111111111111111111111111111111111111111111111111111",
        target:
          "ghcr.io/a/b@sha256:2222222222222222222222222222222222222222222222222222222222222222",
        words: "the earlier version",
      }),
    ).rejects.toThrow(/runs app copies on web-2 and worker-1/);

    const keepStep = await databaseStep(
      { ...run, options: { database: "keep" } },
      {
        current:
          "ghcr.io/a/b@sha256:1111111111111111111111111111111111111111111111111111111111111111",
        target:
          "ghcr.io/a/b@sha256:2222222222222222222222222222222222222222222222222222222222222222",
        words: "the earlier version",
      },
    );
    expect(keepStep.choice).toBe("keep");
  });
});
