// biome-ignore-all lint/suspicious/noTemplateCurlyInString: bash and GitHub Actions syntax, not JavaScript templates.
// Feature 033 (T3307 & T3308): serial 1-by-1 rolling deploy, rollback, and secret rotation across
// web and worker copy servers, keeping single-copy workflows unchanged.
import { spawnSync } from "node:child_process";
import { APP_SERVER, DeployPlanSchema } from "@opscrew/plan-schema";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";
import { testContext, testPlan } from "../__fixtures__/plans";
import { withMonitoring } from "./__fixtures__/plans";
import { shWorks } from "./__fixtures__/sh";
import {
  copyServerEnvSecrets,
  copyServerPrepullCommands,
  copyServerRollbackCommands,
  copyServerSwitchCommands,
  deploySecretNamesFor,
  maskFileScript,
  renderWorkflow,
} from "./index";
import { type RotateStep, renderRotateScript, rotateEnvFiles } from "./rotate";

const WG_KEY = (n: number) => `${String(n).repeat(42)}A=`;

type Step = { id?: string; name?: string; if?: string; run?: string; env?: Record<string, string> };

function scaledPlan(
  options: {
    withPooler?: boolean;
    withWorkerCopy?: boolean;
    withHybridCache?: boolean;
    monitoring?: boolean;
  } = {},
) {
  const base = testPlan({ domain: "shop.example.com" });
  const servers: NonNullable<typeof base.servers> = [
    {
      name: "web-2",
      target: {
        provider: "hetzner",
        mode: "vps-compose",
        location: "fsn1",
        serverType: "cx22",
        backups: false,
      },
    },
    ...(options.withWorkerCopy
      ? [
          {
            name: "worker-1",
            target: {
              provider: "own" as const,
              mode: "vps-compose" as const,
              arch: "amd64" as const,
            },
          },
        ]
      : []),
  ];
  const members = [
    { name: APP_SERVER, address: "10.200.0.1", port: 51820, publicKey: WG_KEY(1) },
    { name: "web-2", address: "10.200.0.2", port: 51820, publicKey: WG_KEY(2) },
    ...(options.withWorkerCopy
      ? [{ name: "worker-1", address: "10.200.0.3", port: 51820, publicKey: WG_KEY(3) }]
      : []),
  ];
  return DeployPlanSchema.parse({
    ...base,
    app: { ...base.app, servers: ["web-2"] },
    servers,
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
      workers: options.withWorkerCopy
        ? [
            {
              name: "jobs",
              command: "node worker.js",
              source: "procfile" as const,
              enabled: true,
              count: 1,
              memoryMb: 256,
              servers: ["worker-1"],
            },
          ]
        : [],
      cron: [],
    },
    network: {
      range: "10.200.0.0/24",
      members,
    },
  });
}

function monitoredScaledPlan(options: Parameters<typeof scaledPlan>[0] = {}) {
  return withMonitoring(scaledPlan(options));
}

function deploySteps(plan: ReturnType<typeof scaledPlan>): Step[] {
  const wf = parse(renderWorkflow(plan, testContext()).content) as {
    jobs: { deploy: { steps: Step[] } };
  };
  return wf.jobs.deploy.steps;
}

describe("033 copy-server deploy secrets & serial rolling workflow (T3307)", () => {
  it("lists per-copy-server app.env and optional worker.db.env deploy secrets", () => {
    const plan = scaledPlan({ withPooler: true, withWorkerCopy: true });
    const names = deploySecretNamesFor(plan);
    expect(names).toContain(copyServerEnvSecrets("web-2").appEnv);
    expect(names).not.toContain(copyServerEnvSecrets("web-2").workerDbEnv);
    expect(names).toContain(copyServerEnvSecrets("worker-1").appEnv);
    expect(names).toContain(copyServerEnvSecrets("worker-1").workerDbEnv);
    expect(names).toContain("OPSCREW_SERVER_WEB_2_HOST");
    expect(names).toContain("OPSCREW_SERVER_WORKER_1_HOST");
  });

  it("orders SSH setup -> prepull -> app start -> serial copy switches -> health -> rollback", () => {
    const plan = scaledPlan({ withPooler: true, withWorkerCopy: true });
    const steps = deploySteps(plan);
    const ids = steps.map((s) => s.id ?? s.name);
    const at = (label: string) => ids.indexOf(label);

    expect(at("Configure SSH for the app's other servers")).toBeGreaterThan(-1);
    expect(at("Prepare and pre-pull on copy server web-2")).toBeGreaterThan(
      at("Configure SSH for the app's other servers"),
    );
    expect(at("Prepare and pre-pull on copy server worker-1")).toBeGreaterThan(
      at("Prepare and pre-pull on copy server web-2"),
    );
    expect(at("start")).toBeGreaterThan(at("Prepare and pre-pull on copy server worker-1"));
    expect(at("copy_web_2")).toBeGreaterThan(at("start"));
    expect(at("copy_worker_1")).toBeGreaterThan(at("copy_web_2"));
    expect(at("health")).toBeGreaterThan(at("copy_worker_1"));
    expect(at("Roll back to the previous version")).toBeGreaterThan(at("health"));

    const rollback = steps[at("Roll back to the previous version")];
    expect(rollback?.if).toContain("steps.copy_web_2.outcome == 'failure'");
    expect(rollback?.if).toContain("steps.copy_worker_1.outcome == 'cancelled'");
    expect(rollback?.env).toHaveProperty("SERVER_HOST_WEB_2");
    expect(rollback?.env).toHaveProperty("SERVER_HOST_WORKER_1");
    expect(rollback?.run).toContain("for server in worker-1 web-2; do");
  });

  it("handles hybrid servers (backing service + web copy) without starting app prematurely", () => {
    const plan = scaledPlan({ withHybridCache: true });
    const steps = deploySteps(plan);
    const updateCache = steps.find((s) => s.name === "Update the services on the server web-2");
    expect(updateCache).toBeDefined();
    expect(updateCache?.env).toHaveProperty("OPSCREW_SERVER_WEB_2_APP_ENV");
    expect(updateCache?.env).toHaveProperty("IMAGE");
    expect(updateCache?.run).toContain("docker compose pull cache");
    expect(updateCache?.run).toContain("docker compose up -d --no-deps --wait cache");
    expect(updateCache?.run).not.toContain("docker compose up -d --wait --remove-orphans");

    const prepull = steps.find((s) => s.name === "Prepare and pre-pull on copy server web-2");
    expect(prepull).toBeDefined();
    // Hybrid server already uploaded compose.yaml & app.env in the service update step.
    expect(prepull?.run).not.toContain("scp ");
    expect(prepull?.run).toContain("docker compose pull app app-proxy");
  });

  it("includes copy-server app.env in maskFileScript when monitoring is enabled", () => {
    const plan = monitoredScaledPlan({ withPooler: true, withWorkerCopy: true });
    const webMask = maskFileScript(plan, "web-2");
    expect(webMask).toContain("app.env");
    expect(webMask).not.toContain("worker.db.env");
    const workerMask = maskFileScript(plan, "worker-1");
    expect(workerMask).toContain("app.env");
    expect(workerMask).toContain("worker.db.env");
  });

  it.skipIf(!shWorks())(
    "generates POSIX-valid shell scripts for prepull, switch, and rollback",
    () => {
      const plan = scaledPlan({ withPooler: true, withWorkerCopy: true });
      const scripts = [
        copyServerPrepullCommands(plan, "web-2"),
        copyServerPrepullCommands(plan, "worker-1"),
        copyServerSwitchCommands(plan, "web-2"),
        copyServerSwitchCommands(plan, "worker-1"),
        copyServerRollbackCommands(plan, "web-2"),
        copyServerRollbackCommands(plan, "worker-1"),
      ];
      for (const lines of scripts) {
        const res = spawnSync("sh", ["-n"], { input: `${lines.join("\n")}\n`, encoding: "utf8" });
        expect(res.status, res.stderr).toBe(0);
      }
      const webSwitch = copyServerSwitchCommands(plan, "web-2").join("\n");
      expect(webSwitch).toContain("docker compose port app-proxy 80");
      expect(webSwitch).toContain("kamal-proxy list");
      expect(webSwitch).toContain("if command -v curl > /dev/null 2>&1; then");
      expect(webSwitch).toContain("http://10.200.0.2:18090/api/health");
      expect(webSwitch).toContain("Host: shop.example.com");
      expect(webSwitch).not.toContain("opscrew-edge");

      const workerSwitch = copyServerSwitchCommands(plan, "worker-1").join("\n");
      expect(workerSwitch).not.toContain("app-proxy");
      expect(workerSwitch).toContain("docker compose up -d --no-deps jobs");
    },
  );

  it("refuses database-mutating rollbacks in switchCommands and rolls back copies even when DB put-back gets stuck", () => {
    const base = scaledPlan({ withWorkerCopy: true });
    const withRemoteDb = DeployPlanSchema.parse({
      ...base,
      deploy: { ...base.deploy, snapshots: true },
      servers: [
        ...(base.servers ?? []),
        {
          name: "db-box",
          target: {
            provider: "hetzner",
            mode: "vps-compose",
            location: "fsn1",
            serverType: "cx22",
            backups: false,
          },
        },
      ],
      services: base.services.map((s) => ({ ...s, server: "db-box" })),
      network: {
        range: base.network?.range ?? "10.200.0.0/24",
        members: [
          ...(base.network?.members ?? []),
          { name: "db-box", address: "10.200.0.4", port: 51820, publicKey: WG_KEY(4) },
        ],
      },
    });
    const steps = deploySteps(withRemoteDb);
    const start = steps.find((s) => s.id === "start");
    expect(start?.run).toContain(
      "This environment runs copies across several servers, which would keep serving while the database changes",
    );
    const rollback = steps.find((s) => s.name === "Roll back to the previous version");
    expect(rollback?.run).toContain("copy_server_sh()");
    // Copy rollback runs both on the stuck DB put-back path and on the normal rollback path.
    const matches = rollback?.run?.match(/copy_server_sh "\$server"/g) ?? [];
    expect(matches.length).toBe(2);
  });
});

describe("033 secret rotation across copy servers (T3308)", () => {
  const dbStep: RotateStep = {
    service: "db",
    envFile: "db.env",
    mode: "swap",
    begin: [["sh", "-c", "change"]],
    finish: [],
    recreate: false,
  };
  const cacheStep: RotateStep = {
    service: "cache",
    envFile: "cache.env",
    mode: "dual",
    begin: [["sh", "-c", "add"]],
    finish: [["sh", "-c", "drop"]],
    recreate: false,
  };

  it("includes app.env and optional worker.db.env in rotateEnvFiles on copy servers", () => {
    const plan = scaledPlan({ withPooler: true, withWorkerCopy: true });
    expect(rotateEnvFiles(plan, [], "web-2")).toEqual(["app.env"]);
    expect(rotateEnvFiles(plan, [], "worker-1")).toEqual(["app.env", "worker.db.env"]);
  });

  it.skipIf(!shWorks())(
    "uses split begin/finish on APP_SERVER and pure copies, and begin/switch/finish on hybrid copies",
    () => {
      const plan = scaledPlan({ withPooler: true, withWorkerCopy: true, withHybridCache: true });

      const appScript = renderRotateScript(plan, [dbStep], APP_SERVER).join("\n");
      expect(appScript).toContain("begin | finish)");
      expect(appScript).toContain("switching the app to the new values");

      const hybridScript = renderRotateScript(plan, [cacheStep], "web-2").join("\n");
      expect(hybridScript).toContain("begin | switch | finish)");
      expect(hybridScript).toContain("10.200.0.2:18090");

      const pureCopyScript = renderRotateScript(plan, [], "worker-1").join("\n");
      expect(pureCopyScript).toContain("begin | finish)");
      expect(pureCopyScript).toContain("worker.db.env");
      expect(pureCopyScript).not.toContain("app-proxy");

      for (const script of [appScript, hybridScript, pureCopyScript]) {
        const res = spawnSync("sh", ["-n"], { input: `${script}\n`, encoding: "utf8" });
        expect(res.status, res.stderr).toBe(0);
      }
    },
  );
});
