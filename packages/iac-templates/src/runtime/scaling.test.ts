// Feature 033 (Phase 1, T3305-T3306): copy-server Compose, WireGuard service publishing,
// consumer-aware service hosts, and multi-upstream load balancing across Caddy, nginx, and
// OpenLiteSpeed.
import { randomBytes } from "node:crypto";
import { DeployPlanSchema } from "@opscrew/plan-schema";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";
import { testContext, testPlan } from "../__fixtures__/plans";
import { appVariables, workerVariables } from "../catalog";
import { APP_COPY_PROXY_PORT, APP_KAMAL_PROXY_SERVICE, copyProxyUpstreams } from "../edge";
import { renderCompose, renderEdgeSite, renderServerCompose } from "./index";

const key = () => randomBytes(32).toString("base64");

function scaledPlan(
  overrides: {
    edge?: "caddy" | "nginx" | "openlitespeed";
    policy?: "round_robin" | "least_conn" | "ip_hash";
    pooler?: "pgbouncer";
    workers?: boolean;
    cron?: boolean;
  } = {},
) {
  const base = testPlan({ domain: "shop.example.com" });
  const db = base.services.find((s) => s.kind === "postgres");
  return DeployPlanSchema.parse({
    ...base,
    target: { ...base.target, edge: overrides.edge ?? "caddy" },
    app: { ...base.app, servers: ["web-2", "web-3"] },
    servers: [
      {
        name: "web-2",
        target: {
          provider: "hetzner",
          mode: "vps-compose",
          location: "nbg1",
          serverType: "cpx22",
          backups: false,
        },
      },
      {
        name: "web-3",
        target: { provider: "own", mode: "vps-compose", arch: "amd64" },
      },
    ],
    scaling: {
      loadBalancer: { kind: "edge", policy: overrides.policy ?? "round_robin" },
    },
    services:
      db === undefined
        ? base.services
        : [
            {
              ...db,
              options: {
                ...(db.options as Record<string, unknown>),
                ...(overrides.pooler === "pgbouncer"
                  ? { logins: "separate", pooler: "pgbouncer" }
                  : {}),
              },
            },
          ],
    processes: {
      workers:
        overrides.workers === true
          ? [
              {
                name: "worker",
                command: "node worker.js",
                source: "procfile",
                count: 2,
                servers: ["web-2"],
              },
            ]
          : [],
      cron:
        overrides.cron === true
          ? [{ name: "cleanup", schedule: "0 * * * *", command: "node cleanup.js" }]
          : [],
    },
    network: {
      range: "10.200.4.0/24",
      members: [
        { name: "app", address: "10.200.4.1", port: 51820, publicKey: key() },
        { name: "web-2", address: "10.200.4.2", port: 51820, publicKey: key() },
        { name: "web-3", address: "10.200.4.3", port: 51820, publicKey: key() },
      ],
    },
  });
}

describe("feature 033 (T3305): copy-server Compose and WireGuard service publishing", () => {
  it("publishes app-server backing services and PgBouncer on app's WireGuard IP when remote copies exist", () => {
    const plan = scaledPlan({ pooler: "pgbouncer", workers: true });
    const compose = parse(renderCompose(plan).content) as {
      services: Record<string, { ports?: string[] }>;
    };
    expect(compose.services.db?.ports).toEqual(["10.200.4.1:5432:5432"]);
    expect(compose.services["db-pooler"]?.ports).toEqual(["10.200.4.1:6432:6432"]);

    const db = plan.services[0];
    expect(db).toBeDefined();
    if (db !== undefined) {
      // On app server: uses internal Compose DNS (db-pooler).
      const onApp = appVariables({ plan, service: db, secretRef: (n) => `<${n}>` });
      expect(onApp.DATABASE_URL).toContain("@db-pooler:6432/");
      // On remote web-2 copy server: reaches app server's PgBouncer via app's WireGuard IP.
      const onCopy = appVariables({
        plan,
        service: db,
        secretRef: (n) => `<${n}>`,
        consumerServer: "web-2",
      });
      expect(onCopy.DATABASE_URL).toContain("@10.200.4.1:6432/");
      // Remote workers reach Postgres directly on app's WireGuard IP (5432, bypassing PgBouncer).
      const remoteWorkers = workerVariables(plan, (_s, n) => `<${n}>`, "web-2");
      expect(remoteWorkers.DATABASE_URL).toContain("@10.200.4.1:5432/");
    }
  });

  it("renders copy-server Compose with app, WG-only app-proxy, placed workers, and never release or cron", () => {
    const plan = scaledPlan({ workers: true, cron: true });
    const web2 = parse(renderServerCompose(plan, "web-2").content) as {
      services: Record<string, Record<string, unknown>>;
      volumes?: Record<string, unknown>;
    };
    expect(Object.keys(web2.services).sort()).toEqual(["app", APP_KAMAL_PROXY_SERVICE, "worker"]);
    expect(web2.services.release).toBeUndefined();
    expect(web2.services.cron).toBeUndefined();
    expect(web2.services[APP_KAMAL_PROXY_SERVICE]?.ports).toEqual([
      `10.200.4.2:${APP_COPY_PROXY_PORT}:80`,
    ]);
    expect(web2.volumes).toHaveProperty("kamal-proxy-config");

    // web-3 has no worker placed on it, only web copy.
    const web3 = parse(renderServerCompose(plan, "web-3").content) as {
      services: Record<string, Record<string, unknown>>;
    };
    expect(Object.keys(web3.services).sort()).toEqual(["app", APP_KAMAL_PROXY_SERVICE]);
    expect(web3.services[APP_KAMAL_PROXY_SERVICE]?.ports).toEqual([
      `10.200.4.3:${APP_COPY_PROXY_PORT}:80`,
    ]);
  });
});

describe("feature 033 (T3306): multi-upstream load balancing across Caddy, nginx, and OpenLiteSpeed", () => {
  it("renders Caddy reverse_proxy with WireGuard copy upstreams, policy, active health checks, and Host header", () => {
    const plan = scaledPlan({ edge: "caddy", policy: "least_conn" });
    expect(copyProxyUpstreams(plan)).toEqual([
      `10.200.4.2:${APP_COPY_PROXY_PORT}`,
      `10.200.4.3:${APP_COPY_PROXY_PORT}`,
    ]);
    const site = renderEdgeSite(plan, testContext())[0]?.content ?? "";
    expect(site).toContain(
      `reverse_proxy ${plan.app.name}-kamal-proxy:80 10.200.4.2:${APP_COPY_PROXY_PORT} 10.200.4.3:${APP_COPY_PROXY_PORT} {`,
    );
    expect(site).toContain("lb_policy least_conn");
    expect(site).toContain(`health_uri ${plan.app.healthPath}`);
    expect(site).toContain("health_headers {");
    expect(site).toContain(`Host ${plan.dns.domain}`);
    expect(site).toContain("fail_duration 30s");
    expect(site).toContain("max_fails 2");
  });

  it("uses Caddy client_ip_hash when ip_hash is selected behind Cloudflare real-IP", () => {
    const base = scaledPlan({ edge: "caddy", policy: "ip_hash" });
    const proxied = DeployPlanSchema.parse({
      ...base,
      dns: { ...base.dns, proxied: true },
    });
    const site =
      renderEdgeSite(proxied, testContext({ cloudflareRanges: ["173.245.48.0/20"] }))[0]?.content ??
      "";
    expect(site).toContain("lb_policy client_ip_hash");
    expect(site).not.toContain("lb_policy ip_hash");
  });

  it("renders nginx upstream with policy, local + WG copy servers, and proxy_next_upstream", () => {
    const plan = scaledPlan({ edge: "nginx", policy: "ip_hash" });
    const site = renderEdgeSite(plan, testContext())[0]?.content ?? "";
    expect(site).toContain(`upstream ${plan.app.name}-kamal-proxy {`);
    expect(site).toContain("\tip_hash;");
    expect(site).toContain(
      `\tserver ${plan.app.name}-kamal-proxy:80 resolve max_fails=2 fail_timeout=30s;`,
    );
    expect(site).toContain(
      `\tserver 10.200.4.2:${APP_COPY_PROXY_PORT} max_fails=2 fail_timeout=30s;`,
    );
    expect(site).toContain(
      `\tserver 10.200.4.3:${APP_COPY_PROXY_PORT} max_fails=2 fail_timeout=30s;`,
    );
    expect(site).toContain("proxy_next_upstream error timeout http_502 http_503 http_504;");
  });

  it("renders OpenLiteSpeed per-copy proxy extprocessors behind a loadbalancer processor", () => {
    const plan = scaledPlan({ edge: "openlitespeed" });
    const vhconf = renderEdgeSite(plan, testContext())[0]?.content ?? "";
    const alias = `${plan.app.name}-kamal-proxy`;
    expect(vhconf).toContain(`extprocessor ${alias}-0 {`);
    expect(vhconf).toContain(`extprocessor ${alias}-1 {`);
    expect(vhconf).toContain(`extprocessor ${alias}-2 {`);
    expect(vhconf).toContain(`10.200.4.2:${APP_COPY_PROXY_PORT}`);
    expect(vhconf).toContain(`10.200.4.3:${APP_COPY_PROXY_PORT}`);
    expect(vhconf).toContain(`extprocessor ${alias} {`);
    expect(vhconf).toContain("type                    loadbalancer");
    expect(vhconf).toContain(`proxy::${alias}-0, proxy::${alias}-1, proxy::${alias}-2`);
    expect(vhconf).toContain("context / {");
  });
});
