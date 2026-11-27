import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { FetchLike } from "@opscrew/contracts";
import { findExecutable } from "@opscrew/core";
import { fakeSecret } from "@opscrew/core/testing";
import { DEPLOY_SECRETS } from "@opscrew/iac-templates";
import { DeployPlanSchema } from "@opscrew/plan-schema";
import { describe, expect, it } from "vitest";
import {
  createProject,
  createTestPhaseDeps,
  FakeEngine,
  FakeGitHub,
  projectRunner,
  readyRemote,
  ScriptedApprovalHandler,
  SERVER_IPV4,
  SERVER_IPV6,
  testPlan,
} from "../testing";
import { noOtherApps } from "../testing/other-apps";
import { readOriginTlsValues } from "./origin-tls";
import { runProvision } from "./run";
import type { ProvisionServices } from "./types";

const HCLOUD = fakeSecret("hcloud-token");
const FASTLY_KEY = fakeSecret("generic-password", "fastly-flow-key");
const BUNNY_KEY = fakeSecret("generic-password", "bunny-dns-flow-key");
const STRIPE = fakeSecret("stripe-live-key");

function fastlyBunnyPlan() {
  const base = testPlan({ domain: "shop.example.com" });
  return DeployPlanSchema.parse({
    ...base,
    dns: {
      provider: "bunny",
      edge: "fastly",
      domain: "shop.example.com",
      proxied: true,
      www: true,
    },
    security: {
      ...base.security,
      httpAllowedFrom: "edge",
      wafCustomRules: true,
    },
  });
}

function fakeFastlyAndBunnyApi() {
  let activeVersion = 1;
  let installedClientCert: string | null = null;
  let installedClientKey: string | null = null;
  let installedCaCert: string | null = null;
  let installedAddress: string | null = null;
  const calls: string[] = [];

  const fetch: FetchLike = (async (url: string | URL, init?: RequestInit) => {
    const href = String(url);
    const method = init?.method ?? "GET";
    if (href.includes("api.fastly.com/tokens/self")) {
      calls.push("fastly:verify");
      return new Response(JSON.stringify({ id: "tok-1" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    if (href.includes("api.fastly.com/public-ip-list")) {
      calls.push("fastly:ips");
      return new Response(
        JSON.stringify({
          addresses: ["23.235.32.0/20", "43.249.72.0/22"],
          ipv6_addresses: ["2a04:4e40::/32"],
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    }
    if (href.includes("api.bunny.net/dnszone")) {
      calls.push("bunny:dnszone");
      return new Response(JSON.stringify({ Items: [{ Id: 4321, Domain: "example.com" }] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    if (method === "GET" && href.endsWith("/version")) {
      return new Response(JSON.stringify([{ number: activeVersion, active: true }]), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    if (method === "GET" && href.includes("/backend/opscrew_origin")) {
      return new Response(
        JSON.stringify({
          name: "opscrew_origin",
          address: SERVER_IPV4,
          ssl_client_cert: installedClientCert,
          ssl_ca_cert: installedCaCert,
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    }
    if (method === "PUT" && href.endsWith("/clone")) {
      const next = activeVersion + 1;
      calls.push(`fastly:clone:${activeVersion}->${next}`);
      return new Response(JSON.stringify({ number: next }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    if (method === "PUT" && href.includes("/backend/opscrew_origin")) {
      const body = JSON.parse(String(init?.body)) as {
        ssl_client_cert: string;
        ssl_client_key: string;
        ssl_ca_cert?: string;
        address?: string;
      };
      calls.push("fastly:update-backend");
      installedClientCert = body.ssl_client_cert;
      installedClientKey = body.ssl_client_key;
      installedCaCert = body.ssl_ca_cert ?? null;
      installedAddress = body.address ?? null;
      return new Response(JSON.stringify({ name: "opscrew_origin" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    if (method === "PUT" && href.endsWith("/activate")) {
      const match = /\/version\/(\d+)\//.exec(href);
      activeVersion = Number(match?.[1]);
      calls.push(`fastly:activate:v${activeVersion}`);
      return new Response(JSON.stringify({ number: activeVersion, active: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    return new Response("not found", { status: 404 });
  }) as unknown as FetchLike;

  return {
    fetch,
    calls,
    getInstalled: () => ({
      clientCert: installedClientCert,
      clientKey: installedClientKey,
      caCert: installedCaCert,
      address: installedAddress,
    }),
  };
}

describe.skipIf(!findExecutable("git"))(
  "Fastly + Bunny split-DNS end-to-end provision flow",
  () => {
    it("verifies both providers, routes Bunny DNS to Fastly, renders pull.pem + OPSCREW_ORIGIN_TLS, and syncs Fastly origin mTLS + ssl_ca_cert", async () => {
      const engine = new FakeEngine({
        outputs: {
          server_ipv4: SERVER_IPV4,
          server_ipv6: SERVER_IPV6,
          url: "https://shop.example.com",
          fastly_service_id: "svc-fastly-99",
          fastly_backend_name: "opscrew_origin",
          fastly_tls_subscription_id: "sub-fastly-1",
        },
      });
      const project = await createProject(fastlyBunnyPlan());
      await writeFile(join(project.root, "production.env"), `STRIPE_SECRET_KEY=${STRIPE}\n`);
      const github = new FakeGitHub();
      const api = fakeFastlyAndBunnyApi();
      const handler = new ScriptedApprovalHandler(() => true);
      const deps = await createTestPhaseDeps({
        root: project.root,
        env: {
          ...process.env,
          OPSCREW_HOME: join(project.root, ".home-opscrew"),
          HCLOUD_TOKEN: HCLOUD,
          FASTLY_API_KEY: FASTLY_KEY,
          BUNNYNET_API_KEY: BUNNY_KEY,
          OPSCREW_APP_ENV_FILE: "production.env",
        },
        runner: projectRunner(),
        approvalHandler: handler,
      });
      deps.redactor.addLiteral(HCLOUD, "HCLOUD_TOKEN");

      const services: ProvisionServices = {
        otherApps: { inspect: noOtherApps },
        engine: async () => engine,
        provider: { configured: true, verify: async () => ({ ok: true, message: "ok" }) },
        github,
        tcpConnect: async () => true,
        remote: readyRemote,
        sleep: async () => undefined,
        edgeFetch: api.fetch,
      };

      const result = await runProvision(deps, { services });
      expect(result.applied).toBe(true);

      // 1. Both Fastly and Bunny credentials were verified, Fastly CIDRs fetched, and Fastly mTLS applied.
      expect(api.calls).toContain("fastly:verify");
      expect(api.calls).toContain("bunny:dnszone");
      expect(api.calls).toContain("fastly:ips");
      expect(api.calls).toContain("fastly:clone:1->2");
      expect(api.calls).toContain("fastly:update-backend");
      expect(api.calls).toContain("fastly:activate:v2");

      // 2. Infra files wire Bunny DNS -> Fastly edge target + ACME validation records, never origin IPs.
      const mainTf = await readFile(join(project.root, "opscrew/infra/prod/main.tf"), "utf8");
      expect(mainTf).toContain("edge_cname_target      = module.edge.edge_cname_target");
      expect(mainTf).toContain("tls_validation_records = module.edge.tls_validation_records");
      expect(mainTf).toContain('resource "fastly_tls_subscription_validation" "edge"');
      expect(mainTf).toContain("depends_on      = [module.dns]");

      const tfvars = JSON.parse(
        await readFile(join(project.root, "opscrew/infra/prod/terraform.tfvars.json"), "utf8"),
      ) as Record<string, unknown>;
      expect(tfvars.bunny_dns_zone_id).toBe(4321);
      expect(tfvars.bunny_dns_zone_name).toBe("example.com");
      expect(tfvars.bunny_record_name).toBe("shop");
      expect(tfvars.bunny_www_record_name).toBe("www.shop");
      expect(tfvars.http_allowed_cidrs).toEqual([
        "23.235.32.0/20",
        "43.249.72.0/22",
        "2a04:4e40::/32",
      ]);

      // 3. Local origin cert + CA + pull.pem generated, pull.pem rendered, OPSCREW_ORIGIN_TLS stored.
      const values = await readOriginTlsValues(deps);
      expect(values.ORIGIN_TLS_CERT).toContain("BEGIN CERTIFICATE");
      expect(values.ORIGIN_TLS_KEY).toContain("PRIVATE KEY");
      expect(values.ORIGIN_TLS_CA_CERT).toContain("BEGIN CERTIFICATE");
      expect(values.ORIGIN_PULL_CERT).toContain("BEGIN CERTIFICATE");
      expect(values.ORIGIN_PULL_KEY).toContain("PRIVATE KEY");

      const pullPem = await readFile(
        join(project.root, "opscrew/runtime/edge/tls/pull.pem"),
        "utf8",
      );
      expect(pullPem.trim()).toBe(values.ORIGIN_PULL_CERT?.trim());

      const originTlsDeploySecret = github.secrets.get(DEPLOY_SECRETS.originTls);
      expect(originTlsDeploySecret).toContain(values.ORIGIN_TLS_CERT as string);
      expect(originTlsDeploySecret).toContain(values.ORIGIN_TLS_KEY as string);

      // 4. Fastly backend received pull.pem client cert/key, per-app origin CA cert, and origin address.
      const installed = api.getInstalled();
      expect(installed.clientCert).toBe(values.ORIGIN_PULL_CERT?.trim());
      expect(installed.clientKey).toBe(values.ORIGIN_PULL_KEY?.trim());
      expect(installed.caCert).toBe(values.ORIGIN_TLS_CA_CERT?.trim());
      expect(installed.address).toBe(SERVER_IPV4);

      // 5. Private keys and API tokens never leak into Terraform files, reporter, or audit log.
      const printed = `${mainTf}\n${JSON.stringify(tfvars)}\n${deps.reporter.text()}\n${JSON.stringify(deps.audit.entries)}`;
      expect(printed).not.toContain(FASTLY_KEY);
      expect(printed).not.toContain(BUNNY_KEY);
      expect(printed).not.toContain(values.ORIGIN_PULL_KEY as string);
      expect(printed).not.toContain(values.ORIGIN_TLS_KEY as string);
    });
  },
);
