import { generateKeyPairSync } from "node:crypto";
import type { FetchLike } from "@opscrew/contracts";
import { fakeSecret } from "@opscrew/core/testing";
import { DeployPlanSchema } from "@opscrew/plan-schema";
import { describe, expect, it } from "vitest";
import { createTestPhaseDeps, ScriptedApprovalHandler, testPlan } from "../testing";
import { setupThirdPartyEdge } from "./edge-origin-token";
import { syncOriginMtls } from "./fastly-origin-mtls";

const API_KEY = fakeSecret("generic-password", "fastly-mtls-test-key");
const BUNNY_KEY = fakeSecret("generic-password", "bunny-split-dns-test-key");
const CERT_PEM = "-----BEGIN CERTIFICATE-----\nFASTLY-TEST-CERT\n-----END CERTIFICATE-----";
const CA_CERT_PEM = "-----BEGIN CERTIFICATE-----\nFASTLY-ORIGIN-CA\n-----END CERTIFICATE-----";
const KEY_PEM = generateKeyPairSync("ec", { namedCurve: "prime256v1" })
  .privateKey.export({ type: "pkcs8", format: "pem" })
  .toString();

function fastlyPlan(dnsProvider: "bunny" | "gcore" = "bunny") {
  const base = testPlan({ domain: "shop.example.com" });
  return DeployPlanSchema.parse({
    ...base,
    dns: {
      provider: dnsProvider,
      edge: "fastly",
      domain: "shop.example.com",
      zone: "example.com",
      proxied: true,
      www: false,
    },
    security: {
      ...base.security,
      httpAllowedFrom: "edge",
      wafCustomRules: true,
    },
  });
}

function fakeFastlyFetch(initialCert: string | null = null, initialCa: string | null = null) {
  let activeVersion = 4;
  let cert = initialCert;
  let caCert = initialCa;
  const calls: string[] = [];

  const fetch: FetchLike = (async (url: string | URL, init?: RequestInit) => {
    const href = String(url);
    const method = init?.method ?? "GET";
    if (method === "GET" && href.endsWith("/version")) {
      return new Response(JSON.stringify([{ number: activeVersion, active: true }]), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    if (method === "GET" && href.includes("/backend/")) {
      return new Response(
        JSON.stringify({
          name: "opscrew_origin",
          address: "203.0.113.10",
          ssl_client_cert: cert,
          ssl_ca_cert: caCert,
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    }
    if (method === "PUT" && href.endsWith("/clone")) {
      const next = activeVersion + 1;
      calls.push(`clone:${activeVersion}->${next}`);
      return new Response(JSON.stringify({ number: next }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    if (method === "PUT" && href.includes("/backend/")) {
      const body = JSON.parse(String(init?.body)) as {
        ssl_client_cert: string;
        ssl_ca_cert?: string;
      };
      const match = /\/version\/(\d+)\//.exec(href);
      calls.push(`update:v${match?.[1]}`);
      cert = body.ssl_client_cert;
      if (body.ssl_ca_cert !== undefined) caCert = body.ssl_ca_cert;
      return new Response(JSON.stringify({ name: "opscrew_origin" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    if (method === "PUT" && href.endsWith("/activate")) {
      const match = /\/version\/(\d+)\//.exec(href);
      const next = Number(match?.[1]);
      calls.push(`activate:v${next}`);
      activeVersion = next;
      return new Response(JSON.stringify({ number: next, active: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    return new Response("not found", { status: 404 });
  }) as unknown as FetchLike;

  return { calls, fetch, getCaCert: () => caCert };
}

describe("syncOriginMtls and split-DNS setupThirdPartyEdge (036 PR 4)", () => {
  it("resolves the active mTLS edge provider from the plan, approves by hash, and pins client cert + origin CA without leaking keys", async () => {
    const handler = new ScriptedApprovalHandler(() => true);
    const deps = await createTestPhaseDeps({ approvalHandler: handler });
    const fake = fakeFastlyFetch(null, null);
    const plan = fastlyPlan();

    const res = await syncOriginMtls(deps, plan, {
      apiKey: API_KEY,
      serviceId: "svc-123",
      backendName: "opscrew_origin",
      clientCertPem: CERT_PEM,
      clientKeyPem: KEY_PEM,
      originCaCertPem: CA_CERT_PEM,
      fetch: fake.fetch,
      command: "opscrew provision",
    });
    expect(res.applied).toBe(true);
    expect(res.activatedVersion).toBe(5);
    expect(fake.calls).toEqual(["clone:4->5", "update:v5", "activate:v5"]);
    expect(fake.getCaCert()).toBe(CA_CERT_PEM);
    expect(handler.requests).toHaveLength(1);
    expect(handler.requests[0]?.details).not.toContain(KEY_PEM);
    expect(handler.requests[0]?.details).not.toContain(API_KEY);

    // Second run is a noop without prompting.
    const second = await syncOriginMtls(deps, plan, {
      apiKey: API_KEY,
      serviceId: "svc-123",
      backendName: "opscrew_origin",
      clientCertPem: CERT_PEM,
      clientKeyPem: KEY_PEM,
      originCaCertPem: CA_CERT_PEM,
      fetch: fake.fetch,
      command: "opscrew provision",
    });
    expect(second.applied).toBe(false);
    expect(second.plan.action).toBe("noop");
    expect(handler.requests).toHaveLength(1);
  });

  it("refuses non-mTLS plans and leaves Fastly untouched when approval is refused or planOnly is true", async () => {
    const fake = fakeFastlyFetch(null);
    const deps = await createTestPhaseDeps({
      approvalHandler: new ScriptedApprovalHandler(() => false),
    });
    const plan = fastlyPlan();

    await expect(
      syncOriginMtls(deps, testPlan({ domain: "shop.example.com" }), {
        apiKey: API_KEY,
        serviceId: "svc-123",
        backendName: "opscrew_origin",
        clientCertPem: CERT_PEM,
        clientKeyPem: KEY_PEM,
        fetch: fake.fetch,
        command: "opscrew provision",
      }),
    ).rejects.toMatchObject({ code: "INVALID_INPUT" });

    const planOnly = await syncOriginMtls(deps, plan, {
      apiKey: API_KEY,
      serviceId: "svc-123",
      backendName: "opscrew_origin",
      clientCertPem: CERT_PEM,
      clientKeyPem: KEY_PEM,
      fetch: fake.fetch,
      command: "opscrew provision",
      planOnly: true,
    });
    expect(planOnly.applied).toBe(false);
    expect(fake.calls).toEqual([]);

    await expect(
      syncOriginMtls(deps, plan, {
        apiKey: API_KEY,
        serviceId: "svc-123",
        backendName: "opscrew_origin",
        clientCertPem: CERT_PEM,
        clientKeyPem: KEY_PEM,
        fetch: fake.fetch,
        command: "opscrew provision",
      }),
    ).rejects.toMatchObject({
      code: "APPROVAL_REFUSED",
      message: expect.stringContaining("HTTP 503"),
    });
    expect(fake.calls).toEqual([]);
  });

  it("setupThirdPartyEdge verifies BOTH Fastly and Bunny credentials and looks up Bunny's DNS zone id and name on split DNS", async () => {
    const seenUrls: string[] = [];
    const fetch: FetchLike = (async (url: string | URL) => {
      const href = String(url);
      seenUrls.push(href);
      if (href.includes("api.fastly.com/tokens/self")) {
        return new Response(JSON.stringify({ id: "tok-1" }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      if (href.includes("api.fastly.com/public-ip-list")) {
        return new Response(
          JSON.stringify({ addresses: ["23.235.32.0/20"], ipv6_addresses: ["2a04:4e40::/32"] }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }
      if (href.includes("api.bunny.net/dnszone")) {
        return new Response(JSON.stringify({ Items: [{ Id: 4321, Domain: "example.com" }] }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      return new Response("not found", { status: 404 });
    }) as unknown as FetchLike;

    const deps = await createTestPhaseDeps({
      env: {
        FASTLY_API_KEY: API_KEY,
        BUNNYNET_API_KEY: BUNNY_KEY,
      },
    });
    const setup = await setupThirdPartyEdge(deps, fastlyPlan("bunny"), { edgeFetch: fetch });
    expect(setup).toEqual({
      id: "fastly",
      envVar: "FASTLY_API_KEY",
      apiKey: API_KEY,
      dnsZoneId: 4321,
      dnsZoneName: "example.com",
      dnsProvider: {
        id: "bunny",
        envVar: "BUNNYNET_API_KEY",
        apiKey: BUNNY_KEY,
      },
      edgeRanges: ["23.235.32.0/20", "2a04:4e40::/32"],
    });
    expect(seenUrls.some((u) => u.includes("api.fastly.com/tokens/self"))).toBe(true);
    expect(seenUrls.some((u) => u.includes("api.bunny.net/dnszone"))).toBe(true);
  });
});
