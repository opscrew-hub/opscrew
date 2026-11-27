import { generateKeyPairSync } from "node:crypto";
import type { FetchLike } from "@opscrew/contracts";
import { OpsCrewError, Redactor } from "@opscrew/core";
import { fakeSecret } from "@opscrew/core/testing";
import { describe, expect, it } from "vitest";
import { fastlyClient } from "./client";

const API_KEY = fakeSecret("generic-password", "fastly-api-key");
const TEST_CERT_PEM =
  "-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END CERTIFICATE-----";
const TEST_KEY_PEM = generateKeyPairSync("ec", { namedCurve: "prime256v1" })
  .privateKey.export({ type: "pkcs8", format: "pem" })
  .toString();

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("fastlyClient", () => {
  it("verifies credentials via Fastly-Key and refuses missing or rejected tokens", async () => {
    const missing = fastlyClient({ apiKey: "  " });
    expect((await missing.verifyCredentials()).ok).toBe(false);

    const seenHeaders: Record<string, string>[] = [];
    const okClient = fastlyClient({
      apiKey: API_KEY,
      fetch: (async (_url: string | URL, init?: RequestInit) => {
        seenHeaders.push((init?.headers ?? {}) as Record<string, string>);
        return jsonResponse({ id: "tok-1" });
      }) as unknown as FetchLike,
    });
    expect(await okClient.verifyCredentials()).toEqual({
      ok: true,
      message: "Fastly API token verified.",
    });
    expect(seenHeaders[0]?.["Fastly-Key"]).toBe(API_KEY);

    const badClient = fastlyClient({
      apiKey: API_KEY,
      fetch: (async () => jsonResponse({ msg: "Unauthorized" }, 401)) as unknown as FetchLike,
    });
    const bad = await badClient.verifyCredentials();
    expect(bad.ok).toBe(false);
    expect(bad.message).toContain("HTTP 401");
    expect(bad.message).not.toContain(API_KEY);
  });

  it("fetches compact IPv4/IPv6 CIDR ranges from /public-ip-list without auth and validates with zod", async () => {
    const seenAuth: (string | undefined)[] = [];
    const client = fastlyClient({
      apiKey: "",
      fetch: (async (_url: string | URL, init?: RequestInit) => {
        const headers = (init?.headers ?? {}) as Record<string, string>;
        seenAuth.push(headers["Fastly-Key"]);
        return jsonResponse({
          addresses: ["23.235.32.0/20", "43.249.72.0/22"],
          ipv6_addresses: ["2a04:4e40::/32"],
        });
      }) as unknown as FetchLike,
    });
    expect(await client.getIpRanges()).toEqual({
      ipv4: ["23.235.32.0/20", "43.249.72.0/22"],
      ipv6: ["2a04:4e40::/32"],
    });
    expect(seenAuth).toEqual([undefined]);

    const malformed = fastlyClient({
      apiKey: "",
      fetch: (async () => jsonResponse({ addresses: [] })) as unknown as FetchLike,
    });
    await expect(malformed.getIpRanges()).rejects.toMatchObject({ code: "PROVIDER_ERROR" });
  });

  it("clones, updates backend mTLS, activates, and redacts API key + private key on errors", async () => {
    const calls: { url: string; method?: string; body?: unknown }[] = [];
    const redactor = new Redactor();
    const client = fastlyClient({
      apiKey: API_KEY,
      redactor,
      fetch: (async (url: string | URL, init?: RequestInit) => {
        const u = String(url);
        calls.push({
          url: u,
          method: init?.method,
          body: init?.body ? JSON.parse(String(init.body)) : undefined,
        });
        if (u.endsWith("/version")) {
          return jsonResponse([
            { number: 1, active: false },
            { number: 2, active: true },
          ]);
        }
        if (u.endsWith("/backend/opscrew_origin") && init?.method === "GET") {
          return jsonResponse({
            name: "opscrew_origin",
            address: "203.0.113.10",
            ssl_client_cert: null,
          });
        }
        if (u.endsWith("/clone")) return jsonResponse({ number: 3 });
        return jsonResponse({ ok: true });
      }) as unknown as FetchLike,
    });

    expect(await client.getActiveVersion("svc-1")).toBe(2);
    expect(await client.getBackend("svc-1", 2, "opscrew_origin")).toEqual({
      name: "opscrew_origin",
      address: "203.0.113.10",
      ssl_client_cert: null,
    });
    const next = await client.cloneVersion("svc-1", 2);
    expect(next).toBe(3);
    await client.updateBackendMtls({
      serviceId: "svc-1",
      version: next,
      backendName: "opscrew_origin",
      clientCertPem: TEST_CERT_PEM,
      clientKeyPem: TEST_KEY_PEM,
    });
    await client.activateVersion("svc-1", next);

    expect(calls.map((c) => `${c.method} ${c.url}`)).toEqual([
      "GET https://api.fastly.com/service/svc-1/version",
      "GET https://api.fastly.com/service/svc-1/version/2/backend/opscrew_origin",
      "PUT https://api.fastly.com/service/svc-1/version/2/clone",
      "PUT https://api.fastly.com/service/svc-1/version/3/backend/opscrew_origin",
      "PUT https://api.fastly.com/service/svc-1/version/3/activate",
    ]);

    const failing = fastlyClient({
      apiKey: API_KEY,
      redactor,
      fetch: (async () =>
        new Response(`echo ${API_KEY} and ${TEST_KEY_PEM}`, {
          status: 500,
        })) as unknown as FetchLike,
    });
    const err = await failing
      .updateBackendMtls({
        serviceId: "svc-1",
        version: 3,
        backendName: "opscrew_origin",
        clientCertPem: TEST_CERT_PEM,
        clientKeyPem: TEST_KEY_PEM,
      })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(OpsCrewError);
    expect((err as OpsCrewError).message).not.toContain(API_KEY);
    expect((err as OpsCrewError).message).not.toContain(TEST_KEY_PEM);
  });
});
