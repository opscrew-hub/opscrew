import { OpsCrewError } from "@opscrew/core";
import { definition as bunny } from "@opscrew/edge-provider-bunny";
import { definition as cloudflare } from "@opscrew/edge-provider-cloudflare";
import { definition as fastly } from "@opscrew/edge-provider-fastly";
import { definition as gcore } from "@opscrew/edge-provider-gcore";
import { describe, expect, it } from "vitest";
import { validateEdgeProvider } from "./validate";

describe("validateEdgeProvider", () => {
  it("accepts the built-in Cloudflare, Bunny.net, Gcore, and Fastly definitions", () => {
    expect(validateEdgeProvider(cloudflare)).toBe(cloudflare);
    expect(validateEdgeProvider(bunny)).toBe(bunny);
    expect(validateEdgeProvider(gcore)).toBe(gcore);
    expect(validateEdgeProvider(fastly)).toBe(fastly);
  });

  it("refuses a wrong contract version", () => {
    expect(() => validateEdgeProvider({ ...cloudflare, contractVersion: 99 })).toThrow(
      OpsCrewError,
    );
  });

  it("refuses dynamic-ips paired with non-shared-header originAuth", () => {
    expect(() =>
      validateEdgeProvider({
        ...bunny,
        capabilities: {
          ...bunny.capabilities,
          originIpFiltering: "dynamic-ips",
          originAuth: "mtls-client-cert",
          originAuthHeader: undefined,
        },
      }),
    ).toThrow(/shared-header/);
  });

  it("requires originAuthHeader iff originAuth is shared-header", () => {
    expect(() =>
      validateEdgeProvider({
        ...bunny,
        capabilities: {
          ...bunny.capabilities,
          originAuthHeader: undefined,
        },
      }),
    ).toThrow(/originAuthHeader/);

    expect(() =>
      validateEdgeProvider({
        ...cloudflare,
        capabilities: {
          ...cloudflare.capabilities,
          originAuthHeader: "X-OpsCrew-Origin-Token",
        },
      }),
    ).toThrow(/originAuthHeader/);
  });

  it("refuses an invalid realIpHeader name", () => {
    expect(() =>
      validateEdgeProvider({
        ...cloudflare,
        capabilities: {
          ...cloudflare.capabilities,
          realIpHeader: "bad header!",
        },
      }),
    ).toThrow(/HTTP header name/);
  });
});
