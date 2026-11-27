import { OpsCrewError } from "@opscrew/core";
import { definition as bunny } from "@opscrew/edge-provider-bunny";
import { definition as cloudflare } from "@opscrew/edge-provider-cloudflare";
import { definition as fastly } from "@opscrew/edge-provider-fastly";
import { definition as gcore } from "@opscrew/edge-provider-gcore";
import { describe, expect, it } from "vitest";
import { EDGE_PROVIDERS, edgeProvider, validateEdgeProvider } from "./index";

describe("the edge provider registry", () => {
  it("lists the built-in definitions in order, as their packages export them", () => {
    expect(EDGE_PROVIDERS).toEqual([cloudflare, bunny, gcore, fastly]);
  });

  it("returns a provider's definition by id for edgeProvider", () => {
    expect(edgeProvider("cloudflare")).toBe(cloudflare);
    expect(edgeProvider("bunny")).toBe(bunny);
    expect(edgeProvider("gcore")).toBe(gcore);
    expect(edgeProvider("fastly")).toBe(fastly);
  });

  it("refuses unknown edge provider ids naming the known ones", () => {
    let edgeErr: unknown;
    try {
      edgeProvider("akamai");
    } catch (err) {
      edgeErr = err;
    }
    expect(edgeErr).toBeInstanceOf(OpsCrewError);
    expect(edgeErr).toMatchObject({
      code: "INVALID_INPUT",
      message: 'OpsCrew does not support edge provider "akamai".',
      hint: "Choose one of its edge providers: cloudflare, bunny, gcore and fastly.",
    });
  });
});

describe.each(EDGE_PROVIDERS.map((provider) => [provider.id, provider] as const))(
  "%s conforms to the edge provider contract (ADR 0038)",
  (_id, provider) => {
    it("passes validation", () => {
      expect(validateEdgeProvider(provider)).toBe(provider);
    });

    it("has a plain https token creation URL", () => {
      expect(provider.credentials.createUrl).toMatch(/^https:\/\/[^?#]+$/);
    });
  },
);
