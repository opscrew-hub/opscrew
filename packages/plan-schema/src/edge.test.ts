import { describe, expect, it } from "vitest";
import { activeEdgeProvider, DeployPlanSchema } from "./plan";

function basePlan(dns: Record<string, unknown>, security: Record<string, unknown> = {}) {
  return {
    schemaVersion: 1,
    createdAt: "2026-11-26T00:00:00.000Z",
    updatedAt: "2026-11-26T00:00:00.000Z",
    app: { name: "shop", port: 3000, healthPath: "/health", env: [] },
    target: {
      provider: "hetzner",
      mode: "vps-compose",
      location: "fsn1",
      serverType: "cx23",
      backups: true,
    },
    dns,
    cicd: { provider: "github-actions", registry: "ghcr", branch: "main" },
    security,
    services: [],
    externalServices: [],
    codeChanges: [],
    cost: {
      monthly: { amount: 4.5, currency: "EUR" },
      breakdown: [{ item: "Hetzner cx23", monthly: { amount: 4.5, currency: "EUR" } }],
      pricesIncludeVat: false,
      source: "static",
      asOf: "2026-11-26T00:00:00.000Z",
    },
  };
}

describe("plan-schema DNS host and edge provider rules (036 PR 2 & PR 3)", () => {
  it("accepts Bunny and Gcore DNS+edge (implicit) and external DNS + edge", () => {
    for (const provider of ["bunny", "gcore"] as const) {
      const plan = DeployPlanSchema.parse(
        basePlan({ provider, domain: "shop.example.com", proxied: true }),
      );
      expect(plan.dns.provider).toBe(provider);
      expect(plan.dns.edge).toBeUndefined();
      expect(plan.security.httpAllowedFrom).toBe("edge");
      expect(activeEdgeProvider(plan)).toBe(provider);

      const extDns = DeployPlanSchema.parse(
        basePlan({ provider: "none", edge: provider, domain: "shop.example.com", proxied: true }),
      );
      expect(activeEdgeProvider(extDns)).toBe(provider);
    }
  });

  it("returns undefined for DNS-only plans and cloudflare for proxied Cloudflare plans", () => {
    for (const provider of ["bunny", "gcore"] as const) {
      const dnsOnly = DeployPlanSchema.parse(
        basePlan({ provider, domain: "shop.example.com", proxied: false }),
      );
      expect(activeEdgeProvider(dnsOnly)).toBeUndefined();
    }

    const cf = DeployPlanSchema.parse(
      basePlan({ provider: "cloudflare", domain: "shop.example.com", proxied: true }),
    );
    expect(activeEdgeProvider(cf)).toBe("cloudflare");
  });

  it("refuses dns.edge repeating dns.provider (S5) and dns.edge paired with dns.provider: cloudflare (B2)", () => {
    for (const provider of ["bunny", "gcore"] as const) {
      const duplicate = DeployPlanSchema.safeParse(
        basePlan({ provider, edge: provider, domain: "shop.example.com", proxied: true }),
      );
      expect(duplicate.success).toBe(false);
      expect(duplicate.error?.issues[0]?.message).toContain(`repeats dns.provider ("${provider}")`);

      const cfPlusEdge = DeployPlanSchema.safeParse(
        basePlan({
          provider: "cloudflare",
          edge: provider,
          domain: "shop.example.com",
          proxied: true,
        }),
      );
      expect(cfPlusEdge.success).toBe(false);
      expect(cfPlusEdge.error?.issues[0]?.message).toContain(
        'cannot be combined with dns.provider: "cloudflare"',
      );
    }
  });

  it("refuses dns.edge: cloudflare, dns.edge without proxied: true, and edge DNS without domain", () => {
    const cfEdge = DeployPlanSchema.safeParse(
      basePlan({
        provider: "cloudflare",
        edge: "cloudflare",
        domain: "shop.example.com",
        proxied: true,
      }),
    );
    expect(cfEdge.success).toBe(false);
    expect(cfEdge.error?.issues[0]?.message).toContain('must not be "cloudflare"');

    const unproxied = DeployPlanSchema.safeParse(
      basePlan({
        provider: "none",
        edge: "gcore",
        domain: "shop.example.com",
        proxied: false,
      }),
    );
    expect(unproxied.success).toBe(false);
    expect(unproxied.error?.issues.map((i) => i.path.join("."))).toContain("dns.edge");

    const noDomain = DeployPlanSchema.safeParse(basePlan({ provider: "gcore", proxied: true }));
    expect(noDomain.success).toBe(false);
    expect(noDomain.error?.issues.map((i) => i.path.join("."))).toContain("dns.domain");
  });

  it("refuses Bunny on non-cloud targets (own, portainer, localhost) until their roots wire thirdPartyEdgeRoot", () => {
    const ownTarget = {
      ...basePlan({ provider: "bunny", domain: "shop.example.com", proxied: true }),
      target: { provider: "own", mode: "vps-compose", arch: "amd64", access: "public" },
    };
    const ownResult = DeployPlanSchema.safeParse(ownTarget);
    expect(ownResult.success).toBe(false);
    expect(ownResult.error?.issues.map((i) => i.message).join(" ")).toContain("cloud VPS targets");

    const portainerTarget = {
      ...basePlan({ provider: "none", edge: "bunny", domain: "shop.example.com", proxied: true }),
      target: {
        provider: "portainer",
        mode: "portainer-stack",
        arch: "amd64",
        environmentId: 1,
        redeploy: "updater",
        web: { mode: "caddy" },
      },
    };
    const portainerResult = DeployPlanSchema.safeParse(portainerTarget);
    expect(portainerResult.success).toBe(false);
    expect(portainerResult.error?.issues.map((i) => i.path.join("."))).toContain("dns.edge");
    expect(portainerResult.error?.issues.map((i) => i.message).join(" ")).toContain(
      "cloud VPS targets",
    );

    const localhostTarget = {
      ...basePlan({ provider: "bunny", domain: "shop.example.com", proxied: true }),
      target: {
        provider: "localhost",
        mode: "local-compose",
        arch: "amd64",
        ports: { http: 80, https: 443 },
        image: "local-build",
      },
    };
    const localhostResult = DeployPlanSchema.safeParse(localhostTarget);
    expect(localhostResult.success).toBe(false);
    expect(localhostResult.error?.issues.map((i) => i.message).join(" ")).toContain(
      "cloud VPS targets",
    );
  });

  it("accepts Fastly edge with Bunny or Gcore DNS and refuses Fastly with dns.provider: none or cloudflare", () => {
    for (const provider of ["bunny", "gcore"] as const) {
      const plan = DeployPlanSchema.parse(
        basePlan({
          provider,
          edge: "fastly",
          domain: "shop.example.com",
          zone: "example.com",
          proxied: true,
          www: true,
        }),
      );
      expect(plan.dns.edge).toBe("fastly");
      expect(plan.security.httpAllowedFrom).toBe("edge");
      expect(activeEdgeProvider(plan)).toBe("fastly");
    }

    const withCloudflare = DeployPlanSchema.safeParse(
      basePlan({
        provider: "cloudflare",
        edge: "fastly",
        domain: "shop.example.com",
        proxied: true,
      }),
    );
    expect(withCloudflare.success).toBe(false);
    expect(withCloudflare.error?.issues[0]?.message).toContain(
      'cannot be combined with dns.provider: "cloudflare" yet: set dns.provider to "bunny" or "gcore"',
    );

    const withNone = DeployPlanSchema.safeParse(
      basePlan({
        provider: "none",
        edge: "fastly",
        domain: "shop.example.com",
        proxied: true,
      }),
    );
    expect(withNone.success).toBe(false);
    expect(withNone.error?.issues[0]?.message).toContain(
      'Fastly does not host DNS, so set dns.provider to "bunny" or "gcore"',
    );
    expect(withNone.error?.issues[0]?.message).not.toContain('"cloudflare"');
  });
});
