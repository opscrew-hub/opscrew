import { DeployPlanSchema } from "@opscrew/plan-schema";
import { describe, expect, it } from "vitest";
import { testsslResults } from "../deep/testssl";
import { blockingPolicyFailures, evaluatePlanPolicies } from "./plan";

function fastlyPlan() {
  return DeployPlanSchema.parse({
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
    dns: { provider: "bunny", edge: "fastly", domain: "shop.example.com", proxied: true },
    cicd: { provider: "github-actions", registry: "ghcr", branch: "main" },
    security: { httpAllowedFrom: "edge", wafCustomRules: true },
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
  });
}

describe("Fastly SecOps policies and TLS reporting (036 PR 4)", () => {
  it("passes safe Fastly VCL plans and blocks ssl_client_key in state + open firewall ports", () => {
    const safeJson = {
      planned_values: {
        root_module: {
          child_modules: [
            {
              address: "module.server",
              resources: [
                {
                  address: "module.server.hcloud_firewall.this",
                  type: "hcloud_firewall",
                  values: {
                    rule: [
                      {
                        direction: "in",
                        protocol: "tcp",
                        port: "443",
                        source_ips: ["23.235.32.0/20"],
                      },
                    ],
                  },
                },
              ],
            },
            {
              address: "module.edge",
              resources: [
                {
                  address: "module.edge.fastly_service_vcl.this",
                  type: "fastly_service_vcl",
                  values: {
                    request_setting: [{ action: "pass", force_ssl: true }],
                    backend: [{ name: "opscrew_origin", use_ssl: true, ssl_check_cert: true }],
                  },
                },
              ],
            },
          ],
        },
      },
    };
    const safe = evaluatePlanPolicies(safeJson, fastlyPlan());
    expect(blockingPolicyFailures(safe)).toEqual([]);
    expect(safe.find((r) => r.policyId === "fastly-cache-pass")?.passed).toBe(true);
    expect(safe.find((r) => r.policyId === "fastly-origin-ssl-verify")?.passed).toBe(true);

    const leakyJson = {
      planned_values: {
        root_module: {
          child_modules: [
            {
              address: "module.server",
              resources: [
                {
                  address: "module.server.hcloud_firewall.this",
                  type: "hcloud_firewall",
                  values: {
                    rule: [
                      {
                        direction: "in",
                        protocol: "tcp",
                        port: "443",
                        source_ips: ["0.0.0.0/0"],
                      },
                    ],
                  },
                },
              ],
            },
            {
              address: "module.edge",
              resources: [
                {
                  address: "module.edge.fastly_service_vcl.this",
                  type: "fastly_service_vcl",
                  values: {
                    request_setting: [{ action: "lookup", force_ssl: false }],
                    backend: [
                      {
                        name: "opscrew_origin",
                        use_ssl: true,
                        ssl_check_cert: false,
                        ssl_client_key: "in-state-key-placeholder",
                      },
                    ],
                  },
                },
              ],
            },
          ],
        },
      },
    };
    const leaky = evaluatePlanPolicies(leakyJson, fastlyPlan());
    const blockers = blockingPolicyFailures(leaky);
    expect(blockers.map((r) => r.policyId)).toContain("fastly-origin-ssl-verify");
    expect(blockers.map((r) => r.policyId)).toContain("fastly-no-client-key-in-state");
    expect(blockers.find((r) => r.policyId === "fastly-no-client-key-in-state")?.severity).toBe(
      "critical",
    );
    // Compact CIDR enforcement also flags 0.0.0.0/0 on port 443 naming Fastly.
    const firewallCheck = leaky.find((r) => r.policyId === "origin-cloudflare-only");
    expect(firewallCheck?.passed).toBe(false);
    expect(firewallCheck?.message).toContain("Fastly");
  });

  it("uses Fastly's edge label and TLS hint in testsslResults", () => {
    const results = testsslResults(
      [{ id: "TLS1", severity: "HIGH", finding: "offered" }],
      "shop.example.com",
      true,
      "fastly",
    );
    expect(results[0]?.target).toBe("shop.example.com (Fastly's edge)");
    expect(results[0]?.remediation).toContain("Fastly");
  });
});
