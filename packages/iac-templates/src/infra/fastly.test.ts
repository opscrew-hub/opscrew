import { DeployPlanSchema } from "@opscrew/plan-schema";
import { describe, expect, it } from "vitest";
import { renderEdgeCompose } from "../edge";
import { renderEdgeSite } from "../runtime";
import { renderInfra } from "./index";

const FASTLY_RANGES = ["23.235.32.0/20", "43.249.72.0/22", "2a04:4e40::/32"];

function baseCtx() {
  return {
    opscrewVersion: "0.2.12",
    github: { owner: "acme", repo: "shop" },
    deploySshPublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey test@opscrew",
    edge: { dnsZoneId: 42 },
    edgeRanges: FASTLY_RANGES,
  };
}

function makeFastlyPlan(opts: {
  dnsProvider?: "bunny" | "gcore";
  proxy?: "caddy" | "nginx" | "openlitespeed";
}) {
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
      edge: opts.proxy ?? "caddy",
    },
    dns: {
      provider: opts.dnsProvider ?? "bunny",
      edge: "fastly",
      domain: "app.example.com",
      zone: "example.com",
      proxied: true,
      www: true,
    },
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

describe("Fastly infrastructure and reverse-proxy rendering (036 PR 4)", () => {
  it("renders Bunny DNS (unproxied module dns) + Fastly edge (module edge) with compact CIDR firewall and zero ssl_client_key", () => {
    const files = renderInfra(makeFastlyPlan({ dnsProvider: "bunny" }), baseCtx());
    const byPath = (suffix: string) => files.find((f) => f.path.endsWith(suffix))?.content ?? "";

    const versions = byPath("/versions.tf");
    expect(versions).toContain('source  = "BunnyWay/bunnynet"');
    expect(versions).toContain('source  = "fastly/fastly"');
    expect(versions).toContain('version = "~> 10.4"');

    const main = byPath("/main.tf");
    expect(main).toContain('provider "fastly" {}');
    expect(main).toContain('module "dns"');
    expect(main).toContain('source = "../modules/bunny-edge"');
    expect(main).toContain("edge_cname_target      = module.edge.edge_cname_target");
    expect(main).toContain("tls_validation_records = module.edge.tls_validation_records");
    expect(main).toContain('module "edge"');
    expect(main).toContain('source = "../modules/fastly-edge"');
    expect(main).toContain('resource "fastly_tls_subscription_validation" "edge"');
    expect(main).toContain("subscription_id = module.edge.tls_subscription_id");
    expect(main).toContain("depends_on      = [module.dns]");
    // Split DNS must NEVER point Bunny DNS at the origin server's IP.
    const dnsBlock = main.slice(main.indexOf('module "dns"'), main.indexOf('module "edge"'));
    expect(dnsBlock).not.toContain("ipv4");
    expect(dnsBlock).not.toContain("ipv6");

    const outputs = byPath("/outputs.tf");
    expect(outputs).toContain('output "fastly_service_id"');
    expect(outputs).toContain('output "fastly_backend_name"');
    expect(outputs).toContain('output "fastly_tls_subscription_id"');
    expect(outputs).toContain('output "fastly_edge_cname_target"');
    expect(outputs).toContain('output "fastly_tls_validation_records"');

    const tfvars = JSON.parse(byPath("/terraform.tfvars.json")) as Record<string, unknown>;
    expect(tfvars.bunny_proxied).toBe(false);
    expect(tfvars.bunny_dns_zone_name).toBe("example.com");
    expect(tfvars.fastly_service_name).toBe("opscrew-shop");
    expect(tfvars.fastly_waf_custom_rules).toBe(true);
    // Compact CIDR firewall restricts ports 80/443 strictly to Fastly's CIDRs.
    expect(tfvars.http_allowed_cidrs).toEqual(FASTLY_RANGES);

    const variables = byPath("/variables.tf");
    expect(variables.match(/variable "domain" \{/g)).toHaveLength(1);
    expect(variables.match(/variable "www" \{/g)).toHaveLength(1);

    const moduleMain = byPath("modules/fastly-edge/main.tf");
    expect(moduleMain).toContain('resource "fastly_service_vcl" "this"');
    expect(moduleMain).toContain('data "fastly_tls_configuration" "default"');
    expect(moduleMain).toContain('action    = "pass"');
    expect(moduleMain).toContain("status            = 403");
    expect(moduleMain).not.toContain("ssl_client_key");

    const bunnyMain = byPath("modules/bunny-edge/main.tf");
    expect(bunnyMain).toContain('resource "bunnynet_dns_record" "edge_target"');
    expect(bunnyMain).toContain('type    = var.record_name == "" ? "Flatten" : "CNAME"');
    expect(bunnyMain).toContain("!var.split_dns");
    expect(bunnyMain).toContain("precondition {");
    expect(bunnyMain).toContain('resource "bunnynet_dns_record" "tls_validation"');
    expect(main).toContain("split_dns              = true");
  });

  it("uses learned ctx.edge.dnsZoneName when dns.zone is omitted for subdomains on Bunny and Gcore", () => {
    for (const dnsProvider of ["bunny", "gcore"] as const) {
      const plan = makeFastlyPlan({ dnsProvider });
      const { zone: _omitted, ...dnsWithoutZone } = plan.dns;
      const files = renderInfra(
        { ...plan, dns: dnsWithoutZone },
        { ...baseCtx(), edge: { dnsZoneId: 42, dnsZoneName: "example.com" } },
      );
      const tfvars = JSON.parse(
        files.find((f) => f.path.endsWith("/terraform.tfvars.json"))?.content ?? "{}",
      ) as Record<string, unknown>;
      if (dnsProvider === "bunny") {
        expect(tfvars.bunny_record_name).toBe("app");
        expect(tfvars.bunny_www_record_name).toBe("www.app");
        expect(tfvars.bunny_dns_zone_name).toBe("example.com");
      } else {
        expect(tfvars.gcore_dns_zone).toBe("example.com");
      }
    }
  });

  it("renders Gcore DNS (unproxied module dns) + Fastly edge (module edge) routing to Fastly targets without collisions", () => {
    const files = renderInfra(makeFastlyPlan({ dnsProvider: "gcore" }), baseCtx());
    const byPath = (suffix: string) => files.find((f) => f.path.endsWith(suffix))?.content ?? "";

    const main = byPath("/main.tf");
    expect(main).toContain('module "dns"');
    expect(main).toContain('source = "../modules/gcore-edge"');
    expect(main).toContain("edge_cname_target      = module.edge.edge_cname_target");
    expect(main).toContain("edge_ipv4_targets      = module.edge.edge_ipv4_targets");
    expect(main).toContain("edge_ipv6_targets      = module.edge.edge_ipv6_targets");
    expect(main).toContain("tls_validation_records = module.edge.tls_validation_records");
    expect(main).toContain('module "edge"');
    expect(main).toContain('source = "../modules/fastly-edge"');
    expect(main).toContain('resource "fastly_tls_subscription_validation" "edge"');
    const dnsBlock = main.slice(main.indexOf('module "dns"'), main.indexOf('module "edge"'));
    expect(dnsBlock).not.toContain("module.server.ipv4_address");
    expect(dnsBlock).not.toContain("module.server.ipv6_address");

    const gcoreMain = byPath("modules/gcore-edge/main.tf");
    expect(gcoreMain).toContain('resource "gcore_dns_zone_record" "edge_a"');
    expect(gcoreMain).toContain('resource "gcore_dns_zone_record" "edge_cname"');
    expect(gcoreMain).toContain('resource "gcore_dns_zone_record" "tls_validation"');

    const tfvars = JSON.parse(byPath("/terraform.tfvars.json")) as Record<string, unknown>;
    expect(tfvars.gcore_proxied).toBe(false);
    expect(tfvars.http_allowed_cidrs).toEqual(FASTLY_RANGES);
  });

  it("uses Fastly-Client-IP and Fastly's compact CIDRs in Caddy, nginx, and OpenLiteSpeed without shared-header snippets", () => {
    const caddyCompose = renderEdgeCompose(makeFastlyPlan({ proxy: "caddy" }), FASTLY_RANGES);
    expect(caddyCompose.content).toContain("trusted_proxies static 23.235.32.0/20");
    expect(caddyCompose.content).toContain("client_ip_headers Fastly-Client-IP");

    const olsCompose = renderEdgeCompose(makeFastlyPlan({ proxy: "openlitespeed" }), FASTLY_RANGES);
    expect(olsCompose.content).toContain("Fastly-Client-IP");
    expect(olsCompose.content).toContain("23.235.32.0/20T");

    const nginxFiles = renderEdgeSite(makeFastlyPlan({ proxy: "nginx" }), {
      edgeRanges: FASTLY_RANGES,
      originTls: { hostnames: ["app.example.com", "www.app.example.com"] },
    });
    const site = nginxFiles.find((f) => f.path.endsWith("/shop.conf"))?.content ?? "";
    expect(site).toContain("set_real_ip_from 23.235.32.0/20;");
    expect(site).toContain("real_ip_header Fastly-Client-IP;");
    expect(site).toContain("ssl_verify_client on;");
    expect(site).toContain("pull.pem;");
    expect(site).not.toContain("origin-token");
  });
});
