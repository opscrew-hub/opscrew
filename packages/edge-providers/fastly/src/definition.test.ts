import { describe, expect, it } from "vitest";
import { definition } from "./definition";
import { FASTLY_EDGE_MODULE_FILES } from "./module";
import { renderFastlyRoot } from "./root";

describe("@opscrew/edge-provider-fastly", () => {
  it("exposes Fastly edge-only capabilities, mTLS client cert auth, compact-cidrs, Fastly-Client-IP, and Terraform metadata", () => {
    expect(definition.id).toBe("fastly");
    expect(definition.displayName).toBe("Fastly");
    expect(definition.capabilities).toEqual({
      originAuth: "mtls-client-cert",
      originIpFiltering: "compact-cidrs",
      realIpHeader: "Fastly-Client-IP",
    });
    expect(definition.credentials.envVars).toEqual(["FASTLY_API_KEY"]);
    expect(definition.terraform.provider).toEqual({
      name: "fastly",
      source: "fastly/fastly",
      version: "~> 10.4",
    });
    expect(definition.terraform.dnsRecordResourceType).toBeUndefined();
    expect(definition.terraform.module?.name).toBe("fastly-edge");
    expect(definition.terraform.root?.resourceIdOutput).toBe("fastly_service_id");
    expect(definition.terraform.root?.backendNameOutput).toBe("fastly_backend_name");
    expect(definition.terraform.root?.edgeDnsOutputs).toEqual({
      cnameTarget: "edge_cname_target",
      ipv4Targets: "edge_ipv4_targets",
      ipv6Targets: "edge_ipv6_targets",
      tlsValidationRecords: "tls_validation_records",
    });
    expect(typeof definition.secops?.checkPlan).toBe("function");
    expect(typeof definition.connector?.verifyCredentials).toBe("function");
    expect(typeof definition.connector?.getIpRanges).toBe("function");
  });

  it("renders a safe fastly-edge Terraform module with dynamic pass, free VCL 403 probe blocking, managed TLS, and no ssl_client_key", () => {
    const main = FASTLY_EDGE_MODULE_FILES["main.tf"] ?? "";
    const outputs = FASTLY_EDGE_MODULE_FILES["outputs.tf"] ?? "";
    expect(main).toContain('resource "fastly_service_vcl" "this"');
    expect(main).toContain('action    = "pass"');
    expect(main).toContain("force_ssl = true");
    expect(main).toContain("use_ssl           = true");
    expect(main).toContain("ssl_check_cert    = true");
    expect(main).toContain('dynamic "condition"');
    expect(main).toContain('dynamic "response_object"');
    expect(main).toContain("status            = 403");
    for (const part of ["\\.env", "\\.git/", "wp-admin", "wp-login", "xmlrpc", "phpmyadmin"]) {
      expect(main).toContain(part);
    }
    expect(main).toContain('data "fastly_tls_configuration" "default"');
    expect(main).toContain('resource "fastly_tls_subscription" "this"');
    expect(main).toContain("configuration_id      = data.fastly_tls_configuration.default.id");
    expect(main).toContain("ignore_changes = [backend]");
    expect(outputs).toContain('output "edge_cname_target"');
    expect(outputs).toContain("try([for r in data.fastly_tls_configuration.default.dns_records");
    expect(outputs).not.toContain(
      "one([for r in data.fastly_tls_configuration.default.dns_records",
    );
    expect(outputs).toContain('output "edge_ipv4_targets"');
    expect(outputs).toContain('output "edge_ipv6_targets"');
    expect(outputs).toContain('output "tls_validation_records"');
    expect(outputs).toContain("for host in local.tls_hosts :");
    expect(outputs).toContain("fastly_tls_subscription.this.managed_dns_challenges");
    // Security invariant (ADR 0038 D6): mTLS private key NEVER enters Terraform state.
    expect(main).not.toContain("ssl_client_key");
  });

  it("falls back to ipv6Expr for origin_host, emits fastly_tls_subscription_validation, and uses moduleName consistently", () => {
    const root = renderFastlyRoot({
      moduleName: "dns",
      appName: "shop",
      domain: "shop.example.com",
      zone: "example.com",
      www: false,
      proxied: true,
      manageDns: false,
      wafCustomRules: true,
      ipv4Expr: "module.server.ipv4_address",
      ipv6Expr: "module.server.ipv6_address",
      hasDomainVar: false,
      dependsOnDnsModule: true,
    });
    const main = root.mainLines.join("\n");
    const outputs = root.outputLines.join("\n");
    expect(main).toContain(
      "origin_host      = coalesce(module.server.ipv4_address, module.server.ipv6_address)",
    );
    expect(main).toContain('module "dns" {');
    expect(main).toContain('resource "fastly_tls_subscription_validation" "dns" {');
    expect(main).toContain("subscription_id = module.dns.tls_subscription_id");
    expect(main).toContain("depends_on      = [module.dns]");
    expect(outputs).toContain("value = module.dns.service_id");
    expect(outputs).toContain("value = module.dns.backend_name");
    expect(outputs).toContain("value = module.dns.tls_subscription_id");
    expect(outputs).not.toContain("module.edge.");
  });
});
