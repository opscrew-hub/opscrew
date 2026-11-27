/**
 * Root Terraform contribution and SecOps plan policies for Fastly (ADR 0038 / ADR 0029).
 * Keeping both here ensures `@opscrew/iac-templates` and `@opscrew/secops` never branch on
 * `id === "fastly"`.
 */
import type {
  EdgePlanPolicyResult,
  EdgePlanResource,
  EdgeRootContribution,
  EdgeRootInput,
  EdgeVariableSpec,
} from "@opscrew/contracts";
import { FASTLY_EDGE_MODULE_NAME } from "./module";

/** Deterministic Fastly VCL service name (lower-case alphanumeric + hyphens). */
export function fastlyServiceName(appName: string, environmentName?: string): string {
  const suffix =
    environmentName === undefined || environmentName === "prod" ? "" : `-${environmentName}`;
  return `opscrew-${appName}${suffix}`.toLowerCase().replace(/[^a-z0-9-]/g, "-");
}

function formatModuleBlock(
  comment: readonly string[],
  name: string,
  source: string,
  args: readonly (readonly [string, string])[],
): string[] {
  const width = Math.max(...args.map(([key]) => key.length));
  return [
    ...comment,
    `module "${name}" {`,
    `  source = "../modules/${source}"`,
    "",
    ...args.map(([key, value]) => `  ${key.padEnd(width)} = ${value}`),
    "}",
    "",
  ];
}

function formatOutput(name: string, expr: string): string[] {
  return [`output "${name}" {`, `  value = ${expr}`, "}", ""];
}

/** Renders Fastly's root Terraform module block, variables, outputs, and tfvars. */
export function renderFastlyRoot(input: EdgeRootInput): EdgeRootContribution {
  const variables: EdgeVariableSpec[] = [
    ...(input.hasDomainVar
      ? []
      : [
          { name: "domain", type: "string", description: "Hostname of the app." },
          { name: "www", type: "bool", description: "Also serve www.<domain>." },
        ]),
    {
      name: "fastly_service_name",
      type: "string",
      description: "Name of the Fastly VCL service for this app.",
    },
    {
      name: "fastly_waf_custom_rules",
      type: "bool",
      description: "Add Fastly's free VCL condition + 403 response_object for common probes.",
    },
  ];
  const args: [string, string][] = [
    ["service_name", "var.fastly_service_name"],
    ["domain", "var.domain"],
    ["www", "var.www"],
    ["origin_host", `coalesce(${input.ipv4Expr}, ${input.ipv6Expr})`],
    ["waf_custom_rules", "var.fastly_waf_custom_rules"],
  ];
  const moduleName = input.moduleName ?? "edge";
  const validationLines = [
    "# Completes Fastly's managed TLS ACME validation once the DNS records are created.",
    `resource "fastly_tls_subscription_validation" "${moduleName}" {`,
    `  subscription_id = module.${moduleName}.tls_subscription_id`,
    ...(input.dependsOnDnsModule === true ? ["  depends_on      = [module.dns]"] : []),
    "}",
    "",
  ];
  return {
    mainLines: [
      ...formatModuleBlock(
        [
          "# Fastly VCL service (dynamic pass, verified origin HTTPS, free VCL 403 probe blocking, managed TLS).",
          "# Origin mTLS ssl_client_key and ssl_ca_cert are configured via the Fastly API after apply, never in Terraform state.",
        ],
        moduleName,
        FASTLY_EDGE_MODULE_NAME,
        args,
      ),
      ...validationLines,
    ],
    variables,
    outputLines: [
      ...formatOutput("fastly_service_id", `module.${moduleName}.service_id`),
      ...formatOutput("fastly_backend_name", `module.${moduleName}.backend_name`),
      ...formatOutput("fastly_tls_subscription_id", `module.${moduleName}.tls_subscription_id`),
      ...formatOutput("fastly_edge_cname_target", `module.${moduleName}.edge_cname_target`),
      ...formatOutput(
        "fastly_tls_validation_records",
        `module.${moduleName}.tls_validation_records`,
      ),
    ],
    tfvars: {
      ...(input.hasDomainVar ? {} : { domain: input.domain, www: input.www }),
      fastly_service_name: fastlyServiceName(input.appName, input.environmentName),
      fastly_waf_custom_rules: input.wafCustomRules,
    },
  };
}

/** SecOps Terraform plan checks for Fastly VCL resources (ADR 0038 D6). */
export function checkFastlyPlan(resources: readonly EdgePlanResource[]): EdgePlanPolicyResult[] {
  const results: EdgePlanPolicyResult[] = [];
  for (const svc of resources.filter((r) => r.type === "fastly_service_vcl")) {
    const reqSettings = Array.isArray(svc.values.request_setting)
      ? (svc.values.request_setting as Record<string, unknown>[])
      : [];
    const hasPass = reqSettings.some((s) => s?.action === "pass");
    results.push({
      id: "fastly-cache-pass",
      title: "Fastly VCL service bypasses caching for dynamic responses by default",
      severity: "medium",
      passed: hasPass,
      detail: hasPass
        ? 'Fastly VCL service sets request_setting action = "pass" so dynamic responses are not cached.'
        : 'Add a request_setting block with action = "pass" on fastly_service_vcl so dynamic responses are not cached.',
      resource: svc.address,
    });
    const backends = Array.isArray(svc.values.backend)
      ? (svc.values.backend as Record<string, unknown>[])
      : [];
    for (const backend of backends) {
      const verifiesSsl = backend?.use_ssl === true && backend?.ssl_check_cert === true;
      results.push({
        id: "fastly-origin-ssl-verify",
        title: "Fastly backend verifies the origin TLS certificate",
        severity: "high",
        passed: verifiesSsl,
        detail: verifiesSsl
          ? "Fastly backend connects over HTTPS with ssl_check_cert = true."
          : "Set use_ssl = true and ssl_check_cert = true on the Fastly backend.",
        resource: svc.address,
      });
      if (typeof backend?.ssl_client_key === "string" && backend.ssl_client_key.length > 0) {
        results.push({
          id: "fastly-no-client-key-in-state",
          title: "Origin mTLS client private key is not stored in Terraform state",
          severity: "critical",
          passed: false,
          detail:
            "Setting backend.ssl_client_key in fastly_service_vcl persists the mTLS private key in Terraform state. Configure Fastly origin mTLS through the Fastly API connector instead.",
          resource: svc.address,
        });
      }
    }
  }
  return results;
}
