/**
 * Root Terraform contribution and SecOps plan policies for Gcore (ADR 0038 / ADR 0029).
 * Keeping both here ensures `@opscrew/iac-templates` and `@opscrew/secops` never branch on
 * `id === "gcore"`.
 */
import type {
  EdgePlanPolicyResult,
  EdgePlanResource,
  EdgeRootContribution,
  EdgeRootInput,
  EdgeVariableSpec,
} from "@opscrew/contracts";
import { GCORE_EDGE_MODULE_NAME } from "./module";

/** Deterministic Gcore CDN origin group name (lower-case alphanumeric + hyphens). */
export function gcoreOriginGroupName(appName: string, environmentName?: string): string {
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

/** Renders Gcore's root Terraform module block, variables, outputs, and tfvars. */
export function renderGcoreRoot(input: EdgeRootInput): EdgeRootContribution {
  const variables: EdgeVariableSpec[] = [
    ...(input.hasDomainVar
      ? []
      : [
          { name: "domain", type: "string", description: "Hostname of the app." },
          { name: "www", type: "bool", description: "Also serve www.<domain>." },
        ]),
    {
      name: "gcore_origin_group_name",
      type: "string",
      description: "Name of the Gcore CDN origin group for this app.",
    },
    {
      name: "gcore_proxied",
      type: "bool",
      description: "Proxy traffic through Gcore CDN.",
    },
    {
      name: "gcore_waf_custom_rules",
      type: "bool",
      description: "Add Gcore's free force_return 403 rule for common probes.",
    },
    ...(input.manageDns
      ? [
          {
            name: "gcore_dns_zone",
            type: "string",
            description: "Gcore DNS zone name (for example example.com).",
          },
        ]
      : []),
  ];
  const args: [string, string][] = [
    ["origin_group_name", "var.gcore_origin_group_name"],
    ["domain", "var.domain"],
    ["www", "var.www"],
    ...(input.edgeDns === undefined
      ? ([["origin_host", `coalesce(${input.ipv4Expr}, ${input.ipv6Expr})`]] as [string, string][])
      : []),
    ["proxied", "var.gcore_proxied"],
    ["waf_custom_rules", "var.gcore_waf_custom_rules"],
    ["manage_dns", input.manageDns ? "true" : "false"],
    ...(input.manageDns
      ? ([
          ["dns_zone", "var.gcore_dns_zone"],
          ...(input.edgeDns === undefined
            ? ([
                ["ipv4", input.ipv4Expr],
                ["ipv6", input.ipv6Expr],
              ] as [string, string][])
            : ([
                ["split_dns", "true"],
                ["edge_cname_target", input.edgeDns.cnameTargetExpr],
                ...(input.edgeDns.ipv4TargetsExpr === undefined
                  ? []
                  : ([["edge_ipv4_targets", input.edgeDns.ipv4TargetsExpr]] as [string, string][])),
                ...(input.edgeDns.ipv6TargetsExpr === undefined
                  ? []
                  : ([["edge_ipv6_targets", input.edgeDns.ipv6TargetsExpr]] as [string, string][])),
                ...(input.edgeDns.tlsValidationRecordsExpr === undefined
                  ? []
                  : ([["tls_validation_records", input.edgeDns.tlsValidationRecordsExpr]] as [
                      string,
                      string,
                    ][])),
              ] as [string, string][])),
        ] as [string, string][])
      : []),
  ];
  const moduleName = input.moduleName ?? "edge";
  return {
    mainLines: formatModuleBlock(
      [
        "# Gcore CDN resource (caching off, HTTPS to origin, free force_return 403 probe blocking).",
        "# The shared origin-verification header is applied via the Gcore API after apply, never here.",
      ],
      moduleName,
      GCORE_EDGE_MODULE_NAME,
      args,
    ),
    variables,
    outputLines:
      moduleName === "edge"
        ? [...formatOutput("gcore_cdn_resource_id", "module.edge.cdn_resource_id")]
        : [],
    tfvars: {
      ...(input.hasDomainVar ? {} : { domain: input.domain, www: input.www }),
      gcore_origin_group_name: gcoreOriginGroupName(input.appName, input.environmentName),
      gcore_proxied: input.proxied,
      gcore_waf_custom_rules: input.wafCustomRules,
      ...(input.manageDns
        ? {
            gcore_dns_zone: input.zone ?? input.domain,
          }
        : {}),
    },
  };
}

/** SecOps Terraform plan checks for Gcore CDN resources (ADR 0038 D6). */
export function checkGcorePlan(resources: readonly EdgePlanResource[]): EdgePlanPolicyResult[] {
  const results: EdgePlanPolicyResult[] = [];
  for (const cdn of resources.filter((r) => r.type === "gcore_cdn_resource")) {
    const opts = Array.isArray(cdn.values.options)
      ? (cdn.values.options[0] as Record<string, unknown> | undefined)
      : (cdn.values.options as Record<string, unknown> | undefined);
    const cacheBlock = Array.isArray(opts?.edge_cache_settings)
      ? (opts?.edge_cache_settings[0] as Record<string, unknown> | undefined)
      : (opts?.edge_cache_settings as Record<string, unknown> | undefined);
    const cacheDisabled = cacheBlock?.enabled === false;
    results.push({
      id: "gcore-cache-disabled",
      title: "Gcore CDN resource does not cache dynamic responses by default",
      severity: "medium",
      passed: cacheDisabled,
      detail: cacheDisabled
        ? "Gcore CDN resource has edge_cache_settings.enabled = false so dynamic responses are not cached."
        : "Set edge_cache_settings.enabled = false on the Gcore CDN resource so dynamic or authenticated responses are not cached.",
      resource: cdn.address,
    });
    const originHttps = cdn.values.origin_protocol === "HTTPS";
    results.push({
      id: "gcore-origin-https",
      title: "Gcore CDN connects to the origin server over HTTPS",
      severity: "high",
      passed: originHttps,
      detail: originHttps
        ? 'Gcore CDN resource uses origin_protocol = "HTTPS".'
        : 'Set origin_protocol = "HTTPS" on the Gcore CDN resource so edge-to-origin traffic is encrypted.',
      resource: cdn.address,
    });
    const edgeHttps = cdn.values.ssl_enabled === true;
    results.push({
      id: "gcore-edge-https",
      title: "Gcore CDN serves visitors over HTTPS with an edge certificate",
      severity: "high",
      passed: edgeHttps,
      detail: edgeHttps
        ? "Gcore CDN resource has ssl_enabled = true."
        : "Set ssl_enabled = true (with a gcore_cdn_sslcert) on the Gcore CDN resource so HTTPS delivery works.",
      resource: cdn.address,
    });
    const staticHeaders = Array.isArray(opts?.static_request_headers)
      ? (opts?.static_request_headers[0] as Record<string, unknown> | undefined)
      : (opts?.static_request_headers as Record<string, unknown> | undefined);
    if (staticHeaders?.enabled === true) {
      results.push({
        id: "gcore-no-secret-header-in-state",
        title: "Origin verification header is not stored in Terraform state",
        severity: "critical",
        passed: false,
        detail:
          "Setting gcore_cdn_resource.options.static_request_headers in Terraform persists header values in Terraform state. Apply OpsCrew's origin-verification header through the Gcore API connector instead.",
        resource: cdn.address,
      });
    }
  }
  return results;
}
