/**
 * Root Terraform contribution and SecOps plan policies for Bunny.net (ADR 0038 / ADR 0029).
 * Keeping both here ensures `@opscrew/iac-templates` and `@opscrew/secops` never branch on
 * `id === "bunny"`.
 */
import type {
  EdgePlanPolicyResult,
  EdgePlanResource,
  EdgeRootContribution,
  EdgeRootInput,
  EdgeVariableSpec,
} from "@opscrew/contracts";
import { OpsCrewError } from "@opscrew/core";
import { BUNNY_EDGE_MODULE_NAME } from "./module";

/** Deterministic Bunny.net Pull Zone slug (lower-case alphanumeric + hyphens). */
export function bunnyPullzoneName(appName: string, environmentName?: string): string {
  const suffix =
    environmentName === undefined || environmentName === "prod" ? "" : `-${environmentName}`;
  return `opscrew-${appName}${suffix}`.toLowerCase().replace(/[^a-z0-9-]/g, "-");
}

/**
 * Relative record names inside a Bunny DNS zone for `domain` and `www.<domain>`.
 * Returns `""` / `"www"` for the zone apex and `<sublabel>` / `"www.<sublabel>"` for a subdomain.
 */
export function bunnyRecordNames(
  domain: string,
  zone: string | undefined,
): { recordName: string; wwwRecordName: string } {
  const d = domain.toLowerCase().replace(/\.$/, "");
  const z = zone?.toLowerCase().replace(/\.$/, "");
  if (z === undefined || d === z || !d.endsWith(`.${z}`)) {
    return { recordName: "", wwwRecordName: "www" };
  }
  const sub = d.slice(0, -(z.length + 1));
  return { recordName: sub, wwwRecordName: `www.${sub}` };
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

/** Renders Bunny.net's root Terraform module block, variables, outputs, and tfvars. */
export function renderBunnyRoot(input: EdgeRootInput): EdgeRootContribution {
  const { recordName, wwwRecordName } = bunnyRecordNames(input.domain, input.zone);
  if (input.manageDns && (input.dnsZoneId === undefined || input.dnsZoneId <= 0)) {
    throw new OpsCrewError(
      "PHASE_PRECONDITION",
      `OpsCrew could not find a Bunny DNS zone id for "${input.domain}".`,
      {
        hint: "Add the domain's DNS zone in Bunny DNS before running `opscrew provision`.",
      },
    );
  }
  const variables: EdgeVariableSpec[] = [
    ...(input.hasDomainVar
      ? []
      : [
          { name: "domain", type: "string", description: "Hostname of the app." },
          { name: "www", type: "bool", description: "Also serve www.<domain>." },
        ]),
    {
      name: "bunny_pullzone_name",
      type: "string",
      description: "Unique Bunny.net Pull Zone slug for this app.",
    },
    {
      name: "bunny_proxied",
      type: "bool",
      description: "Proxy traffic through the Bunny.net Pull Zone.",
    },
    {
      name: "bunny_waf_custom_rules",
      type: "bool",
      description: "Add Bunny's free BlockRequest Edge Rule for common probes.",
    },
    ...(input.manageDns
      ? [
          {
            name: "bunny_dns_zone_id",
            type: "number",
            description: "Bunny.net DNS zone id.",
          },
          {
            name: "bunny_record_name",
            type: "string",
            description: "Relative record name inside the Bunny DNS zone (empty string for apex).",
          },
          {
            name: "bunny_www_record_name",
            type: "string",
            description: "Relative record name for www.<domain> inside the Bunny DNS zone.",
          },
          ...(input.edgeDns === undefined
            ? []
            : [
                {
                  name: "bunny_dns_zone_name",
                  type: "string",
                  description:
                    "Bunny.net DNS zone name used to compute relative ACME challenge names.",
                },
              ]),
        ]
      : []),
  ];
  const args: [string, string][] = [
    ["pullzone_name", "var.bunny_pullzone_name"],
    ["domain", "var.domain"],
    ["www", "var.www"],
    ...(input.edgeDns === undefined
      ? ([["origin_host", `coalesce(${input.ipv4Expr}, ${input.ipv6Expr})`]] as [string, string][])
      : []),
    ["proxied", "var.bunny_proxied"],
    ["waf_custom_rules", "var.bunny_waf_custom_rules"],
    ["manage_dns", input.manageDns ? "true" : "false"],
    ...(input.manageDns
      ? ([
          ["dns_zone_id", "var.bunny_dns_zone_id"],
          ["record_name", "var.bunny_record_name"],
          ["www_record_name", "var.bunny_www_record_name"],
          ...(input.edgeDns === undefined
            ? ([
                ["ipv4", input.ipv4Expr],
                ["ipv6", input.ipv6Expr],
              ] as [string, string][])
            : ([
                ["split_dns", "true"],
                ["dns_zone_name", "var.bunny_dns_zone_name"],
                ["edge_cname_target", input.edgeDns.cnameTargetExpr],
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
        "# Bunny.net Pull Zone (caching off, verified origin HTTPS, free probe blocking).",
        "# The shared origin-verification header is applied via the Bunny API after apply, never here.",
      ],
      moduleName,
      BUNNY_EDGE_MODULE_NAME,
      args,
    ),
    variables,
    outputLines:
      moduleName === "edge"
        ? [
            ...formatOutput("bunny_pullzone_id", "module.edge.pullzone_id"),
            ...formatOutput("bunny_pullzone_hostname", "module.edge.pullzone_hostname"),
          ]
        : [],
    tfvars: {
      ...(input.hasDomainVar ? {} : { domain: input.domain, www: input.www }),
      bunny_pullzone_name: bunnyPullzoneName(input.appName, input.environmentName),
      bunny_proxied: input.proxied,
      bunny_waf_custom_rules: input.wafCustomRules,
      ...(input.manageDns
        ? {
            bunny_dns_zone_id: input.dnsZoneId,
            bunny_record_name: recordName,
            bunny_www_record_name: wwwRecordName,
            ...(input.edgeDns === undefined
              ? {}
              : { bunny_dns_zone_name: input.zone ?? input.domain }),
          }
        : {}),
    },
  };
}

/** SecOps Terraform plan checks for Bunny.net resources (ADR 0038 D6). */
export function checkBunnyPlan(resources: readonly EdgePlanResource[]): EdgePlanPolicyResult[] {
  const results: EdgePlanPolicyResult[] = [];
  for (const pz of resources.filter((r) => r.type === "bunnynet_pullzone")) {
    results.push({
      id: "bunny-cache-disabled",
      title: "Bunny Pull Zone does not cache dynamic responses by default",
      severity: "medium",
      passed: pz.values.cache_enabled === false,
      detail:
        pz.values.cache_enabled === false
          ? "Bunny Pull Zone has cache_enabled = false so dynamic responses are not cached."
          : "Set cache_enabled = false on the Bunny Pull Zone so dynamic or authenticated responses are not cached.",
      resource: pz.address,
    });
    const origin = Array.isArray(pz.values.origin)
      ? (pz.values.origin[0] as Record<string, unknown> | undefined)
      : (pz.values.origin as Record<string, unknown> | undefined);
    const verifiesSsl = origin?.verify_ssl === true;
    results.push({
      id: "bunny-origin-ssl-verify",
      title: "Bunny Pull Zone verifies the origin TLS certificate",
      severity: "high",
      passed: verifiesSsl,
      detail: verifiesSsl
        ? "Bunny Pull Zone verifies the origin server's TLS certificate."
        : "Set origin.verify_ssl = true on the Bunny Pull Zone so edge-to-origin traffic is verified.",
      resource: pz.address,
    });
  }
  for (const rule of resources.filter((r) => r.type === "bunnynet_pullzone_edgerule")) {
    const actions = Array.isArray(rule.values.actions)
      ? (rule.values.actions as Record<string, unknown>[])
      : [];
    const setsHeader = actions.some((action) => action?.type === "SetRequestHeader");
    if (setsHeader) {
      results.push({
        id: "bunny-no-secret-header-in-state",
        title: "Origin verification header is not stored in Terraform state",
        severity: "critical",
        passed: false,
        detail:
          "A bunnynet_pullzone_edgerule with SetRequestHeader stores header values in Terraform state. Apply OpsCrew's origin-verification header through the Bunny API connector instead.",
        resource: rule.address,
      });
    }
  }
  return results;
}
