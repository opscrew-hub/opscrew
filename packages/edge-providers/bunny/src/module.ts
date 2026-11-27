/**
 * Vendored Terraform module `bunny-edge` for Bunny.net Pull Zone, custom hostnames, free
 * probe-blocking Edge Rule, and optional Bunny DNS records (`BunnyWay/bunnynet` `~> 0.20.2`).
 *
 * Security invariant (ADR 0038 D6): this module NEVER contains a `SetRequestHeader` Edge Rule or
 * any origin-verification secret. OpsCrew applies that header exclusively through the typed Bunny
 * API connector after apply so the secret never lands in Terraform state.
 */

export const BUNNY_EDGE_MODULE_NAME = "bunny-edge";

const VERSIONS_TF = `terraform {
  required_version = ">= 1.6.0"

  required_providers {
    bunnynet = {
      source  = "BunnyWay/bunnynet"
      version = "~> 0.20.2"
    }
  }
}
`;

const VARIABLES_TF = `variable "pullzone_name" {
  description = "Unique Bunny.net Pull Zone name (slug) for this app."
  type        = string
}

variable "domain" {
  description = "Primary hostname of the app, for example app.example.com."
  type        = string
}

variable "www" {
  description = "Also serve www.<domain>."
  type        = bool
  default     = false
}

variable "origin_host" {
  description = "Origin server IPv4 address or hostname reached by Bunny.net over verified HTTPS."
  type        = string
  default     = ""
}

variable "waf_custom_rules" {
  description = "Add Bunny's free BlockRequest Edge Rule for common secret and admin-panel probes."
  type        = bool
  default     = true
}

variable "manage_dns" {
  description = "Manage DNS records in a Bunny DNS zone (true when dns.provider is bunny)."
  type        = bool
  default     = false
}

variable "dns_zone_id" {
  description = "Bunny DNS zone id when manage_dns is true."
  type        = number
  default     = null
}

variable "record_name" {
  description = "Relative record name inside the Bunny DNS zone (empty string for zone apex)."
  type        = string
  default     = ""
}

variable "www_record_name" {
  description = "Relative record name for www.<domain> inside the Bunny DNS zone."
  type        = string
  default     = "www"
}

variable "proxied" {
  description = "Proxy traffic through the Bunny Pull Zone (false for Bunny DNS only)."
  type        = bool
  default     = true
}

variable "ipv4" {
  description = "Origin server public IPv4 address (for DNS-only A record when proxied is false)."
  type        = string
  default     = null
}

variable "ipv6" {
  description = "Origin server public IPv6 address (for DNS-only AAAA record when proxied is false)."
  type        = string
  default     = null
}

variable "dns_zone_name" {
  description = "DNS zone name (for example example.com) used to derive relative ACME challenge names."
  type        = string
  default     = null
}

variable "split_dns" {
  description = "True when Bunny hosts DNS for a separate edge provider (refuses falling back to origin IPs)."
  type        = bool
  default     = false
}

variable "edge_cname_target" {
  description = "External edge CNAME/Flatten target (for example Fastly) when Bunny hosts DNS for another edge."
  type        = string
  default     = null
}

variable "tls_validation_records" {
  description = "Optional ACME DNS validation records required by an external edge provider."
  type = map(object({
    type  = string
    name  = string
    value = string
  }))
  default = {}
}
`;

const MAIN_TF = `# Bunny.net Pull Zone: dynamic-app-safe defaults (caching disabled, verified origin HTTPS, Host
# header forwarded). The shared origin-verification header is applied outside Terraform via the
# Bunny.net API so its secret never enters Terraform state (ADR 0038 D6).
resource "bunnynet_pullzone" "this" {
  count         = var.proxied ? 1 : 0
  name          = var.pullzone_name
  cache_enabled = false

  origin {
    type                = "OriginUrl"
    url                 = "https://\${strcontains(var.origin_host, ":") ? "[\${var.origin_host}]" : var.origin_host}"
    verify_ssl          = true
    forward_host_header = true
  }

  routing {
    tier = "Standard"
  }
}

resource "bunnynet_pullzone_hostname" "domain" {
  count       = var.proxied ? 1 : 0
  pullzone    = bunnynet_pullzone.this[0].id
  name        = var.domain
  tls_enabled = true
  force_ssl   = true
}

resource "bunnynet_pullzone_hostname" "www" {
  count       = var.proxied && var.www ? 1 : 0
  pullzone    = bunnynet_pullzone.this[0].id
  name        = "www.\${var.domain}"
  tls_enabled = true
  force_ssl   = true
}

# Included free on every Pull Zone: blocks common secret and admin-panel probes at the edge.
resource "bunnynet_pullzone_edgerule" "block_probes" {
  count       = var.proxied && var.waf_custom_rules ? 1 : 0
  pullzone    = bunnynet_pullzone.this[0].id
  description = "OpsCrew block common probes"
  enabled     = true
  match_type  = "MatchAny"

  actions = [
    {
      type       = "BlockRequest"
      parameter1 = null
      parameter2 = null
      parameter3 = null
    }
  ]

  triggers = [
    {
      type       = "Url"
      match_type = "MatchAny"
      patterns = [
        "*/.env*",
        "*/.git/*",
        "*/wp-admin*",
        "*/wp-login.php*",
        "*/xmlrpc.php*",
        "*/phpmyadmin*",
      ]
      parameter1 = null
      parameter2 = null
    }
  ]
}

# Bunny DNS records (only when dns.provider is "bunny"): PullZone record flattens apex routing
# natively when proxied; A/AAAA/CNAME records point directly at the server when DNS-only.
resource "bunnynet_dns_record" "pullzone" {
  count       = var.manage_dns && var.proxied ? 1 : 0
  zone        = var.dns_zone_id
  name        = var.record_name
  type        = "PullZone"
  pullzone_id = bunnynet_pullzone.this[0].id
  enabled     = true
}

resource "bunnynet_dns_record" "www_pullzone" {
  count       = var.manage_dns && var.proxied && var.www ? 1 : 0
  zone        = var.dns_zone_id
  name        = var.www_record_name
  type        = "PullZone"
  pullzone_id = bunnynet_pullzone.this[0].id
  enabled     = true
}

resource "bunnynet_dns_record" "a" {
  count   = var.manage_dns && !var.proxied && !var.split_dns && var.ipv4 != null ? 1 : 0
  zone    = var.dns_zone_id
  name    = var.record_name
  type    = "A"
  value   = var.ipv4
  enabled = true
}

resource "bunnynet_dns_record" "aaaa" {
  count   = var.manage_dns && !var.proxied && !var.split_dns && var.ipv6 != null ? 1 : 0
  zone    = var.dns_zone_id
  name    = var.record_name
  type    = "AAAA"
  value   = var.ipv6
  enabled = true
}

resource "bunnynet_dns_record" "www_cname" {
  count   = var.manage_dns && !var.proxied && !var.split_dns && var.www ? 1 : 0
  zone    = var.dns_zone_id
  name    = var.www_record_name
  type    = "CNAME"
  value   = var.domain
  enabled = true
}

# Split-DNS routing to a separate edge proxy (for example Fastly): Bunny Flatten at apex, CNAME on
# subdomains, plus ACME DNS validation records for the edge's managed TLS certificate.
resource "bunnynet_dns_record" "edge_target" {
  count   = var.manage_dns && !var.proxied && var.split_dns ? 1 : 0
  zone    = var.dns_zone_id
  name    = var.record_name
  type    = var.record_name == "" ? "Flatten" : "CNAME"
  value   = var.edge_cname_target != null ? trimsuffix(var.edge_cname_target, ".") : ""
  enabled = true

  lifecycle {
    precondition {
      condition     = var.edge_cname_target != null && var.edge_cname_target != ""
      error_message = "An external edge CNAME target is required in split-DNS mode; refusing to fall back to the origin server IP."
    }
  }
}

resource "bunnynet_dns_record" "www_edge_target" {
  count   = var.manage_dns && !var.proxied && var.split_dns && var.www ? 1 : 0
  zone    = var.dns_zone_id
  name    = var.www_record_name
  type    = "CNAME"
  value   = var.edge_cname_target != null ? trimsuffix(var.edge_cname_target, ".") : ""
  enabled = true

  lifecycle {
    precondition {
      condition     = var.edge_cname_target != null && var.edge_cname_target != ""
      error_message = "An external edge CNAME target is required in split-DNS mode; refusing to fall back to the origin server IP."
    }
  }
}

resource "bunnynet_dns_record" "tls_validation" {
  for_each = var.manage_dns ? var.tls_validation_records : {}
  zone     = var.dns_zone_id
  name     = var.dns_zone_name != null ? trimsuffix(trimsuffix(each.value.name, "."), ".\${var.dns_zone_name}") : trimsuffix(each.value.name, ".")
  type     = each.value.type
  value    = trimsuffix(each.value.value, ".")
  ttl      = 60
  enabled  = true
}
`;

const OUTPUTS_TF = `output "pullzone_id" {
  description = "Numeric Bunny.net Pull Zone id (null when DNS-only)."
  value       = one(bunnynet_pullzone.this[*].id)
}

output "pullzone_hostname" {
  description = "Bunny.net Pull Zone target hostname (<name>.b-cdn.net), null when DNS-only."
  value       = var.proxied ? "\${var.pullzone_name}.b-cdn.net" : null
}

output "url" {
  description = "Public URL of the app."
  value       = "https://\${var.domain}"
}
`;

export const BUNNY_EDGE_MODULE_FILES: Readonly<Record<string, string>> = {
  "versions.tf": VERSIONS_TF,
  "variables.tf": VARIABLES_TF,
  "main.tf": MAIN_TF,
  "outputs.tf": OUTPUTS_TF,
};
