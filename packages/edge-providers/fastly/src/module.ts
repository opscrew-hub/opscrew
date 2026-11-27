/**
 * Vendored Terraform module `fastly-edge` for Fastly VCL service, free VCL probe-blocking
 * (`condition` + `response_object` 403), dynamic-app cache bypass (`action = "pass"`), and
 * managed TLS subscription (`fastly/fastly` `~> 10.4`).
 *
 * Security invariant (ADR 0038 D6): this module NEVER sets `ssl_client_key` on `backend`, so the
 * origin mTLS private key never enters Terraform state. OpsCrew configures `ssl_client_cert` +
 * `ssl_client_key` via the typed Fastly API client after apply, reusing `pull.pem` on the server.
 */

export const FASTLY_EDGE_MODULE_NAME = "fastly-edge";
export const FASTLY_BACKEND_NAME = "opscrew_origin";

const VERSIONS_TF = `terraform {
  required_version = ">= 1.6.0"

  required_providers {
    fastly = {
      source  = "fastly/fastly"
      version = "~> 10.4"
    }
  }
}
`;

const VARIABLES_TF = `variable "service_name" {
  description = "Name of the Fastly VCL service for this app."
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
  description = "Origin server IPv4 address or hostname reached by Fastly over verified HTTPS."
  type        = string
}

variable "waf_custom_rules" {
  description = "Add Fastly's free VCL condition + 403 response_object blocking common probes."
  type        = bool
  default     = true
}
`;

const MAIN_TF = `locals {
  tls_hosts = var.www ? [var.domain, "www.\${var.domain}"] : [var.domain]
}

# Fastly VCL service: dynamic-app-safe defaults (cache bypass via action = "pass", force HTTPS,
# verified HTTPS to origin). Backend mTLS client key and origin CA are applied outside Terraform
# via the Fastly API so the private key never enters Terraform state (ADR 0038 D6), and
# lifecycle.ignore_changes prevents later Terraform applies from wiping mTLS (causing HTTP 503).
resource "fastly_service_vcl" "this" {
  name = var.service_name

  domain {
    name    = var.domain
    comment = "Managed by OpsCrew"
  }

  dynamic "domain" {
    for_each = var.www ? ["www.\${var.domain}"] : []
    content {
      name    = domain.value
      comment = "Managed by OpsCrew"
    }
  }

  backend {
    name              = "opscrew_origin"
    address           = var.origin_host
    port              = 443
    use_ssl           = true
    ssl_check_cert    = true
    ssl_cert_hostname = var.domain
    ssl_sni_hostname  = var.domain
    override_host     = var.domain
  }

  request_setting {
    name      = "OpsCrew dynamic pass and force HTTPS"
    action    = "pass"
    force_ssl = true
  }

  # Included free on every Fastly tier: blocks common secret and admin-panel probes at the edge.
  dynamic "condition" {
    for_each = var.waf_custom_rules ? [1] : []
    content {
      name      = "OpsCrew block common probes"
      type      = "REQUEST"
      statement = "req.url.path ~ \\"^/(\\\\.env|\\\\.git/|wp-admin|wp-login\\\\.php|xmlrpc\\\\.php|phpmyadmin)\\""
    }
  }

  dynamic "response_object" {
    for_each = var.waf_custom_rules ? [1] : []
    content {
      name              = "OpsCrew probe 403"
      status            = 403
      response          = "Forbidden"
      content_type      = "text/plain"
      content           = "Forbidden"
      request_condition = "OpsCrew block common probes"
    }
  }

  force_destroy = true

  lifecycle {
    ignore_changes = [backend]
  }
}

# Default Fastly TLS configuration exposing anycast IPv4/IPv6 and CNAME targets for DNS.
data "fastly_tls_configuration" "default" {
  default = true
}

# Managed TLS certificate (free up to 5 domains on Fastly's developer tier).
resource "fastly_tls_subscription" "this" {
  domains               = local.tls_hosts
  certificate_authority = "certainly"
  configuration_id      = data.fastly_tls_configuration.default.id
  depends_on            = [fastly_service_vcl.this]
}
`;

const OUTPUTS_TF = `output "service_id" {
  description = "Fastly VCL service id."
  value       = fastly_service_vcl.this.id
}

output "backend_name" {
  description = "Fastly backend name configured for origin mTLS."
  value       = "opscrew_origin"
}

output "tls_subscription_id" {
  description = "Fastly managed TLS subscription id."
  value       = fastly_tls_subscription.this.id
}

output "edge_cname_target" {
  description = "Fastly TLS configuration CNAME target for DNS routing."
  value       = try([for r in data.fastly_tls_configuration.default.dns_records : r.record_value if r.record_type == "CNAME"][0], null)
}

output "edge_ipv4_targets" {
  description = "Fastly TLS configuration anycast IPv4 A record targets."
  value       = [for r in data.fastly_tls_configuration.default.dns_records : r.record_value if r.record_type == "A"]
}

output "edge_ipv6_targets" {
  description = "Fastly TLS configuration anycast IPv6 AAAA record targets."
  value       = [for r in data.fastly_tls_configuration.default.dns_records : r.record_value if r.record_type == "AAAA"]
}

output "tls_validation_records" {
  description = "ACME DNS validation records keyed by plan-time-known hostnames for fastly_tls_subscription_validation."
  value = {
    for host in local.tls_hosts :
    host => [
      for challenge in fastly_tls_subscription.this.managed_dns_challenges : {
        type  = challenge.record_type
        name  = challenge.record_name
        value = challenge.record_value
      }
      if lower(trimsuffix(challenge.record_name, ".")) == lower("_acme-challenge.\${host}")
    ][0]
  }
}

output "url" {
  description = "Public URL of the app."
  value       = "https://\${var.domain}"
}
`;

export const FASTLY_EDGE_MODULE_FILES: Readonly<Record<string, string>> = {
  "versions.tf": VERSIONS_TF,
  "variables.tf": VARIABLES_TF,
  "main.tf": MAIN_TF,
  "outputs.tf": OUTPUTS_TF,
};
