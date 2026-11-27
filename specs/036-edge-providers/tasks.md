# Tasks: Edge providers in place of Cloudflare's proxy

**Feature**: `036-edge-providers` | **Issue**: `#29` | **Plan**: [plan.md](plan.md)

## PR 1 — Edge provider contract with Cloudflare behind it

- [x] **T3601 — Research, ADR 0038 & specs**: Complete official-source research (`research.md` R1–R7), record core lead decisions from `#29`, write `docs/adr/0038-edge-provider-contract.md`, `spec.md`, `plan.md`, and `tasks.md`.
- [x] **T3602 — Edge provider contract (`@opscrew/contracts`)**: Add `packages/contracts/src/edge-provider.ts` (`EDGE_PROVIDER_CONTRACT_VERSION = 1`, `EdgeProviderDefinition`, capability/auth/IP-filtering/terraform/texts types) and export from `packages/contracts/src/index.ts`.
- [x] **T3603 — Cloudflare edge provider & registry (`packages/edge-providers/`)**:
  - Add `"packages/edge-providers/*"` to `pnpm-workspace.yaml`.
  - Implement `packages/edge-providers/cloudflare` (`@opscrew/edge-provider-cloudflare`) exporting Cloudflare's `EdgeProviderDefinition`.
  - Implement `packages/edge-providers/registry` (`@opscrew/edge-providers`) with `validateEdgeProvider`, `EDGE_PROVIDERS`, `edgeProvider`, and conformance/validation tests.
- [x] **T3604 — Rename `security.httpAllowedFrom` to `"edge"` (`@opscrew/plan-schema`)**:
  - Change `security.httpAllowedFrom` from `"any" | "cloudflare"` to `"any" | "edge"` with explicit refusal message for `"cloudflare"` (`set security.httpAllowedFrom to "edge"`).
  - Update defaults, preview check, own-server check, `schemas/plan.schema.json`, and unit tests.
- [x] **T3605 — Wire `@opscrew/edge-providers` and `"edge"` across packages**:
  - Wire `@opscrew/edge-providers` into `@opscrew/iac-templates` (`edge/index.ts`, `edge/nginx.ts`, `edge/openlitespeed.ts`, `predicates.ts`) and `@opscrew/secops` (`policies/plan.ts`, `deep/testssl.ts`) preserving byte-for-byte rendered output for Cloudflare.
  - Update `httpAllowedFrom` checks/fixtures across `iac-templates`, `secops`, `agents`, `mcp-server`, and `cli`.
- [x] **T3606 — Verify, commit, push & open PR 1**:
  - Run `pnpm format`, `pnpm lint`, `pnpm typecheck`, all affected package tests, and `opscrew` CLI build.
  - Push `036-edge-providers` to `fork` and open PR 1 `feat(036): edge provider contract with Cloudflare behind it` (referencing `#29`).

## Follow-up PRs (after PR 1 merges)

- [x] **PR 2 — Bunny.net (`@opscrew/edge-provider-bunny`)**: `dns.provider: "bunny"`, `dns.edge: "bunny"`, Pull Zone + Bunny DNS Terraform module, connector-applied origin verification header (never in Terraform state), server proxy shared-header gate (Caddy/nginx/OpenLiteSpeed), `opscrew rotate` support, unit tests, and `docs/guide/bunny.md`.
- [x] **PR 3 — Gcore (`@opscrew/edge-provider-gcore`)**: `dns.provider: "gcore"`, `dns.edge: "gcore"`, Gcore CDN + DNS Terraform module, `force_return` 403 probe rule, connector-applied origin verification header (never in Terraform state), unit tests, and `docs/guide/gcore.md`.
- [x] **PR 4 — Fastly (`@opscrew/edge-provider-fastly`)**: `dns.edge: "fastly"` (edge-only, refused with `dns.provider: "none"`), `fastly_service_vcl` + VCL probe blocking + `fastly_tls_subscription`, compact CIDR firewall (`fastly_ip_ranges`) + origin mTLS (`pull.pem`, key kept out of Terraform state), unit tests, and `docs/guide/fastly.md`.
