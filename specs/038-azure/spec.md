# Feature Specification: Microsoft Azure Managed-Services Target (Feature 038)

**Feature:** `038-azure` | **Research:** [research.md](research.md) | **ADR:** [ADR 0040](../../docs/adr/0040-managed-cloud-plugins-and-aws.md)  
**Branch:** `038-azure` (stacked on `034-aws`)

## Summary

Adds **Microsoft Azure** as an official separately-installed managed-cloud provider plugin (`@opscrew/provider-azure`, installed via `opscrew plugin add azure`), reusing ADR 0040's `ManagedCloudProviderDefinition` contract, provenance-verified plugin installer, preset + `--set` override architecture, deterministic SecOps static policy gate, keyless GitHub Actions Workload Identity Federation (Entra ID OIDC), and out-of-band Key Vault secret population (zero plaintext secrets in `.tfstate`).

## Core Requirements & Invariants

1. **Separately installed official plugin (`@opscrew/provider-azure`, contractVersion `1`):**
   - Zero runtime workspace dependencies (`@opscrew/contracts` type-only); never bundled into the core `opscrew` CLI.
   - Installed via `opscrew plugin add azure` with `--ignore-scripts`, `npm audit signatures --json`, and SLSA provenance verification against `OFFICIAL_PROVIDER_PLUGINS.azure`.
2. **Presets (`lean`, `balanced`, `production-ha`) & `--set` overrides:**
   - **Compute:** Azure Container Apps Consumption (`container-apps`, default for web + workers + cron via Container Apps Jobs — zero ALB fee, built-in free managed TLS), Azure App Service Linux (`app-service`, flat-rate `B1`/`S1` always-on alternative), and Azure VM + Compose (`vm-compose`, zero-rewrite landing target for `opscrew retarget --to azure`).
   - **Databases & Caches:** Azure Database for PostgreSQL Flexible Server (`postgres-flexible`), Azure Database for MySQL Flexible Server (`mysql-flexible`), and **Azure Managed Redis (`managed-redis`, `azurerm_managed_redis`)** — **NEVER** legacy retiring `azurerm_redis_cache` (research R2).
   - **Storage, Secrets & Edge:** Azure Blob Storage (`blob-storage`, private containers, TLS 1.2+, zero public blob access), Azure Key Vault Standard (`key-vault`, `$0/mo` base + `$0.03/10k` ops — secret shells only in Terraform; values written out-of-band after approval), optional Azure Front Door Standard (`front-door`, avoided on `lean` due to `$35/mo` base fee), and Cloudflare DNS coexistence (`asuid.<host>` TXT + CNAME kept DNS-only / `proxied = false` during Azure managed certificate issuance, research R3).
   - **Cost-trap avoidance:** Avoids Azure Front Door `$35/mo` base fee and Azure NAT Gateway `~$37/mo` on `lean`/`balanced`; prefers free VNet-delegated subnets over `$7.30/mo` Private Endpoints unless required; defaults Container Apps to Consumption profile with explicit `minReplicas`/`maxReplicas` caps and explicit Log Analytics retention (`retention_in_days >= 30`).
3. **Keyless GitHub Actions OIDC (Workload Identity Federation):**
   - User-Assigned Managed Identity (`azurerm_user_assigned_identity`) scoped via least-privilege Azure RBAC to the app's Resource Group (never subscription-wide `Owner`/`Contributor`).
   - `azurerm_federated_identity_credential` with `audience = ["api://AzureADTokenExchange"]`, `issuer = "https://token.actions.githubusercontent.com"`, and exact case-sensitive `subject` matching workflow `environment:` (`repo:<owner>/<repo>:environment:<env>`, plus July 2026 immutable ID support).
   - Workflow uses `permissions: { id-token: write, contents: read }` and commit-pinned `azure/login` with zero stored `AZURE_CREDENTIALS` client secrets.
4. **Deterministic Azure SecOps Policies (`@opscrew/secops`):**
   - `azure-oidc-strict-sub`: requires exact `audience = ["api://AzureADTokenExchange"]`, `issuer = "https://token.actions.githubusercontent.com"`, wildcard-free `subject`, and fails closed when unknown.
   - `azure-rbac-least-privilege`: blocks subscription-wide or `Owner`/`User Access Administrator` role assignments (`azurerm_role_assignment`).
   - `azure-no-retiring-redis`: blocks legacy `azurerm_redis_cache` (must use `azurerm_managed_redis`).
   - `azure-db-private-encrypted`: blocks `public_network_access_enabled = true` on PostgreSQL/MySQL Flexible Server unless recorded in `exceptions[]`.
   - `azure-storage-private-tls`: requires `allow_nested_items_to_be_public = false` and `min_tls_version = "TLS1_2"` on `azurerm_storage_account`.
   - `azure-no-secret-in-state`: blocks `azurerm_key_vault_secret` with non-empty `value` in Terraform state (secrets written out-of-band via Azure connector).
   - `azure-log-retention`: blocks missing/zero `retention_in_days` on `azurerm_log_analytics_workspace`.
   - `azure-nsg-no-open-sensitive-ports`: blocks `azurerm_network_security_group` / `azurerm_network_security_rule` opening DB/cache/SSH ports (`22`, `3306`, `5432`, `6379`, `27017`) to `*` / `Internet` / `0.0.0.0/0`.
5. **Typed Azure ARM/Key Vault Connector & Honest Isolated Restore Drills:**
   - Zero-SDK-bloat injectable HTTP connector (`@opscrew/provider-azure`) using Bearer token (`AZURE_ACCESS_TOKEN` or injectable token provider) with strict credential redaction, Container Apps status, Log Analytics / Container Apps logs, out-of-band Key Vault secret writes (`PUT /secrets/{name}`), Flexible Server backup listing/creation, and honest, approval-gated, private-VNet PITR restore drills that verify `Ready` and confirm deletion before returning `cleanedUp: true`.
6. **Core Phase Routing, Companion Claude Code Plugin & Guide:**
   - Wire `azure` into `DeployProviderSchema` / `AzureTargetSchema`, `interview` (`context.managedProviders`), `design` (`--set`), `provision` (HCL render, SecOps gate, hash-bound apply, out-of-band Key Vault writes, Cloudflare `asuid` DNS-only `proxied: false` wiring), `status`, `logs`, `verify`, `drift`, `snapshot`/`restore drill`, `rotate`, `advise`, `destroy` (typed confirmation), and `retarget --to azure` (`vm-compose`).
   - Companion Claude Code plugin `plugin-azure/` (`opscrew-azure@opscrew` in `.claude-plugin/marketplace.json`) and user guide `docs/guide/azure.md` linked from `docs/guide/index.md`.
