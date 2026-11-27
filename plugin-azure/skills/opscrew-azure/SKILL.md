---
name: opscrew-azure
description: Deploy and operate apps on Microsoft Azure managed services with OpsCrew (Container Apps, App Service, VM + Compose, PostgreSQL/MySQL Flexible Server, Azure Managed Redis, Key Vault, keyless GitHub OIDC).
---

# OpsCrew Azure Skill

Use this skill whenever the user wants to deploy, inspect, resize, or destroy an application on **Microsoft Azure** with OpsCrew.

## Install the Azure provider plugin first

Core OpsCrew never bundles Azure provider code by default. Install the signed official plugin:

```bash
opscrew plugin add azure
```

Check installed plugins with `opscrew plugin list` or the `opscrew_plugins` MCP tool.

## Architecture presets & cost-trap guardrails

OpsCrew picks the right Azure services for the app and explains every component's `why` and monthly USD estimate:

- **`azure-lean`** (default for small apps / tight budgets): Azure Container Apps Consumption (scale-to-zero, 180k vCPU-s free/mo, built-in HTTPS), PostgreSQL/MySQL Flexible Server `B_Standard_B1ms` in a private delegated subnet, Azure Managed Redis `Balanced_B0`, Key Vault Standard (`$0/mo` base), Log Analytics (30-day retention). **Zero** NAT Gateway (`~$37/mo` saved) and **zero** Azure Front Door (`$35/mo` saved).
- **`azure-balanced`**: Container Apps with 1 warm replica, Flexible Server `B_Standard_B2ms`, Azure Managed Redis, private TLS 1.2+ Blob Storage.
- **`azure-production-ha`**: Zone-redundant Container Apps (2+ replicas), Flexible Server `GP_Standard_D2ds_v5` zone-redundant HA + geo-redundant backups, Azure Managed Redis `Balanced_B1` HA, 90-day Log Analytics retention, optional Azure Front Door.

Override any component before apply with `--set`:

```bash
opscrew design --option azure-lean --set compute=app-service --set observability.logsRetentionDays=60
```

## Non-negotiable Azure safety rules

1. **Keyless GitHub OIDC (`azure/login@v2`):** OpsCrew creates a User-Assigned Managed Identity with a Federated Identity Credential pinned strictly to `repo:<owner>/<repo>:environment:<env>` and `api://AzureADTokenExchange` (zero stored client secrets in GitHub).
2. **Resource-group least-privilege RBAC:** Never assigns Subscription `Owner` or `Contributor`.
3. **Zero secrets in Terraform state:** Terraform creates only the `azurerm_key_vault` shell; secret values are populated out-of-band through OpsCrew's Azure connector after plan-hash approval.
4. **No retiring Redis:** OpsCrew always provisions `azurerm_managed_redis` and blocks retiring `azurerm_redis_cache`.
5. **Cloudflare custom domains:** Custom-domain `asuid.<domain>` TXT validation records are created DNS-only (`proxied: false`).
6. **Plan-hash approval & typed destroy:** Every `tofu apply`, Key Vault rotation, PITR restore drill, and `destroy` goes through OpsCrew's SHA-256 plan-hash approval gate.

