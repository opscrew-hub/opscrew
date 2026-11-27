# Microsoft Azure

OpsCrew can deploy your application onto **Microsoft Azure managed services** via the official separately installed `@opscrew/provider-azure` plugin. Core OpsCrew stays lightweight for everyone else — install Azure support only when you need it.

## 1. Install the Azure plugin

```bash
opscrew plugin add azure
```

OpsCrew installs the pinned official `@opscrew/provider-azure` package into `~/.opscrew/plugins/azure` with `--ignore-scripts` and verifies its npm registry signatures and SLSA provenance before loading any code.

If you use Claude Code, you can also install the companion skill plugin `opscrew-azure@opscrew` from the OpsCrew marketplace.

## 2. Authenticate locally

Set your Azure subscription and either a short-lived access token or service principal credentials in your environment:

- `AZURE_SUBSCRIPTION_ID`
- `AZURE_ACCESS_TOKEN` (from `az account get-access-token --query accessToken -o tsv`), **or**
- `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, and `AZURE_CLIENT_SECRET`

Deployments from GitHub Actions never use static Azure secrets — OpsCrew configures **keyless GitHub OIDC** (`azure/login@v2` with a User-Assigned Managed Identity and `azurerm_federated_identity_credential` pinned to `repo:<owner>/<repo>:environment:<env>`).

## 3. Architecture presets

| Preset | Compute | Database | Cache | Edge | Cost traps avoided |
| --- | --- | --- | --- | --- | --- |
| `azure-lean` | Container Apps Consumption (`min_replicas: 0`) | PostgreSQL/MySQL Flexible Server `B_Standard_B1ms` (private VNet) | Azure Managed Redis `Balanced_B0` | Cloudflare or built-in TLS | No NAT Gateway (~$37/mo), no Front Door ($35/mo) |
| `azure-balanced` | Container Apps Consumption (`min_replicas: 1`) | Flexible Server `B_Standard_B2ms` (private VNet) | Azure Managed Redis `Balanced_B0` | Cloudflare or built-in TLS | No NAT Gateway (~$37/mo), no Front Door ($35/mo) |
| `azure-production-ha` | Zone-redundant Container Apps (`min_replicas: 2`) | Flexible Server `GP_Standard_D2ds_v5` zone-redundant HA | Azure Managed Redis `Balanced_B1` HA | Azure Front Door (or Cloudflare if pinned) | Explicit 90-day Log Analytics cap |

You can override any component before provisioning and see the exact monthly cost delta:

```bash
opscrew design --option azure-lean --set compute=app-service
opscrew design --option azure-balanced --set pins.noNat=true --set observability.logsRetentionDays=60
```

Supported compute kinds: `container-apps` (default), `app-service` (Linux B1/P0v3), and `vm-compose` (`Standard_B2ats_v2` bridge for VPS/Compose apps moving to Azure).

## 4. Guardrails & security checks

Every Azure plan is checked deterministically by `@opscrew/secops` before you are asked to approve it:

- **Strict GitHub OIDC:** Fails closed if `azurerm_federated_identity_credential` omits `https://token.actions.githubusercontent.com`, `api://AzureADTokenExchange`, or uses a wildcard `subject`.
- **Resource-group RBAC:** Refuses `Owner`, `User Access Administrator`, and subscription-wide `Contributor`.
- **No retiring Redis:** Blocks `azurerm_redis_cache` and provisions `azurerm_managed_redis`.
- **Private databases & storage:** Enforces `public_network_access_enabled = false` on Flexible Server and TLS 1.2+ / private blobs / `shared_access_key_enabled = false` on Storage Accounts.
- **No secrets in Terraform state:** Terraform creates only the `azurerm_key_vault` shell; secret values are written out-of-band via OpsCrew's Azure connector after plan-hash approval.
- **Explicit log retention:** Blocks Log Analytics workspaces without `retention_in_days` between `30` and `730`.
- **NSG checks:** Refuses inbound rules exposing ports `22`, `3306`, `5432`, `6379`, or `27017` to `Internet`, `*`, `0.0.0.0/0`, or `::/0`.

Guardrails cannot be disabled silently — relaxing one requires an explicit reason under `target.exceptions` in `opscrew/plan.yaml`.

## 5. Custom domains with Cloudflare

When your domain stays on Cloudflare (`dns.provider: cloudflare`), OpsCrew writes the Azure Container Apps `asuid.<domain>` TXT verification record with `proxied: false` (DNS-only) so Azure can validate ownership cleanly.

## 6. Day-2 operations & destroy

- `opscrew status` / `opscrew verify` — checks subscription auth, compute health, and HTTPS endpoint.
- `opscrew logs` — queries redacted logs from your Azure Log Analytics workspace.
- `opscrew drift` — compares rendered HCL and runs a refresh-only OpenTofu plan.
- Backups & PITR restore drills — restores into a private throwaway Flexible Server (`publicNetworkAccess = Disabled`), verifies `Ready`, and confirms deletion after approval.
- `opscrew destroy` — requires SHA-256 plan-hash approval plus typing your app's name (`allowDestroy: true`).

