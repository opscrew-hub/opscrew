/**
 * Lightweight, injectable Microsoft Azure ARM + Key Vault + Log Analytics connector
 * (Feature 038, T3805, ADR 0040 D3).
 *
 * Zero `@azure/*` SDK dependencies and zero runtime `@opscrew/core` imports. All HTTP calls go
 * through injected `deps.fetch`, every error/log line passes through `deps.redactor.redact()`,
 * tokens expire cleanly, secrets are written out-of-band to Key Vault (never `.tfstate`), and
 * PITR restore drills validate timestamps, support PostgreSQL & MySQL, sleep & poll cleanly, and
 * verify DELETE status + 404 before claiming `cleanedUp: true`.
 */
import { createHash } from "node:crypto";
import type {
  ManagedCloudConnector,
  ManagedCloudConnectorDeps,
  ManagedCloudLogLine,
  ManagedCloudRestoreDrillResult,
  ManagedCloudSnapshotEntry,
  ManagedCloudStatusSummary,
} from "@opscrew/contracts";

const ARM_BASE = "https://management.azure.com";
const LOG_ANALYTICS_BASE = "https://api.loganalytics.io";
const ISO_UTC_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;

/** Local error class carrying `code` and `hint` without importing `@opscrew/core` at runtime. */
export class AzureProviderError extends Error {
  readonly code: string;
  readonly hint?: string;

  constructor(code: string, message: string, options?: { readonly hint?: string }) {
    super(message);
    this.name = "AzureProviderError";
    this.code = code;
    if (options?.hint !== undefined) {
      this.hint = options.hint;
    }
  }
}

export interface AzureCredentials {
  readonly subscriptionId: string;
  readonly tenantId?: string;
  readonly clientId?: string;
  readonly clientSecret?: string;
  readonly accessToken?: string;
  readonly keyVaultAccessToken?: string;
  readonly logAnalyticsAccessToken?: string;
}

/** Canonical Azure resource group name matching `azurerm_resource_group.app.name`. */
export function azureResourceGroupName(appName: string, environment: string): string {
  return `rg-opscrew-${appName}-${environment}`.slice(0, 90);
}

/** Canonical Azure Container App / Web App / VM name clamped to Azure's 32-char Container App limit. */
export function azureAppResourceName(appName: string, environment: string): string {
  const raw = `opscrew-${appName}-${environment}`
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");
  if (raw.length <= 32) return raw;
  const suffix = createHash("sha256").update(raw).digest("hex").slice(0, 6);
  return `${raw.slice(0, 25).replace(/-+$/g, "")}-${suffix}`;
}

/** Canonical Azure PostgreSQL/MySQL Flexible Server name matching `database.tf`. */
export function azureDbServerName(appName: string, environment: string): string {
  return `opscrew-${appName}-${environment}-db`.slice(0, 63);
}

/** Canonical Azure Key Vault name (3-24 lowercase alphanumerics/hyphens with collision-free hash suffix). */
export function azureKeyVaultName(appName: string, environment: string): string {
  const base = `kv-${appName}-${environment}`
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");
  const suffix = createHash("sha256").update(`${appName}:${environment}`).digest("hex").slice(0, 6);
  const prefix = base.slice(0, 17).replace(/-+$/g, "");
  return `${prefix}-${suffix}`;
}

function dbProviderNamespace(service: string): string {
  return service.toLowerCase().includes("mysql")
    ? "Microsoft.DBforMySQL"
    : "Microsoft.DBforPostgreSQL";
}

function readCredentials(env: Readonly<Record<string, string | undefined>>): AzureCredentials {
  const subscriptionId = env.AZURE_SUBSCRIPTION_ID?.trim();
  const accessToken = env.AZURE_ACCESS_TOKEN?.trim();
  const keyVaultAccessToken = env.AZURE_KEY_VAULT_ACCESS_TOKEN?.trim();
  const logAnalyticsAccessToken = env.AZURE_LOG_ANALYTICS_ACCESS_TOKEN?.trim();
  const tenantId = env.AZURE_TENANT_ID?.trim();
  const clientId = env.AZURE_CLIENT_ID?.trim();
  const clientSecret = env.AZURE_CLIENT_SECRET?.trim();
  if (!subscriptionId) {
    throw new AzureProviderError("CREDENTIALS_MISSING", "AZURE_SUBSCRIPTION_ID is not set.", {
      hint: "Export AZURE_SUBSCRIPTION_ID along with AZURE_TENANT_ID + AZURE_CLIENT_ID + AZURE_CLIENT_SECRET (or scoped access tokens).",
    });
  }
  if (!accessToken && !(tenantId && clientId && clientSecret)) {
    throw new AzureProviderError(
      "CREDENTIALS_MISSING",
      "Azure credentials are missing: set AZURE_TENANT_ID + AZURE_CLIENT_ID + AZURE_CLIENT_SECRET or AZURE_ACCESS_TOKEN.",
      {
        hint: "Configure service principal credentials or `az account get-access-token`; GitHub Actions deploys use keyless OIDC.",
      },
    );
  }
  return {
    subscriptionId,
    ...(tenantId ? { tenantId } : {}),
    ...(clientId ? { clientId } : {}),
    ...(clientSecret ? { clientSecret } : {}),
    ...(accessToken ? { accessToken } : {}),
    ...(keyVaultAccessToken ? { keyVaultAccessToken } : {}),
    ...(logAnalyticsAccessToken ? { logAnalyticsAccessToken } : {}),
  };
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

const DEFAULT_SLEEP = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

export function createAzureConnector(deps: ManagedCloudConnectorDeps): ManagedCloudConnector {
  const now = deps.now ?? (() => new Date());
  const sleep = deps.sleep ?? DEFAULT_SLEEP;
  const maxPolls = deps.maxPollAttempts ?? 60;
  const tokenCache = new Map<string, { token: string; expiresAtMs: number }>();

  async function acquireToken(scope: string): Promise<{ token: string; subscriptionId: string }> {
    const creds = readCredentials(deps.env);
    // Support explicit per-audience static access tokens first; never blindly reuse an ARM token
    // for Key Vault or Log Analytics when service principal credentials are available.
    if (scope.startsWith("https://vault.azure.net") && creds.keyVaultAccessToken) {
      return { token: creds.keyVaultAccessToken, subscriptionId: creds.subscriptionId };
    }
    if (scope.startsWith("https://api.loganalytics.io") && creds.logAnalyticsAccessToken) {
      return { token: creds.logAnalyticsAccessToken, subscriptionId: creds.subscriptionId };
    }
    if (creds.tenantId && creds.clientId && creds.clientSecret) {
      const cached = tokenCache.get(scope);
      if (cached !== undefined && cached.expiresAtMs > now().getTime()) {
        return { token: cached.token, subscriptionId: creds.subscriptionId };
      }
      const tokenUrl = `https://login.microsoftonline.com/${encodeURIComponent(creds.tenantId)}/oauth2/v2.0/token`;
      const body = new URLSearchParams({
        grant_type: "client_credentials",
        client_id: creds.clientId,
        client_secret: creds.clientSecret,
        scope,
      }).toString();
      const res = await deps.fetch(tokenUrl, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body,
      });
      const text = await res.text();
      if (!res.ok) {
        throw new AzureProviderError(
          "CREDENTIALS_INVALID",
          deps.redactor.redact(
            `Azure AD token exchange failed (HTTP ${res.status}): ${text.slice(0, 200)}`,
          ),
        );
      }
      let parsed: unknown;
      try {
        parsed = JSON.parse(text);
      } catch {
        throw new AzureProviderError(
          "COMMAND_FAILED",
          "Azure AD returned non-JSON token response.",
        );
      }
      if (!isObject(parsed) || typeof parsed.access_token !== "string") {
        throw new AzureProviderError(
          "CREDENTIALS_INVALID",
          "Azure AD response omitted access_token.",
        );
      }
      const expiresInSec =
        typeof parsed.expires_in === "number" && parsed.expires_in > 120 ? parsed.expires_in : 3600;
      tokenCache.set(scope, {
        token: parsed.access_token,
        expiresAtMs: now().getTime() + (expiresInSec - 60) * 1000,
      });
      return { token: parsed.access_token, subscriptionId: creds.subscriptionId };
    }

    if (creds.accessToken) {
      if (scope.startsWith("https://vault.azure.net")) {
        throw new AzureProviderError(
          "CREDENTIALS_MISSING",
          "Key Vault requires a vault-scoped token: set AZURE_KEY_VAULT_ACCESS_TOKEN (from `az account get-access-token --resource https://vault.azure.net`) or service principal credentials.",
        );
      }
      if (scope.startsWith("https://api.loganalytics.io")) {
        throw new AzureProviderError(
          "CREDENTIALS_MISSING",
          "Log Analytics requires a Log Analytics-scoped token: set AZURE_LOG_ANALYTICS_ACCESS_TOKEN (from `az account get-access-token --resource https://api.loganalytics.io`) or service principal credentials.",
        );
      }
      return { token: creds.accessToken, subscriptionId: creds.subscriptionId };
    }

    throw new AzureProviderError(
      "CREDENTIALS_MISSING",
      `No Azure credentials available for scope ${scope}.`,
    );
  }

  async function armRequest(
    method: "GET" | "PUT" | "POST" | "DELETE",
    urlPath: string,
    payload?: unknown,
  ): Promise<{ status: number; json?: unknown; text: string }> {
    const { token, subscriptionId } = await acquireToken("https://management.azure.com/.default");
    const url = `${ARM_BASE}${urlPath.replace("{subscriptionId}", encodeURIComponent(subscriptionId))}`;
    const res = await deps.fetch(url, {
      method,
      headers: {
        authorization: `Bearer ${token}`,
        ...(payload === undefined ? {} : { "content-type": "application/json" }),
      },
      ...(payload === undefined ? {} : { body: JSON.stringify(payload) }),
    });
    const text = await res.text();
    let json: unknown;
    try {
      json = text.length > 0 ? JSON.parse(text) : undefined;
    } catch {
      json = undefined;
    }
    return { status: res.status, json, text };
  }

  return {
    async verifyCredentials() {
      try {
        const res = await armRequest(
          "GET",
          "/subscriptions/{subscriptionId}?api-version=2022-12-01",
        );
        if (res.status < 200 || res.status >= 300) {
          return {
            ok: false,
            error: deps.redactor.redact(
              `Azure ARM subscription check failed (HTTP ${res.status}): ${res.text.slice(0, 200)}`,
            ),
          };
        }
        const subId =
          isObject(res.json) && typeof res.json.subscriptionId === "string"
            ? res.json.subscriptionId
            : deps.env.AZURE_SUBSCRIPTION_ID;
        const display =
          isObject(res.json) && typeof res.json.displayName === "string"
            ? res.json.displayName
            : undefined;
        return {
          ok: true,
          ...(subId ? { accountId: subId } : {}),
          ...(display ? { principalArn: `azure:subscription:${display}` } : {}),
        };
      } catch (error) {
        return {
          ok: false,
          error: deps.redactor.redact(error instanceof Error ? error.message : String(error)),
        };
      }
    },

    async readStatus(input): Promise<ManagedCloudStatusSummary> {
      const rg = azureResourceGroupName(input.appName, input.environment);
      const resourceName = azureAppResourceName(input.appName, input.environment);
      const computePath =
        input.computeKind === "app-service"
          ? `/subscriptions/{subscriptionId}/resourceGroups/${encodeURIComponent(rg)}/providers/Microsoft.Web/sites/${encodeURIComponent(resourceName)}?api-version=2023-12-01`
          : input.computeKind === "vm-compose"
            ? `/subscriptions/{subscriptionId}/resourceGroups/${encodeURIComponent(rg)}/providers/Microsoft.Compute/virtualMachines/${encodeURIComponent(resourceName)}/instanceView?api-version=2024-03-01`
            : `/subscriptions/{subscriptionId}/resourceGroups/${encodeURIComponent(rg)}/providers/Microsoft.App/containerApps/${encodeURIComponent(resourceName)}?api-version=2024-03-01`;

      const res = await armRequest("GET", computePath);
      const props =
        isObject(res.json) && isObject(res.json.properties) ? res.json.properties : undefined;

      let runningState = `HTTP ${res.status}`;
      let healthy = false;
      if (input.computeKind === "vm-compose" && res.status >= 200 && res.status < 300) {
        const statuses =
          isObject(res.json) && Array.isArray(res.json.statuses) ? res.json.statuses : [];
        const power = statuses.find(
          (s) => isObject(s) && typeof s.code === "string" && s.code.startsWith("PowerState/"),
        ) as Record<string, unknown> | undefined;
        runningState =
          typeof power?.displayStatus === "string"
            ? power.displayStatus
            : typeof power?.code === "string"
              ? power.code
              : "Unknown";
        healthy = String(power?.code ?? "").toLowerCase() === "powerstate/running";
      } else if (res.status >= 200 && res.status < 300) {
        runningState =
          typeof props?.runningStatus === "string"
            ? props.runningStatus
            : typeof props?.state === "string"
              ? props.state
              : typeof props?.provisioningState === "string"
                ? props.provisioningState
                : "Running";
        healthy = /running|succeeded|ready/i.test(runningState);
      }

      const fqdn =
        isObject(props?.configuration) &&
        isObject(props.configuration.ingress) &&
        typeof props.configuration.ingress.fqdn === "string"
          ? `https://${props.configuration.ingress.fqdn}`
          : typeof props?.defaultHostName === "string"
            ? `https://${props.defaultHostName}`
            : undefined;

      return {
        healthy,
        region: input.region,
        ...(deps.env.AZURE_SUBSCRIPTION_ID ? { accountId: deps.env.AZURE_SUBSCRIPTION_ID } : {}),
        compute: {
          kind: input.computeKind,
          status: runningState,
          ...(fqdn ? { endpoint: fqdn } : {}),
        },
        services: [],
        alarms: [],
      };
    },

    async readLogs(input): Promise<readonly ManagedCloudLogLine[]> {
      const { token } = await acquireToken("https://api.loganalytics.io/.default");
      const limit = Math.max(1, Math.min(input.limit ?? 100, 1000));
      const filterClause =
        input.filterPattern !== undefined && input.filterPattern.length > 0
          ? ` | where Message contains ${JSON.stringify(input.filterPattern)}`
          : "";
      // Union Container Apps, App Service, and Syslog tables into a normalized projection so
      // column lookup never relies on fragile positional indexes.
      const query = `union isfuzzy=true (ContainerAppConsoleLogs_CL | project TimeGenerated, Stream=ContainerName_s, Message=Log_s), (AppServiceConsoleLogs | project TimeGenerated, Stream=Host, Message=ResultDescription), (Syslog | project TimeGenerated, Stream=ProcessName, Message=SyslogMessage)${filterClause} | order by TimeGenerated desc | take ${limit}`;
      const url = `${LOG_ANALYTICS_BASE}/v1/workspaces/${encodeURIComponent(input.logGroup)}/query`;
      const res = await deps.fetch(url, {
        method: "POST",
        headers: {
          authorization: `Bearer ${token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ query }),
      });
      const text = await res.text();
      if (!res.ok) {
        throw new AzureProviderError(
          "COMMAND_FAILED",
          deps.redactor.redact(
            `Azure Log Analytics query failed (HTTP ${res.status}): ${text.slice(0, 200)}`,
          ),
        );
      }
      let parsed: unknown;
      try {
        parsed = JSON.parse(text);
      } catch {
        return [];
      }
      const tables = isObject(parsed) && Array.isArray(parsed.tables) ? parsed.tables : [];
      const firstTable = isObject(tables[0]) ? tables[0] : undefined;
      const columns = Array.isArray(firstTable?.columns)
        ? firstTable.columns.map((c) => (isObject(c) && typeof c.name === "string" ? c.name : ""))
        : [];
      const idxTime = columns.indexOf("TimeGenerated");
      const idxStream = columns.indexOf("Stream");
      const idxMsg = columns.indexOf("Message");
      const rows = Array.isArray(firstTable?.rows) ? firstTable.rows : [];
      return rows
        .filter((row): row is unknown[] => Array.isArray(row))
        .map((row) => ({
          timestamp:
            typeof row[idxTime >= 0 ? idxTime : 0] === "string"
              ? String(row[idxTime >= 0 ? idxTime : 0])
              : now().toISOString(),
          stream:
            typeof row[idxStream >= 0 ? idxStream : 1] === "string"
              ? String(row[idxStream >= 0 ? idxStream : 1])
              : input.logGroup,
          message: deps.redactor.redact(
            String(row[idxMsg >= 0 ? idxMsg : Math.min(2, row.length - 1)] ?? ""),
          ),
        }));
    },

    async writeSecrets(input): Promise<{ readonly written: readonly string[] }> {
      const { token } = await acquireToken("https://vault.azure.net/.default");
      const vaultUrl = deps.env.AZURE_KEY_VAULT_URL?.trim().replace(/\/+$/, "");
      if (!vaultUrl || !/^https:\/\/[a-z0-9-]+\.vault\.azure\.net$/i.test(vaultUrl)) {
        throw new AzureProviderError(
          "PHASE_PRECONDITION",
          "AZURE_KEY_VAULT_URL must be set to a valid https://<vault>.vault.azure.net URL to write secrets out-of-band.",
        );
      }
      // Fail closed if two distinct secret names collide after Azure Key Vault name sanitization.
      const sanitizedToRaw = new Map<string, string>();
      const prepared: Array<{ kvName: string; value: string; description?: string }> = [];
      for (const secret of input.secrets) {
        const kvName = secret.name.replace(/[^a-zA-Z0-9-]/g, "-");
        const existing = sanitizedToRaw.get(kvName.toLowerCase());
        if (existing !== undefined && existing !== secret.name) {
          throw new AzureProviderError(
            "INVALID_INPUT",
            `Azure Key Vault secret name collision: "${existing}" and "${secret.name}" both map to "${kvName}". Rename one of the secrets.`,
          );
        }
        sanitizedToRaw.set(kvName.toLowerCase(), secret.name);
        prepared.push({
          kvName,
          value: secret.value,
          ...(secret.description === undefined ? {} : { description: secret.description }),
        });
      }

      const written: string[] = [];
      for (const item of prepared) {
        const url = `${vaultUrl}/secrets/${encodeURIComponent(item.kvName)}?api-version=7.4`;
        const res = await deps.fetch(url, {
          method: "PUT",
          headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/json",
          },
          body: JSON.stringify({
            value: item.value,
            ...(item.description ? { contentType: item.description } : {}),
          }),
        });
        if (!res.ok) {
          const text = await res.text();
          throw new AzureProviderError(
            "COMMAND_FAILED",
            deps.redactor.redact(
              `Failed to write Key Vault secret "${item.kvName}" (HTTP ${res.status}): ${text.slice(0, 200)}`,
            ),
          );
        }
        written.push(item.kvName);
      }
      return { written };
    },

    async listSnapshots(input): Promise<readonly ManagedCloudSnapshotEntry[]> {
      const service = deps.env.AZURE_DB_SERVICE ?? "flexible-postgres";
      const providerNs = dbProviderNamespace(service);
      const rg =
        deps.env.AZURE_RESOURCE_GROUP ?? `rg-${input.identifierPrefix.replace(/-db$/, "")}`;
      const urlPath = `/subscriptions/{subscriptionId}/resourceGroups/${encodeURIComponent(rg)}/providers/${providerNs}/flexibleServers/${encodeURIComponent(input.identifierPrefix)}/backups?api-version=2024-08-01`;
      const res = await armRequest("GET", urlPath);
      if (res.status < 200 || res.status >= 300) {
        throw new AzureProviderError(
          "COMMAND_FAILED",
          deps.redactor.redact(
            `Failed to list Azure Flexible Server backups (HTTP ${res.status}): ${res.text.slice(0, 200)}`,
          ),
        );
      }
      const items = isObject(res.json) && Array.isArray(res.json.value) ? res.json.value : [];
      const snapshots: ManagedCloudSnapshotEntry[] = items.filter(isObject).map((item) => {
        const props = isObject(item.properties) ? item.properties : {};
        return {
          id: typeof item.name === "string" ? item.name : "unknown",
          service,
          engine: service.includes("mysql") ? "mysql" : "postgres",
          createdAt:
            typeof props.completedTime === "string" ? props.completedTime : now().toISOString(),
          status: typeof props.backupType === "string" ? props.backupType : "Available",
        };
      });
      return snapshots.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    },

    async takeSnapshot(input): Promise<ManagedCloudSnapshotEntry> {
      const providerNs = dbProviderNamespace(input.service);
      const rg = deps.env.AZURE_RESOURCE_GROUP ?? `rg-${input.instanceId.replace(/-db$/, "")}`;
      const urlPath = `/subscriptions/{subscriptionId}/resourceGroups/${encodeURIComponent(rg)}/providers/${providerNs}/flexibleServers/${encodeURIComponent(input.instanceId)}/backups/${encodeURIComponent(input.snapshotId)}?api-version=2024-08-01`;
      const res = await armRequest("PUT", urlPath, {});
      if (res.status < 200 || res.status >= 300) {
        throw new AzureProviderError(
          "COMMAND_FAILED",
          deps.redactor.redact(
            `Failed to create Azure Flexible Server backup "${input.snapshotId}" (HTTP ${res.status}): ${res.text.slice(0, 200)}`,
          ),
        );
      }
      return {
        id: input.snapshotId,
        service: input.service,
        engine: input.service.includes("mysql") ? "mysql" : "postgres",
        createdAt: now().toISOString(),
        status: res.status === 202 ? "InProgress" : "Completed",
      };
    },

    async runRestoreDrill(input): Promise<ManagedCloudRestoreDrillResult> {
      const started = now().getTime();
      if (!ISO_UTC_RE.test(input.snapshotId)) {
        return {
          snapshotId: input.snapshotId,
          service: input.service,
          verified: false,
          durationMs: 0,
          cleanedUp: false,
          detail: `Azure PointInTimeRestore requires an ISO-8601 UTC timestamp (e.g. 2026-11-27T11:00:00Z), got "${input.snapshotId}".`,
        };
      }

      const providerNs = dbProviderNamespace(input.service);
      const rg =
        deps.env.AZURE_RESOURCE_GROUP ??
        `rg-${input.drillInstanceId.replace(/-db-drill$|-drill$/, "")}`;
      const sourceServer =
        deps.env.AZURE_DB_SERVER_ID ??
        `/subscriptions/${deps.env.AZURE_SUBSCRIPTION_ID ?? ""}/resourceGroups/${rg}/providers/${providerNs}/flexibleServers/${input.drillInstanceId.replace(/-drill$/, "")}`;
      const drillPath = `/subscriptions/{subscriptionId}/resourceGroups/${encodeURIComponent(rg)}/providers/${providerNs}/flexibleServers/${encodeURIComponent(input.drillInstanceId)}?api-version=2024-08-01`;

      const createRes = await armRequest("PUT", drillPath, {
        location: input.region,
        properties: {
          createMode: "PointInTimeRestore",
          sourceServerResourceId: sourceServer,
          pointInTimeUTC: input.snapshotId,
          network: {
            publicNetworkAccess: "Disabled",
            ...(input.dbSubnetGroupName
              ? { delegatedSubnetResourceId: input.dbSubnetGroupName }
              : {}),
          },
        },
      });
      if (createRes.status < 200 || createRes.status >= 300) {
        return {
          snapshotId: input.snapshotId,
          service: input.service,
          verified: false,
          durationMs: Math.max(0, now().getTime() - started),
          cleanedUp: false,
          detail: deps.redactor.redact(
            `Restore drill create failed (HTTP ${createRes.status}): ${createRes.text.slice(0, 200)}`,
          ),
        };
      }

      // Poll until the throwaway private server reports state === "Ready" (or fails).
      let verified = false;
      for (let attempt = 0; attempt < maxPolls; attempt++) {
        const poll = await armRequest("GET", drillPath);
        const state =
          isObject(poll.json) && isObject(poll.json.properties)
            ? String(poll.json.properties.state ?? "")
            : "";
        if (poll.status >= 200 && poll.status < 300 && state === "Ready") {
          verified = true;
          break;
        }
        await sleep(5_000);
      }

      // Delete the throwaway drill server, check DELETE HTTP status, and confirm 404 before
      // reporting cleanedUp: true.
      const deleteRes = await armRequest("DELETE", drillPath);
      let cleanedUp = deleteRes.status === 404;
      if (deleteRes.status >= 200 && deleteRes.status < 300) {
        for (let attempt = 0; attempt < maxPolls; attempt++) {
          const check = await armRequest("GET", drillPath);
          if (check.status === 404) {
            cleanedUp = true;
            break;
          }
          await sleep(5_000);
        }
      }

      return {
        snapshotId: input.snapshotId,
        service: input.service,
        verified,
        durationMs: Math.max(0, now().getTime() - started),
        cleanedUp,
        detail: verified
          ? cleanedUp
            ? `Restored private throwaway server ${input.drillInstanceId} (publicNetworkAccess=Disabled), verified Ready, and confirmed deleted.`
            : `Restored and verified ${input.drillInstanceId}, but deletion failed or was not confirmed (DELETE HTTP ${deleteRes.status}).`
          : `Throwaway restore server ${input.drillInstanceId} did not reach Ready within ${maxPolls} polls (DELETE HTTP ${deleteRes.status}, cleanedUp=${String(cleanedUp)}).`,
      };
    },
  };
}
