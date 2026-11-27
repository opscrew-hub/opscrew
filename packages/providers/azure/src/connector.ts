/**
 * Lightweight, injectable Microsoft Azure ARM + Key Vault + Log Analytics connector
 * (Feature 038, T3805, ADR 0040 D3).
 *
 * Zero `@azure/*` SDK dependencies and zero runtime `@opscrew/core` imports. All HTTP calls go
 * through injected `deps.fetch`, every error/log line passes through `deps.redactor.redact()`,
 * secrets are written out-of-band to Key Vault (never `.tfstate`), and PITR restore drills poll
 * both readiness and deletion cleanly.
 */
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
}

/** Canonical Azure resource group name matching `azurerm_resource_group.app.name`. */
export function azureResourceGroupName(appName: string, environment: string): string {
  return `rg-opscrew-${appName}-${environment}`;
}

/** Canonical Azure PostgreSQL/MySQL Flexible Server name matching `database.tf`. */
export function azureDbServerName(appName: string, environment: string): string {
  return `opscrew-${appName}-${environment}-db`.slice(0, 63);
}

/** Canonical Azure Key Vault name (3-24 lowercase alphanumerics/hyphens). */
export function azureKeyVaultName(appName: string, environment: string): string {
  const cleaned = `kv-${appName}-${environment}`
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");
  return cleaned.slice(0, 24).replace(/-+$/g, "");
}

function readCredentials(env: Readonly<Record<string, string | undefined>>): AzureCredentials {
  const subscriptionId = env.AZURE_SUBSCRIPTION_ID?.trim();
  const accessToken = env.AZURE_ACCESS_TOKEN?.trim();
  const tenantId = env.AZURE_TENANT_ID?.trim();
  const clientId = env.AZURE_CLIENT_ID?.trim();
  const clientSecret = env.AZURE_CLIENT_SECRET?.trim();
  if (!subscriptionId) {
    throw new AzureProviderError("CREDENTIALS_MISSING", "AZURE_SUBSCRIPTION_ID is not set.", {
      hint: "Export AZURE_SUBSCRIPTION_ID along with AZURE_ACCESS_TOKEN (or AZURE_TENANT_ID + AZURE_CLIENT_ID + AZURE_CLIENT_SECRET).",
    });
  }
  if (!accessToken && !(tenantId && clientId && clientSecret)) {
    throw new AzureProviderError(
      "CREDENTIALS_MISSING",
      "Azure credentials are missing: set AZURE_ACCESS_TOKEN or AZURE_TENANT_ID + AZURE_CLIENT_ID + AZURE_CLIENT_SECRET.",
      {
        hint: "Run `az account get-access-token` or configure service principal credentials; GitHub Actions deploys use keyless OIDC.",
      },
    );
  }
  return {
    subscriptionId,
    ...(tenantId ? { tenantId } : {}),
    ...(clientId ? { clientId } : {}),
    ...(clientSecret ? { clientSecret } : {}),
    ...(accessToken ? { accessToken } : {}),
  };
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function createAzureConnector(deps: ManagedCloudConnectorDeps): ManagedCloudConnector {
  const now = deps.now ?? (() => new Date());
  const sleep = deps.sleep ?? (() => Promise.resolve());
  const maxPolls = deps.maxPollAttempts ?? 12;
  const tokenCache = new Map<string, string>();

  async function acquireToken(scope: string): Promise<{ token: string; subscriptionId: string }> {
    const creds = readCredentials(deps.env);
    if (creds.accessToken) {
      return { token: creds.accessToken, subscriptionId: creds.subscriptionId };
    }
    const cached = tokenCache.get(scope);
    if (cached !== undefined) {
      return { token: cached, subscriptionId: creds.subscriptionId };
    }
    const tokenUrl = `https://login.microsoftonline.com/${encodeURIComponent(creds.tenantId ?? "")}/oauth2/v2.0/token`;
    const body = new URLSearchParams({
      grant_type: "client_credentials",
      client_id: creds.clientId ?? "",
      client_secret: creds.clientSecret ?? "",
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
      throw new AzureProviderError("COMMAND_FAILED", "Azure AD returned non-JSON token response.");
    }
    if (!isObject(parsed) || typeof parsed.access_token !== "string") {
      throw new AzureProviderError(
        "CREDENTIALS_INVALID",
        "Azure AD response omitted access_token.",
      );
    }
    tokenCache.set(scope, parsed.access_token);
    return { token: parsed.access_token, subscriptionId: creds.subscriptionId };
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
      const resourceName = `opscrew-${input.appName}-${input.environment}`;
      const computePath =
        input.computeKind === "app-service"
          ? `/subscriptions/{subscriptionId}/resourceGroups/${encodeURIComponent(rg)}/providers/Microsoft.Web/sites/${encodeURIComponent(resourceName)}?api-version=2023-12-01`
          : input.computeKind === "vm-compose"
            ? `/subscriptions/{subscriptionId}/resourceGroups/${encodeURIComponent(rg)}/providers/Microsoft.Compute/virtualMachines/${encodeURIComponent(resourceName)}?api-version=2024-03-01`
            : `/subscriptions/{subscriptionId}/resourceGroups/${encodeURIComponent(rg)}/providers/Microsoft.App/containerApps/${encodeURIComponent(resourceName)}?api-version=2024-03-01`;

      const res = await armRequest("GET", computePath);
      const props =
        isObject(res.json) && isObject(res.json.properties) ? res.json.properties : undefined;
      const runningState =
        typeof props?.runningStatus === "string"
          ? props.runningStatus
          : typeof props?.state === "string"
            ? props.state
            : typeof props?.provisioningState === "string"
              ? props.provisioningState
              : res.status >= 200 && res.status < 300
                ? "Running"
                : `HTTP ${res.status}`;
      const fqdn =
        isObject(props?.configuration) &&
        isObject(props.configuration.ingress) &&
        typeof props.configuration.ingress.fqdn === "string"
          ? `https://${props.configuration.ingress.fqdn}`
          : typeof props?.defaultHostName === "string"
            ? `https://${props.defaultHostName}`
            : undefined;
      const healthy =
        res.status >= 200 && res.status < 300 && /running|succeeded|ready/i.test(runningState);

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
          ? ` | where Log_s contains ${JSON.stringify(input.filterPattern)}`
          : "";
      const query = `ContainerAppConsoleLogs_CL${filterClause} | order by TimeGenerated desc | take ${limit}`;
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
      const rows = Array.isArray(firstTable?.rows) ? firstTable.rows : [];
      return rows
        .filter((row): row is unknown[] => Array.isArray(row))
        .map((row) => ({
          timestamp: typeof row[0] === "string" ? row[0] : now().toISOString(),
          stream: typeof row[1] === "string" ? row[1] : input.logGroup,
          message: deps.redactor.redact(String(row[2] ?? row[row.length - 1] ?? "")),
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
      const written: string[] = [];
      for (const secret of input.secrets) {
        // Key Vault secret names allow only alphanumerics and hyphens.
        const kvName = secret.name.replace(/[^a-zA-Z0-9-]/g, "-");
        const url = `${vaultUrl}/secrets/${encodeURIComponent(kvName)}?api-version=7.4`;
        const res = await deps.fetch(url, {
          method: "PUT",
          headers: {
            authorization: `Bearer ${token}`,
            "content-type": "application/json",
          },
          body: JSON.stringify({
            value: secret.value,
            ...(secret.description ? { contentType: secret.description } : {}),
          }),
        });
        if (!res.ok) {
          const text = await res.text();
          throw new AzureProviderError(
            "COMMAND_FAILED",
            deps.redactor.redact(
              `Failed to write Key Vault secret "${kvName}" (HTTP ${res.status}): ${text.slice(0, 200)}`,
            ),
          );
        }
        written.push(kvName);
      }
      return { written };
    },

    async listSnapshots(input): Promise<readonly ManagedCloudSnapshotEntry[]> {
      const rg =
        deps.env.AZURE_RESOURCE_GROUP ?? `rg-${input.identifierPrefix.replace(/-db$/, "")}`;
      const urlPath = `/subscriptions/{subscriptionId}/resourceGroups/${encodeURIComponent(rg)}/providers/Microsoft.DBforPostgreSQL/flexibleServers/${encodeURIComponent(input.identifierPrefix)}/backups?api-version=2024-08-01`;
      const res = await armRequest("GET", urlPath);
      if (res.status < 200 || res.status >= 300) {
        throw new AzureProviderError(
          "COMMAND_FAILED",
          deps.redactor.redact(
            `Failed to list Azure PostgreSQL Flexible Server backups (HTTP ${res.status}): ${res.text.slice(0, 200)}`,
          ),
        );
      }
      const items = isObject(res.json) && Array.isArray(res.json.value) ? res.json.value : [];
      const snapshots: ManagedCloudSnapshotEntry[] = items.filter(isObject).map((item) => {
        const props = isObject(item.properties) ? item.properties : {};
        return {
          id: typeof item.name === "string" ? item.name : "unknown",
          service: "flexible-postgres",
          engine: "postgres",
          createdAt:
            typeof props.completedTime === "string" ? props.completedTime : now().toISOString(),
          status: typeof props.backupType === "string" ? props.backupType : "Available",
        };
      });
      // Sort newest-first so callers can pick index 0 deterministically.
      return snapshots.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    },

    async takeSnapshot(input): Promise<ManagedCloudSnapshotEntry> {
      const rg = deps.env.AZURE_RESOURCE_GROUP ?? `rg-${input.instanceId.replace(/-db$/, "")}`;
      const urlPath = `/subscriptions/{subscriptionId}/resourceGroups/${encodeURIComponent(rg)}/providers/Microsoft.DBforPostgreSQL/flexibleServers/${encodeURIComponent(input.instanceId)}/backups/${encodeURIComponent(input.snapshotId)}?api-version=2024-08-01`;
      const res = await armRequest("PUT", urlPath, {});
      if (res.status < 200 || res.status >= 300) {
        throw new AzureProviderError(
          "COMMAND_FAILED",
          deps.redactor.redact(
            `Failed to create Azure PostgreSQL backup "${input.snapshotId}" (HTTP ${res.status}): ${res.text.slice(0, 200)}`,
          ),
        );
      }
      return {
        id: input.snapshotId,
        service: input.service,
        engine: input.service.includes("mysql") ? "mysql" : "postgres",
        createdAt: now().toISOString(),
        status: "Completed",
      };
    },

    async runRestoreDrill(input): Promise<ManagedCloudRestoreDrillResult> {
      const started = now().getTime();
      const rg =
        deps.env.AZURE_RESOURCE_GROUP ??
        `rg-${input.drillInstanceId.replace(/-db-drill$|-drill$/, "")}`;
      const sourceServer =
        deps.env.AZURE_DB_SERVER_ID ??
        `/subscriptions/${deps.env.AZURE_SUBSCRIPTION_ID ?? ""}/resourceGroups/${rg}/providers/Microsoft.DBforPostgreSQL/flexibleServers/${input.drillInstanceId.replace(/-drill$/, "")}`;
      const drillPath = `/subscriptions/{subscriptionId}/resourceGroups/${encodeURIComponent(rg)}/providers/Microsoft.DBforPostgreSQL/flexibleServers/${encodeURIComponent(input.drillInstanceId)}?api-version=2024-08-01`;

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
          cleanedUp: true,
          detail: deps.redactor.redact(
            `Restore drill create failed (HTTP ${createRes.status}): ${createRes.text.slice(0, 200)}`,
          ),
        };
      }

      // Poll until the throwaway private server reports state === "Ready".
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
        await sleep(500);
      }

      // Always delete the throwaway drill server and confirm 404 before claiming cleanedUp: true.
      await armRequest("DELETE", drillPath);
      let cleanedUp = false;
      for (let attempt = 0; attempt < maxPolls; attempt++) {
        const check = await armRequest("GET", drillPath);
        if (check.status === 404) {
          cleanedUp = true;
          break;
        }
        await sleep(500);
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
            : `Restored and verified ${input.drillInstanceId}, but deletion was not yet confirmed after ${maxPolls} polls.`
          : `Throwaway restore server ${input.drillInstanceId} did not reach Ready within ${maxPolls} polls (cleanedUp=${String(cleanedUp)}).`,
      };
    },
  };
}
