/**
 * Lightweight, injectable Google Cloud REST connector (Feature 039, T3905, ADR 0040 D3).
 *
 * Zero `@google-cloud/*` SDK dependencies and zero runtime `@opscrew/*` imports.
 * Uses `GOOGLE_OAUTH_ACCESS_TOKEN` / `GCP_ACCESS_TOKEN` + `GOOGLE_CLOUD_PROJECT` / `GCP_PROJECT_ID`
 * through injected `deps.fetch` with per-request timeouts, redacts every error/log line via
 * `deps.redactor.redact()`, writes Secret Manager versions out-of-band (never `.tfstate`), and
 * runs honest, operation-polled Cloud SQL restore drills with `try/finally` cleanup guarantees.
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

export class GcpProviderError extends Error {
  readonly code: string;
  readonly hint?: string;

  constructor(code: string, message: string, options?: { readonly hint?: string }) {
    super(message);
    this.name = "GcpProviderError";
    this.code = code;
    if (options?.hint !== undefined) {
      this.hint = options.hint;
    }
  }
}

export interface GcpCredentials {
  readonly projectId: string;
  readonly accessToken: string;
}

/** Canonical Cloud Run / Compute Engine name clamped to GCP's 49-char service limit. */
export function gcpServiceName(appName: string, environment: string): string {
  const raw = `opscrew-${appName}-${environment}`
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");
  if (raw.length <= 49) return raw;
  const suffix = createHash("sha256").update(raw).digest("hex").slice(0, 6);
  return `${raw.slice(0, 42).replace(/-+$/g, "")}-${suffix}`;
}

/** Canonical Cloud SQL instance identifier matching `database.tf`. */
export function gcpDbInstanceName(appName: string, environment: string): string {
  return `${gcpServiceName(appName, environment)}-db`.slice(0, 63);
}

function readCredentials(env: Readonly<Record<string, string | undefined>>): GcpCredentials {
  const projectId = (env.GOOGLE_CLOUD_PROJECT ?? env.GCP_PROJECT_ID ?? "").trim();
  const accessToken = (env.GOOGLE_OAUTH_ACCESS_TOKEN ?? env.GCP_ACCESS_TOKEN ?? "").trim();
  if (!projectId) {
    throw new GcpProviderError(
      "CREDENTIALS_MISSING",
      "GOOGLE_CLOUD_PROJECT (or GCP_PROJECT_ID) is not set.",
      {
        hint: "Export GOOGLE_CLOUD_PROJECT and GOOGLE_OAUTH_ACCESS_TOKEN (`gcloud auth print-access-token`).",
      },
    );
  }
  if (!accessToken) {
    throw new GcpProviderError(
      "CREDENTIALS_MISSING",
      "GOOGLE_OAUTH_ACCESS_TOKEN (or GCP_ACCESS_TOKEN) is not set.",
      {
        hint: "Run `export GOOGLE_OAUTH_ACCESS_TOKEN=$(gcloud auth print-access-token)`; GitHub Actions deploys use keyless Workload Identity Federation.",
      },
    );
  }
  return { projectId, accessToken };
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function authExpiryHint(status: number): string {
  return status === 401
    ? " Access token may have expired (1h TTL); re-run `export GOOGLE_OAUTH_ACCESS_TOKEN=$(gcloud auth print-access-token)`."
    : "";
}

const DEFAULT_SLEEP = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));
const REQUEST_TIMEOUT_MS = 30_000;
const DRILL_POLL_INTERVAL_MS = 15_000;
/** Default 180 polls x 15s = 45 minutes (covers realistic 10-30 min Cloud SQL clones). */
const DEFAULT_MAX_DRILL_POLLS = 180;

export function createGcpConnector(deps: ManagedCloudConnectorDeps): ManagedCloudConnector {
  const now = deps.now ?? (() => new Date());
  const sleep = deps.sleep ?? DEFAULT_SLEEP;
  const maxPolls = deps.maxPollAttempts ?? DEFAULT_MAX_DRILL_POLLS;

  async function gcpFetch(
    method: "GET" | "POST" | "PUT" | "DELETE",
    url: string,
    payload?: unknown,
  ): Promise<{ status: number; json?: unknown; text: string; projectId: string }> {
    const creds = readCredentials(deps.env);
    const resolvedUrl = url.replace("{projectId}", encodeURIComponent(creds.projectId));
    const res = await deps.fetch(resolvedUrl, {
      method,
      headers: {
        authorization: `Bearer ${creds.accessToken}`,
        ...(payload === undefined ? {} : { "content-type": "application/json" }),
      },
      ...(payload === undefined ? {} : { body: JSON.stringify(payload) }),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    const text = await res.text();
    let json: unknown;
    try {
      json = text.length > 0 ? JSON.parse(text) : undefined;
    } catch {
      json = undefined;
    }
    return { status: res.status, json, text, projectId: creds.projectId };
  }

  return {
    async verifyCredentials() {
      try {
        const res = await gcpFetch(
          "GET",
          "https://cloudresourcemanager.googleapis.com/v3/projects/{projectId}",
        );
        if (res.status < 200 || res.status >= 300) {
          return {
            ok: false,
            error: deps.redactor.redact(
              `GCP project verification failed (HTTP ${res.status}): ${res.text.slice(0, 200)}${authExpiryHint(res.status)}`,
            ),
          };
        }
        const projectId =
          isObject(res.json) && typeof res.json.projectId === "string"
            ? res.json.projectId
            : res.projectId;
        const displayName =
          isObject(res.json) && typeof res.json.displayName === "string"
            ? res.json.displayName
            : projectId;
        return {
          ok: true,
          accountId: projectId,
          principalArn: `gcp:project:${displayName}`,
        };
      } catch (error) {
        return {
          ok: false,
          error: deps.redactor.redact(error instanceof Error ? error.message : String(error)),
        };
      }
    },

    async readStatus(input): Promise<ManagedCloudStatusSummary> {
      const name = gcpServiceName(input.appName, input.environment);
      if (input.computeKind === "compute-engine") {
        const zone = `${input.region}-a`;
        const res = await gcpFetch(
          "GET",
          `https://compute.googleapis.com/compute/v1/projects/{projectId}/zones/${encodeURIComponent(zone)}/instances/${encodeURIComponent(name)}`,
        );
        const state =
          isObject(res.json) && typeof res.json.status === "string"
            ? res.json.status
            : `HTTP ${res.status}`;
        return {
          healthy: res.status >= 200 && res.status < 300 && state === "RUNNING",
          region: input.region,
          accountId: res.projectId,
          compute: { kind: "compute-engine", status: state },
          services: [],
          alarms: [],
        };
      }

      const res = await gcpFetch(
        "GET",
        `https://run.googleapis.com/v2/projects/{projectId}/locations/${encodeURIComponent(input.region)}/services/${encodeURIComponent(name)}`,
      );
      const uri = isObject(res.json) && typeof res.json.uri === "string" ? res.json.uri : undefined;
      const terminal =
        isObject(res.json) && isObject(res.json.terminalCondition)
          ? res.json.terminalCondition
          : undefined;
      const status =
        typeof terminal?.state === "string"
          ? terminal.state
          : res.status >= 200 && res.status < 300
            ? "UNKNOWN"
            : `HTTP ${res.status}`;
      return {
        healthy: res.status >= 200 && res.status < 300 && status === "CONDITION_SUCCEEDED",
        region: input.region,
        accountId: res.projectId,
        compute: {
          kind: "cloud-run",
          status,
          ...(uri ? { endpoint: uri } : {}),
        },
        services: [],
        alarms: [],
      };
    },

    async readLogs(input): Promise<readonly ManagedCloudLogLine[]> {
      const creds = readCredentials(deps.env);
      const limit = Math.max(1, Math.min(input.limit ?? 100, 1000));
      const resourceFilter =
        input.computeKind === "compute-engine"
          ? `resource.type="gce_instance" AND labels."compute.googleapis.com/resource_name"=${JSON.stringify(input.logGroup)}`
          : `resource.type="cloud_run_revision" AND resource.labels.service_name=${JSON.stringify(input.logGroup)}`;
      const parts = [
        resourceFilter,
        ...(input.since ? [`timestamp>=${JSON.stringify(input.since.toISOString())}`] : []),
        ...(input.filterPattern ? [input.filterPattern] : []),
      ];
      const res = await gcpFetch("POST", "https://logging.googleapis.com/v2/entries:list", {
        resourceNames: [`projects/${creds.projectId}`],
        filter: parts.join(" AND "),
        orderBy: "timestamp desc",
        pageSize: limit,
      });
      if (res.status < 200 || res.status >= 300) {
        throw new GcpProviderError(
          "COMMAND_FAILED",
          deps.redactor.redact(
            `Cloud Logging query failed (HTTP ${res.status}): ${res.text.slice(0, 200)}${authExpiryHint(res.status)}`,
          ),
        );
      }
      const entries = isObject(res.json) && Array.isArray(res.json.entries) ? res.json.entries : [];
      return entries.filter(isObject).map((entry) => {
        const textPayload =
          typeof entry.textPayload === "string"
            ? entry.textPayload
            : isObject(entry.jsonPayload)
              ? JSON.stringify(entry.jsonPayload)
              : "";
        return {
          timestamp: typeof entry.timestamp === "string" ? entry.timestamp : now().toISOString(),
          stream: typeof entry.logName === "string" ? entry.logName : input.logGroup,
          message: deps.redactor.redact(textPayload),
        };
      });
    },

    async writeSecrets(input): Promise<{ readonly written: readonly string[] }> {
      const sanitizedToRaw = new Map<string, string>();
      const prepared: Array<{ secretId: string; value: string }> = [];
      for (const secret of input.secrets) {
        const secretId = secret.name.replace(/[^a-zA-Z0-9_-]/g, "_");
        const existing = sanitizedToRaw.get(secretId);
        if (existing !== undefined && existing !== secret.name) {
          throw new GcpProviderError(
            "INVALID_INPUT",
            `GCP Secret Manager name collision: "${existing}" and "${secret.name}" both map to "${secretId}".`,
          );
        }
        sanitizedToRaw.set(secretId, secret.name);
        prepared.push({ secretId, value: secret.value });
      }

      const written: string[] = [];
      for (const item of prepared) {
        const url = `https://secretmanager.googleapis.com/v1/projects/{projectId}/secrets/${encodeURIComponent(item.secretId)}:addVersion`;
        const res = await gcpFetch("POST", url, {
          payload: { data: Buffer.from(item.value, "utf8").toString("base64") },
        });
        if (res.status < 200 || res.status >= 300) {
          throw new GcpProviderError(
            "COMMAND_FAILED",
            deps.redactor.redact(
              `Failed to add Secret Manager version for "${item.secretId}" (HTTP ${res.status}): ${res.text.slice(0, 200)}${authExpiryHint(res.status)}`,
            ),
          );
        }
        written.push(item.secretId);
      }
      return { written };
    },

    async listSnapshots(input): Promise<readonly ManagedCloudSnapshotEntry[]> {
      const res = await gcpFetch(
        "GET",
        `https://sqladmin.googleapis.com/v1/projects/{projectId}/instances/${encodeURIComponent(input.identifierPrefix)}/backupRuns`,
      );
      if (res.status < 200 || res.status >= 300) {
        throw new GcpProviderError(
          "COMMAND_FAILED",
          deps.redactor.redact(
            `Failed to list Cloud SQL backup runs (HTTP ${res.status}): ${res.text.slice(0, 200)}${authExpiryHint(res.status)}`,
          ),
        );
      }
      const dbService = input.service ?? "cloud-sql-postgres";
      const engine = dbService.includes("mysql") ? "mysql" : "postgres";
      const items = isObject(res.json) && Array.isArray(res.json.items) ? res.json.items : [];
      const snapshots: ManagedCloudSnapshotEntry[] = items.filter(isObject).map((item) => ({
        id: String(item.id ?? "unknown"),
        service: dbService,
        engine,
        createdAt:
          typeof item.windowStartTime === "string"
            ? item.windowStartTime
            : typeof item.enqueuedTime === "string"
              ? item.enqueuedTime
              : now().toISOString(),
        status: typeof item.status === "string" ? item.status : "SUCCESSFUL",
      }));
      return snapshots.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    },

    async takeSnapshot(input): Promise<ManagedCloudSnapshotEntry> {
      const res = await gcpFetch(
        "POST",
        `https://sqladmin.googleapis.com/v1/projects/{projectId}/instances/${encodeURIComponent(input.instanceId)}/backupRuns`,
        { description: input.snapshotId },
      );
      if (res.status < 200 || res.status >= 300) {
        throw new GcpProviderError(
          "COMMAND_FAILED",
          deps.redactor.redact(
            `Failed to trigger Cloud SQL backup "${input.snapshotId}" (HTTP ${res.status}): ${res.text.slice(0, 200)}${authExpiryHint(res.status)}`,
          ),
        );
      }
      return {
        id: input.snapshotId,
        service: input.service,
        engine: input.service.includes("mysql") ? "mysql" : "postgres",
        createdAt: now().toISOString(),
        status: "ENQUEUED",
      };
    },

    async runRestoreDrill(input): Promise<ManagedCloudRestoreDrillResult> {
      const started = now().getTime();
      const sourceInstance =
        deps.env.GCP_DB_INSTANCE ?? input.drillInstanceId.replace(/-drill$/, "");
      if (input.drillInstanceId === sourceInstance || !input.drillInstanceId.endsWith("-drill")) {
        throw new GcpProviderError(
          "INVALID_INPUT",
          `Refused restore drill: throwaway drillInstanceId "${input.drillInstanceId}" must differ from source instance "${sourceInstance}" and end with "-drill".`,
        );
      }

      // Resolve backupRunId -> exact ISO pointInTime so the drill clones the backup, not live HEAD.
      let pointInTime: string | undefined;
      if (/^\d{4}-\d{2}-\d{2}T/.test(input.snapshotId)) {
        pointInTime = input.snapshotId;
      } else {
        const bkpRes = await gcpFetch(
          "GET",
          `https://sqladmin.googleapis.com/v1/projects/{projectId}/instances/${encodeURIComponent(sourceInstance)}/backupRuns/${encodeURIComponent(input.snapshotId)}`,
        );
        if (bkpRes.status < 200 || bkpRes.status >= 300 || !isObject(bkpRes.json)) {
          return {
            snapshotId: input.snapshotId,
            service: input.service,
            verified: false,
            durationMs: Math.max(0, now().getTime() - started),
            cleanedUp: true,
            detail: deps.redactor.redact(
              `Could not resolve Cloud SQL backup run "${input.snapshotId}" to a point-in-time timestamp (HTTP ${bkpRes.status})${authExpiryHint(bkpRes.status)}.`,
            ),
          };
        }
        const ts =
          typeof bkpRes.json.endTime === "string"
            ? bkpRes.json.endTime
            : typeof bkpRes.json.windowStartTime === "string"
              ? bkpRes.json.windowStartTime
              : undefined;
        if (ts === undefined) {
          return {
            snapshotId: input.snapshotId,
            service: input.service,
            verified: false,
            durationMs: Math.max(0, now().getTime() - started),
            cleanedUp: true,
            detail: `Cloud SQL backup run "${input.snapshotId}" has no endTime or windowStartTime; refusing to clone current HEAD instead of the backup.`,
          };
        }
        pointInTime = ts;
      }

      const cloneUrl = `https://sqladmin.googleapis.com/v1/projects/{projectId}/instances/${encodeURIComponent(sourceInstance)}/clone`;
      const drillUrl = `https://sqladmin.googleapis.com/v1/projects/{projectId}/instances/${encodeURIComponent(input.drillInstanceId)}`;

      const createRes = await gcpFetch("POST", cloneUrl, {
        cloneContext: {
          destinationInstanceName: input.drillInstanceId,
          pointInTime,
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
            `Cloud SQL restore drill clone failed (HTTP ${createRes.status}): ${createRes.text.slice(0, 200)}${authExpiryHint(createRes.status)}`,
          ),
        };
      }

      const opName =
        isObject(createRes.json) && typeof createRes.json.name === "string"
          ? createRes.json.name
          : undefined;

      let verified = false;
      let cleanedUp = false;
      let deleteStatus = 0;
      let pollError: string | undefined;

      try {
        // 1. Wait for the clone operation to reach DONE before checking instance or issuing DELETE (prevents HTTP 409).
        if (opName !== undefined) {
          const opUrl = `https://sqladmin.googleapis.com/v1/projects/{projectId}/operations/${encodeURIComponent(opName)}`;
          for (let attempt = 0; attempt < maxPolls; attempt++) {
            const opRes = await gcpFetch("GET", opUrl);
            if (opRes.status === 401) {
              pollError = `Operation poll failed with HTTP 401.${authExpiryHint(401)}`;
              break;
            }
            const opStatus = isObject(opRes.json) ? String(opRes.json.status ?? "") : "";
            if (opRes.status >= 200 && opRes.status < 300 && opStatus === "DONE") {
              if (isObject(opRes.json) && opRes.json.error !== undefined) {
                pollError = `Clone operation failed: ${JSON.stringify(opRes.json.error).slice(0, 200)}`;
              }
              break;
            }
            await sleep(DRILL_POLL_INTERVAL_MS);
          }
        }

        // 2. Verify throwaway clone instance reaches RUNNABLE.
        if (pollError === undefined) {
          for (let attempt = 0; attempt < maxPolls; attempt++) {
            const poll = await gcpFetch("GET", drillUrl);
            if (poll.status === 401) {
              pollError = `Instance poll failed with HTTP 401.${authExpiryHint(401)}`;
              break;
            }
            const state = isObject(poll.json) ? String(poll.json.state ?? "") : "";
            if (poll.status >= 200 && poll.status < 300 && state === "RUNNABLE") {
              verified = true;
              break;
            }
            await sleep(DRILL_POLL_INTERVAL_MS);
          }
        }
      } catch (err) {
        pollError = err instanceof Error ? err.message : String(err);
      } finally {
        // Always attempt cleanup of the throwaway drill instance even if polling threw or returned 401.
        try {
          const deleteRes = await gcpFetch("DELETE", drillUrl);
          deleteStatus = deleteRes.status;
          cleanedUp = deleteRes.status === 404;
          if (deleteRes.status >= 200 && deleteRes.status < 300) {
            for (let attempt = 0; attempt < maxPolls; attempt++) {
              const check = await gcpFetch("GET", drillUrl);
              if (check.status === 404) {
                cleanedUp = true;
                break;
              }
              await sleep(DRILL_POLL_INTERVAL_MS);
            }
          }
        } catch (cleanupErr) {
          cleanedUp = false;
          const msg = cleanupErr instanceof Error ? cleanupErr.message : String(cleanupErr);
          pollError = pollError ? `${pollError}; cleanup failed: ${msg}` : `cleanup failed: ${msg}`;
        }
      }

      return {
        snapshotId: input.snapshotId,
        service: input.service,
        verified,
        durationMs: Math.max(0, now().getTime() - started),
        cleanedUp,
        detail: deps.redactor.redact(
          verified
            ? cleanedUp
              ? `Cloned private throwaway Cloud SQL instance ${input.drillInstanceId} at ${pointInTime}, verified RUNNABLE, and confirmed deleted.`
              : `Cloned and verified ${input.drillInstanceId} at ${pointInTime}, but deletion was not confirmed (DELETE HTTP ${deleteStatus}).`
            : `Throwaway Cloud SQL clone ${input.drillInstanceId} did not reach RUNNABLE (${pollError ?? `timed out after ${maxPolls} polls`}; DELETE HTTP ${deleteStatus}, cleanedUp=${String(cleanedUp)}).`,
        ),
      };
    },
  };
}
