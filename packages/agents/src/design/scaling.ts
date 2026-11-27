import { listText } from "@opscrew/core";
import { KAMAL_PROXY_MEMORY_MB } from "@opscrew/iac-templates";
import {
  APP_SERVER,
  appCopyServers,
  type DeployPlan,
  type ExtraServer,
  hasRemoteAppCopies,
  isCloudTarget,
  type PlanService,
  type ProjectFacts,
  postgresPooler,
  webServers,
} from "@opscrew/plan-schema";
import { providerProfile } from "../providers";
import type { MemoryLimit } from "../shared/memory";
import { estimateHop, type ServerPlace } from "./delay";
import { loginsVersion } from "./postgres-logins";

/**
 * Memory limits of the web and worker copies placed on extra server `serverName` (feature 033):
 * the web process plus `app-proxy` (32 MB) when `app.servers` names it, and each enabled worker's
 * `memoryMb * count` when `worker.servers` names it. Empty on the front app server (`app`), whose
 * own limits are already counted by `appMemoryLimits`.
 */
export function copyServerLimits(
  plan: Pick<DeployPlan, "app" | "processes">,
  serverName: string,
): MemoryLimit[] {
  if (serverName === APP_SERVER) return [];
  const limits: MemoryLimit[] = [];
  if ((plan.app.servers ?? []).includes(serverName)) {
    limits.push(
      { name: "the web process", memoryMb: plan.app.memoryMb },
      { name: "app-proxy", memoryMb: KAMAL_PROXY_MEMORY_MB },
    );
  }
  for (const worker of plan.processes.workers) {
    if (!worker.enabled || !(worker.servers ?? []).includes(serverName)) continue;
    limits.push({
      name: worker.count > 1 ? `worker ${worker.name} (×${worker.count})` : `worker ${worker.name}`,
      memoryMb: worker.memoryMb * worker.count,
    });
  }
  return limits;
}

/**
 * Plain-English warnings for each stateless-readiness issue detected during `opscrew analyze`
 * (`facts.statelessIssues`) when `app.servers` runs multiple web copies across servers (feature
 * 033). Hard blockers (`storage.sqlite`, `storage.files`) are refused by `DeployPlanSchema`.
 */
export function statelessReadinessWarnings(
  plan: Pick<DeployPlan, "app">,
  facts: Pick<ProjectFacts, "statelessIssues"> | undefined,
): string[] {
  if ((plan.app.servers?.length ?? 0) === 0) return [];
  const issues = facts?.statelessIssues ?? [];
  if (issues.length === 0) return [];
  const count = webServers(plan).length;
  return issues.map((issue) => {
    const label = issue.kind === "local-sessions" ? "local sessions" : "local file uploads";
    const where = issue.file === undefined ? "" : ` in ${issue.file}`;
    return `Multi-server web scaling warning (${label}, ${issue.framework}${where}): ${issue.evidence}. Across ${count} web servers, visitors routed to different copies can see inconsistent state. ${issue.remediation}`;
  });
}

/** Result of checking PostgreSQL connection pooling for multi-server web scaling. */
export interface PgBouncerScalingResult {
  plan: DeployPlan;
  lines: string[];
  warnings: string[];
}

/**
 * Recommends and enables PgBouncer (`options.pooler: "pgbouncer"`, with `options.logins:
 * "separate"`) on enabled self-hosted PostgreSQL services when `webServers(plan).length > 1`
 * (feature 033, 050). When PostgreSQL is older than 15 or an already-deployed database does not
 * use `logins: "separate"`, leaves the service untouched and emits a plain-English warning instead.
 */
export function pgBouncerScaling(plan: DeployPlan, deployed = false): PgBouncerScalingResult {
  const copyCount = appCopyServers(plan).length;
  if (copyCount === 0) return { plan, lines: [], warnings: [] };
  const webCount = webServers(plan).length;
  const serverLabel =
    webCount > 1 ? `${webCount} web servers` : `${1 + copyCount} app/worker servers`;
  const lines: string[] = [];
  const warnings: string[] = [];
  let changed = false;
  const services = plan.services.map((service): PlanService => {
    if (!service.enabled || service.kind !== "postgres" || postgresPooler(service)) return service;
    const canAutoEnable =
      loginsVersion(service.version) && (!deployed || service.options.logins === "separate");
    if (canAutoEnable) {
      changed = true;
      lines.push(
        `Enabled PgBouncer (\`pooler: pgbouncer\`) on PostgreSQL (${service.name}): running ${serverLabel} multiplies database connections, and PgBouncer pools them to avoid exhausting PostgreSQL's \`max_connections\`.`,
      );
      return {
        ...service,
        options: {
          ...service.options,
          logins: "separate",
          pooler: "pgbouncer",
        },
      };
    }
    if (!loginsVersion(service.version)) {
      warnings.push(
        `PostgreSQL (${service.name}, version ${service.version}) has no connection pooler while ${serverLabel} are planned: multiple copies multiply database connections and can exhaust PostgreSQL's \`max_connections\`. Upgrade PostgreSQL to 15 or newer and set \`options: { logins: separate, pooler: pgbouncer }\` on ${service.name} in opscrew/plan.yaml.`,
      );
    } else {
      warnings.push(
        `PostgreSQL (${service.name}) has no connection pooler while ${serverLabel} are planned: multiple copies multiply database connections and can exhaust PostgreSQL's \`max_connections\`. Enable \`options: { logins: separate, pooler: pgbouncer }\` on ${service.name} in opscrew/plan.yaml.`,
      );
    }
    return service;
  });
  return {
    plan: changed ? { ...plan, services } : plan,
    lines,
    warnings,
  };
}

/** Where a server runs, for cross-provider and cross-region latency checks. */
function placeOfTarget(target: DeployPlan["target"] | ExtraServer["target"]): ServerPlace {
  return isCloudTarget(target)
    ? { provider: target.provider, location: target.location }
    : { provider: "own" };
}

/** Plain-English label for a server's provider and location. */
function placeLabel(place: ServerPlace): string {
  return place.provider === "own"
    ? "your own server"
    : `${providerProfile(place.provider).displayName} (${place.location})`;
}

/** True when two servers are on different providers or in different cloud locations. */
function isCrossPlace(a: ServerPlace, b: ServerPlace): boolean {
  if (a.provider !== b.provider) return true;
  if (a.provider === "own" || b.provider === "own") return false;
  return a.location !== b.location;
}

/** Plain-English list of web/worker copies running on extra server `copyName`. */
function copyRoles(plan: Pick<DeployPlan, "app" | "processes">, copyName: string): string {
  const roles: string[] = [];
  if ((plan.app.servers ?? []).includes(copyName)) roles.push("the web process");
  for (const worker of plan.processes.workers) {
    if (worker.enabled && (worker.servers ?? []).includes(copyName)) {
      roles.push(`worker ${worker.name}`);
    }
  }
  return listText(roles);
}

/**
 * Warnings when `hasRemoteAppCopies(plan)` is true and an enabled backing service (database,
 * cache, queue, etc.) runs on a different provider or different cloud `location` than a remote
 * web or worker copy server (feature 033).
 */
export function copyLatencyWarnings(
  plan: Pick<DeployPlan, "target" | "app" | "processes" | "services" | "servers">,
): string[] {
  if (!hasRemoteAppCopies(plan)) return [];
  const enabled = plan.services.filter((service) => service.enabled);
  if (enabled.length === 0) return [];

  const byServer = new Map<string, PlanService[]>();
  for (const service of enabled) {
    const serverName = service.server ?? APP_SERVER;
    const list = byServer.get(serverName) ?? [];
    list.push(service);
    byServer.set(serverName, list);
  }

  const targetOf = (name: string): DeployPlan["target"] | ExtraServer["target"] | undefined =>
    name === APP_SERVER ? plan.target : plan.servers?.find((s) => s.name === name)?.target;

  const warnings: string[] = [];
  for (const copyName of appCopyServers(plan)) {
    const copyTarget = targetOf(copyName);
    if (copyTarget === undefined) continue;
    const copyPlace = placeOfTarget(copyTarget);
    const roles = copyRoles(plan, copyName);

    for (const [serviceServer, svcs] of byServer) {
      if (serviceServer === copyName) continue;
      const serviceTarget = targetOf(serviceServer);
      if (serviceTarget === undefined) continue;
      const servicePlace = placeOfTarget(serviceTarget);
      if (!isCrossPlace(copyPlace, servicePlace)) continue;

      const hop = estimateHop(copyPlace, servicePlace);
      const why =
        copyPlace.provider !== servicePlace.provider ? "different providers" : "different regions";
      const estimate =
        hop === undefined ? "" : ` (about ${Math.round(hop.roundTripMs)} ms per round trip)`;
      const svcNames = listText(svcs.map((s) => s.name));
      warnings.push(
        `Cross-network database/cache latency warning: server ${copyName} (${placeLabel(copyPlace)}, running ${roles}) and ${svcNames} on server ${serviceServer} (${placeLabel(servicePlace)}) are on ${why}. Every query crosses the internet over WireGuard and adds round-trip latency${estimate}. Place copy servers in the same provider and region as the database when low latency matters.`,
      );
    }
  }
  return warnings;
}
