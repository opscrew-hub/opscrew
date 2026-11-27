import type { RemoteExec } from "@opscrew/contracts";
import { listText, OpsCrewError, upperFirst } from "@opscrew/core";
import {
  APP_KAMAL_PROXY_SERVICE,
  EDGE_PROJECT,
  hostSettingsServices,
  serviceSpec,
} from "@opscrew/iac-templates";
import { APP_SERVER, type DeployPlan, poolerName, postgresPooler } from "@opscrew/plan-schema";
import { hasExtraServers } from "../shared/servers";

/** A component of the plan that runs as containers: its Compose service and what it is. */
export interface PlannedComponent {
  /** The Compose service: `app`, a worker's name, `cron`, a service's name. */
  service: string;
  /** In words: `the web process`, `the worker`, `the cron jobs`, `MySQL`, `PgBouncer`. */
  what: string;
}

/**
 * The plan's components that run as containers of the app's Compose project (FR-1331): the web
 * process, every enabled worker, the cron jobs when one is enabled, and every enabled service, a
 * PostgreSQL's pooler (`<db>-pooler`, 050) after its database.
 */
export function plannedComponents(plan: DeployPlan): PlannedComponent[] {
  return [
    { service: "app", what: "the web process" },
    ...plan.processes.workers
      .filter((worker) => worker.enabled)
      .map((worker) => ({ service: worker.name, what: "the worker" })),
    ...(plan.processes.cron.some((job) => job.enabled)
      ? [{ service: "cron", what: "the cron jobs" }]
      : []),
    ...plan.services
      .filter((service) => service.enabled)
      .flatMap((service) => [
        { service: service.name, what: serviceSpec(service.kind).title },
        ...(postgresPooler(service) ? [{ service: poolerName(service), what: "PgBouncer" }] : []),
      ]),
  ];
}

/**
 * The server a component runs on: a service's `server` (a pooler's, its database's), else the
 * app's server (the web process, workers and cron jobs always run there).
 */
export function componentServer(plan: DeployPlan, service: string): string {
  return (
    plan.services.find(
      (s) => s.name === service || (postgresPooler(s) && poolerName(s) === service),
    )?.server ?? APP_SERVER
  );
}

/** The planned components on `server` (including web & worker copies placed on extra servers, 033). */
function componentsOn(plan: DeployPlan, server: string): PlannedComponent[] {
  if (server === APP_SERVER) {
    return plannedComponents(plan).filter((c) => componentServer(plan, c.service) === APP_SERVER);
  }
  return [
    ...((plan.app.servers ?? []).includes(server)
      ? [{ service: "app", what: "the web process" }]
      : []),
    ...plan.processes.workers
      .filter((worker) => worker.enabled && (worker.servers?.includes(server) ?? false))
      .map((worker) => ({ service: worker.name, what: "the worker" })),
    ...plannedComponents(plan).filter((c) => componentServer(plan, c.service) === server),
  ];
}

/**
 * How a block about `server` names it: ` on server <name>` when the app has extra servers, else
 * nothing (one server needs no name).
 */
export function onServer(plan: Pick<DeployPlan, "servers">, server: string): string {
  return hasExtraServers(plan) ? ` on server ${server}` : "";
}

/** One container of the app's Compose project: its name, whether it runs, and its Docker networks. */
export interface AppContainer {
  name: string;
  running: boolean;
  /** Docker networks the container is attached to, when read from `docker ps`. */
  networks?: readonly string[];
}

/**
 * The Compose service of the app's container `<app>-<service>-<n>`; undefined for another name and
 * for one-off containers (`docker compose run`).
 */
export function containerService(app: string, name: string): string | undefined {
  const service = new RegExp(`^${app}-(.+)-\\d+$`).exec(name)?.[1];
  return service === undefined || service.includes("-run-") ? undefined : service;
}

/**
 * Containers that run once and exit, so a stopped one is no fault: the release command and the
 * one-shot container that sets the host's kernel settings on a server OpsCrew created.
 */
export function oneShotServices(plan: DeployPlan): Set<string> {
  return new Set(["release", ...hostSettingsServices(plan)]);
}

/** A planned component and how many of its containers there are and run. */
export interface ComponentState extends PlannedComponent {
  containers: number;
  running: number;
}

/** Each planned component's containers, and the app's other services found on the server. */
export interface ComponentStatus {
  components: ComponentState[];
  /** The app's Compose services on the server that are no component of the plan, sorted. */
  others: string[];
  /**
   * Non-proxy services of the app still attached to the shared `opscrew-edge` network (present
   * only when any are found; fixed by the next deploy).
   */
  onEdgeNetwork?: string[];
  /**
   * True when the app runs on its server without a running per-app `kamal-proxy` container
   * (present only when true).
   */
  missingAppProxy?: boolean;
}

/** One container of the app's Compose project, by its Compose service. */
export interface ServiceContainer {
  service: string;
  running: boolean;
  /** Docker networks the container is attached to, when read from `docker ps`. */
  networks?: readonly string[];
}

/** The app's containers `containers` by their Compose service, one-off containers left out. */
export function serviceContainers(
  app: string,
  containers: readonly AppContainer[],
): ServiceContainer[] {
  return containers.flatMap(({ name, running, networks }) => {
    const service = containerService(app, name);
    return service === undefined
      ? []
      : [{ service, running, ...(networks !== undefined ? { networks } : {}) }];
  });
}

/** How each of the plan's components on `server` runs in its app's containers `containers`. */
export function componentStatus(
  plan: DeployPlan,
  containers: readonly ServiceContainer[],
  server = APP_SERVER,
): ComponentStatus {
  const counts = new Map<string, { containers: number; running: number }>();
  const onEdge = new Set<string>();
  let hasNetworkFacts = false;
  for (const { service, running, networks } of containers) {
    const count = counts.get(service) ?? { containers: 0, running: 0 };
    count.containers += 1;
    if (running) count.running += 1;
    counts.set(service, count);
    if (networks !== undefined && networks.length > 0) {
      hasNetworkFacts = true;
      if (service !== APP_KAMAL_PROXY_SERVICE && networks.includes(EDGE_PROJECT)) {
        onEdge.add(service);
      }
    }
  }
  const components = componentsOn(plan, server).map((component) => ({
    ...component,
    ...(counts.get(component.service) ?? { containers: 0, running: 0 }),
  }));
  const planned = new Set(components.map((component) => component.service));
  const oneShot = oneShotServices(plan);
  const expectsAppProxy =
    (server === APP_SERVER || (plan.app.servers?.includes(server) ?? false)) &&
    plan.target.provider !== "portainer";
  const others = [...counts.keys()]
    .filter(
      (service) =>
        !planned.has(service) &&
        !oneShot.has(service) &&
        !(expectsAppProxy && service === APP_KAMAL_PROXY_SERVICE),
    )
    .sort();
  const onEdgeNetwork = [...onEdge].sort();
  const proxyCount = counts.get(APP_KAMAL_PROXY_SERVICE);
  const appPresent = (counts.get("app")?.containers ?? 0) > 0;
  const missingAppProxy =
    expectsAppProxy &&
    appPresent &&
    ((proxyCount !== undefined && proxyCount.running === 0) ||
      (hasNetworkFacts && (proxyCount?.running ?? 0) === 0));
  return {
    components,
    others,
    ...(onEdgeNetwork.length > 0 ? { onEdgeNetwork } : {}),
    ...(missingAppProxy ? { missingAppProxy: true } : {}),
  };
}

/** Whether a component runs, in words. */
function stateText(state: ComponentState): string {
  if (state.containers === 0) return "no container";
  if (state.running === 0) return state.containers === 1 ? "stopped" : "all copies stopped";
  if (state.running < state.containers) {
    return `${state.running} of ${state.containers} copies running`;
  }
  return state.containers === 1 ? "running" : `running (${state.containers} copies)`;
}

/**
 * The status lines of the plan's components on `server` (FR-1331): each with whether it runs when
 * `status` was read from the server, and the app's services the plan no longer has there. With
 * extra servers, the heading names the server.
 */
export function componentStatusLines(
  plan: DeployPlan,
  status: ComponentStatus | undefined,
  server = APP_SERVER,
): string[] {
  const on = onServer(plan, server);
  if (status === undefined) {
    return [
      `Components${on} (from opscrew/plan.yaml):`,
      ...componentsOn(plan, server).map(
        (component) => `  ${upperFirst(component.what)} (${component.service})`,
      ),
    ];
  }
  return [
    `Components${on}:`,
    ...status.components.map(
      (state) => `  ${upperFirst(state.what)} (${state.service}): ${stateText(state)}`,
    ),
    ...status.others.map(
      (service) =>
        `  ${service}: on ${on === "" ? "the server" : `server ${server}`}, but no component in opscrew/plan.yaml ${on === "" ? "" : "there "}any more (the next deploy removes it)`,
    ),
    ...(status.onEdgeNetwork !== undefined && status.onEdgeNetwork.length > 0
      ? [
          `  Isolation: ${listText(status.onEdgeNetwork)} ${status.onEdgeNetwork.length === 1 ? "is" : "are"} still on the shared edge network (${EDGE_PROJECT}); re-run the deploy workflow to isolate the app behind its own proxy`,
        ]
      : []),
    ...(status.missingAppProxy === true
      ? [
          `  Proxy (${APP_KAMAL_PROXY_SERVICE}): not running; re-run the deploy workflow to start the app's proxy`,
        ]
      : []),
  ];
}

/** A container name as Docker allows it. */
export const CONTAINER_NAME = /^[A-Za-z0-9][A-Za-z0-9_.-]*$/;

/**
 * The app's containers on a server, read over `remote` with `docker ps` (read-only): every
 * container of the app's Compose project `app`, running or not, except one-off ones.
 * @throws OpsCrewError `COMMAND_FAILED` when the command fails.
 */
export async function readAppContainers(remote: RemoteExec, app: string): Promise<AppContainer[]> {
  const result = await remote.run(
    `docker ps -a --filter label=com.docker.compose.project=${app} --filter label=com.docker.compose.oneoff=False --format '{{.Names}}|{{.State}}|{{.Networks}}'`,
    { timeoutMs: 30_000 },
  );
  if (result.exitCode !== 0) {
    throw new OpsCrewError(
      "COMMAND_FAILED",
      `OpsCrew could not read the app's containers on the server over SSH (exit code ${result.exitCode}).`,
      {
        hint: "Check that the server is on and that this computer reaches it as the deploy user with the project's deploy key (`opscrew status --ip` shows its address), then try again.",
      },
    );
  }
  return result.stdout.split(/\r?\n/).flatMap((line) => {
    const [name, state, networksRaw] = line.trim().split("|");
    if (name === undefined || !CONTAINER_NAME.test(name)) return [];
    const networks =
      networksRaw === undefined
        ? undefined
        : networksRaw
            .split(",")
            .map((network) => network.trim())
            .filter((network) => network !== "");
    return [
      { name, running: state === "running", ...(networks !== undefined ? { networks } : {}) },
    ];
  });
}
