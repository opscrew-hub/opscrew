/**
 * A restore drill's copy (029 plan.md 19., research R15–R17, R26): a snapshot restored on the
 * server that holds it, or this computer, into a throwaway Compose project, `<app>-drill` in
 * `.drill/<snapshot id>/` of the app's folder, to prove that the snapshot restores and the app
 * starts on it. The copy reaches nothing outside the machine and nothing reaches it: one network
 * with no internet, no published port, no hostname or proxy site, and none of the production
 * `.env`'s values. `snapshot.sh drill` (`./script`) runs it; `./record` is its approval and log.
 */
import {
  type DeployPlan,
  giteaOf,
  isHostingTarget,
  isServerlessTarget,
  poolerName,
  postgresPooler,
} from "@opscrew/plan-schema";
import { parse, Scalar, stringify } from "yaml";
import type { PreviewEnvTemplates } from "../previews";
import { wrongTarget } from "../providers";
import { noStartMigrations } from "../railpack-laravel";
import { renderCompose } from "../runtime";
import { renderServices } from "../runtime/components";
import { runtimeDir } from "../runtime-dir";
import type { RenderedFile } from "../types";
import { DIGEST_REF_PATTERN, planFilePath } from "../workflow/shared";
import type { RestoreProject } from "../workflow/snapshots";

/** The folder in the app's folder on the server that holds each drill's copy, `<id>/`. */
export const DRILL_DIR = ".drill";

/**
 * The file in a drill's folder with the values of `.env.preview`, which the app reads before its
 * `app.env` when {@link DrillOptions.previewValues} says there are some. `renderDrill` never writes
 * it: the values reach the server only when the drill runs.
 */
export const DRILL_VALUES_FILE = "values.env";

/** A snapshot's id: letters and digits only, as `snapshot.sh` checks it. */
const SNAPSHOT_ID = /^[0-9A-Za-z]+$/;

/**
 * The image of a local build on this computer whose image ID a snapshot recorded (`hex`, 64 hex
 * digits): the local deploy tags each build `opscrew-local/<app>:<first 12 digits of its ID>`.
 */
export function localBuildImage(plan: Pick<DeployPlan, "app">, hex: string): string {
  return `opscrew-local/${plan.app.name}:${hex.slice(0, 12)}`;
}

/**
 * True for an image a drill of `plan` may run: one pinned by its digest, or on this computer a
 * local build's tag ({@link localBuildImage}).
 */
export function drillImageOk(plan: DeployPlan, image: string): boolean {
  if (new RegExp(DIGEST_REF_PATTERN).test(image)) return true;
  return (
    plan.target.provider === "localhost" &&
    new RegExp(`^opscrew-local/${plan.app.name}:[0-9a-f]{12}$`).test(image)
  );
}

/** The snapshot a drill restores. */
export interface DrillSnapshot {
  /** Its id, the folder `.snapshots/<id>` on the server. */
  id: string;
  /**
   * The parts it holds (`about.json`'s services with a file): the names of services in the plan,
   * `sqlite` and `files` for the app's SQLite volume and kept folder.
   */
  parts: readonly string[];
}

/** What a drill's copy needs besides the plan and the snapshot. */
export interface DrillOptions {
  /**
   * The app's image, pinned by its digest: `ghcr.io/<owner>/<repo>[/<key>]@sha256:<hex>`; on this
   * computer also a local build's tag ({@link localBuildImage}), which is never pulled.
   */
  image: string;
  /**
   * The copy's env files, built for {@link drillPlan} with none of `.env`'s values: the app's (its
   * plain settings and the copy's own service values) and each of the copy's services'. Generated
   * values may be the preview server's `@SECRET:<name>:<format>@` placeholders, which the drill
   * fills on the server with new values.
   */
  env: PreviewEnvTemplates;
  /** `.env.preview` has values: the app reads {@link DRILL_VALUES_FILE} first. */
  previewValues?: boolean;
}

/**
 * The folder of the drill of the snapshot `id` in the app's folder, `.drill/<id>`.
 * @throws OpsCrewError for an id that is not letters and digits.
 */
export function drillDir(id: string): string {
  if (!SNAPSHOT_ID.test(id)) {
    throw wrongTarget(
      `${JSON.stringify(id)} is not a snapshot's id: it has only letters and digits.`,
    );
  }
  return `${DRILL_DIR}/${id}`;
}

/**
 * The name of the app `app`'s drill (its plan's `app.name`): `<app>-drill`, its copy's Compose
 * project and the app's name in {@link drillPlan}, which a drill's approval has typed.
 */
export function drillName(app: string): string {
  return `${app}-drill`;
}

/**
 * The drill's Compose project for the snapshot `id` (`restoreFunctions` restores into it):
 * `<app>-drill`, its file `.drill/<id>/compose.yaml` and the restores' output in
 * `.drill/<id>/restore.log`, never in the snapshots' folder.
 */
export function drillProject(plan: DeployPlan, id: string): RestoreProject {
  const dir = drillDir(id);
  return { name: drillName(plan.app.name), file: `${dir}/compose.yaml`, log: `${dir}/restore.log` };
}

/**
 * The plan a drill's copy is rendered from, which its env files are built for: the app as
 * `<app>-drill` without its release command, workers or cron, and only the enabled services the
 * snapshot holds, all on the server the drill runs on, with no extra servers, private network or
 * move. Not parsed again: the fields it changes stay valid.
 * @throws OpsCrewError for a snapshot part the plan has no service or volume of.
 */
export function drillPlan(plan: DeployPlan, snapshot: DrillSnapshot): DeployPlan {
  const services = plan.services.filter((s) => s.enabled && snapshot.parts.includes(s.name));
  const { sqlite, files } = plan.storage ?? {};
  const gitea = giteaOf(plan);
  const volumes = [
    ...(sqlite === undefined ? [] : ["sqlite"]),
    ...(files === undefined ? [] : ["files"]),
    ...(gitea === undefined ? [] : ["gitea"]),
    ...(gitea?.database === "postgres" ? ["gitea-db"] : []),
  ];
  for (const part of snapshot.parts) {
    if (!services.some((s) => s.name === part) && !volumes.includes(part)) {
      throw wrongTarget(
        `The snapshot ${snapshot.id} holds ${part}, which ${planFilePath(plan)} has no service or volume of, so OpsCrew can't restore it in a drill.`,
      );
    }
  }
  return {
    ...plan,
    app: { ...plan.app, name: drillName(plan.app.name), releaseCommand: undefined },
    processes: { workers: [], cron: [] },
    services: services.map((service) => ({ ...service, server: undefined })),
    servers: undefined,
    network: undefined,
    move: undefined,
  };
}

/**
 * The Compose services of a drill's copy besides the app, from {@link drillPlan}'s: each service,
 * then a PostgreSQL's pooler (050), which the restored app reaches its database through.
 */
export function drillServices(drill: DeployPlan): string[] {
  return drill.services.flatMap((service) =>
    postgresPooler(service) ? [service.name, poolerName(service)] : [service.name],
  );
}

/** A service of a rendered Compose file. */
type ComposeService = Record<string, unknown> & { depends_on?: Record<string, unknown> };

/**
 * The drill's copy of the snapshot on its server, each file under `.drill/<id>/` of the app's
 * folder ({@link drillDir}), rendered as the preview recipe's are (`renderCompose` and the
 * services' files) from {@link drillPlan}:
 * - `compose.yaml`, the project `<app>-drill`: the app at `o.image`, with its health check and
 *   memory limit, and the snapshot's services with their pinned images, health checks and limits
 *   (a PostgreSQL's pooler with its database, {@link drillServices}), their data in
 *   `/srv/data/<app>-drill/` (on this computer in the project's own volumes); no workers, cron, release command or host-settings container; one network, `internal: true` (no
 *   internet), and no published port or site; every container `restart: "no"`, so a kept copy
 *   never comes back after a reboot, and a local build's image is never pulled. The app reads
 *   `app.env` (after {@link DRILL_VALUES_FILE} with `o.previewValues`), never the app's `.env`,
 *   and the image is named in the file, so no `.env` is read for it either;
 * - `app.env` and `<service>.env` from `o.env`;
 * - the services' settings files, `services/<service>/<file>`.
 * @throws OpsCrewError for a target that is neither a server nor this computer, an image a drill
 * may not run ({@link drillImageOk}), a snapshot id or part the plan can't restore, or `o.env`
 * without a service's env file.
 */
export function renderDrill(
  plan: DeployPlan,
  snapshot: DrillSnapshot,
  o: DrillOptions,
): RenderedFile[] {
  const { target } = plan;
  if (target.provider === "portainer" || isHostingTarget(target) || isServerlessTarget(target)) {
    throw wrongTarget("A restore drill runs on a server, OpsCrew's or your own, or this computer.");
  }
  if (!drillImageOk(plan, o.image)) {
    throw wrongTarget(
      `The image ${JSON.stringify(o.image)} is not pinned by its digest (ghcr.io/…@sha256:<hex>).`,
    );
  }
  const dir = drillDir(snapshot.id);
  const drill = drillPlan(plan, snapshot);
  const rendered = parse(renderCompose(drill).content) as {
    services: Record<string, ComposeService>;
    volumes?: Record<string, unknown>;
  };
  const kept = ["app", ...drillServices(drill)];
  const services = Object.fromEntries(
    kept.map((name) => {
      const {
        ports: _ports,
        networks: _networks,
        depends_on,
        ...service
      } = rendered.services[name] as ComposeService;
      const after = Object.entries(depends_on ?? {}).filter(([other]) => kept.includes(other));
      const app =
        name === "app"
          ? {
              image: o.image,
              ...(o.image.startsWith("opscrew-local/") ? { pull_policy: "never" } : {}),
              env_file: o.previewValues ? [DRILL_VALUES_FILE, "app.env"] : ["app.env"],
              // The drill counts the restored tables: Railpack's start would migrate them first.
              environment: { ...(service.environment as object), ...noStartMigrations(plan) },
            }
          : {};
      // Quoted: a YAML 1.1 reader takes a plain `no` for false.
      const restart = new Scalar("no");
      restart.type = Scalar.QUOTE_DOUBLE;
      return [
        name,
        {
          ...service,
          ...app,
          restart,
          networks: ["internal"],
          ...(after.length > 0 ? { depends_on: Object.fromEntries(after) } : {}),
        },
      ];
    }),
  );
  const document = {
    name: drillProject(plan, snapshot.id).name,
    services,
    networks: { internal: { internal: true } },
    ...(rendered.volumes === undefined ? {} : { volumes: rendered.volumes }),
  };
  const header = [
    `# Generated by OpsCrew from ${planFilePath(plan)} for a restore drill of the snapshot ${snapshot.id}:`,
    "# a copy of the app and its data with no internet, no published port and no site, and none of",
    "# the app's .env values. opscrew restore --drill starts it and removes it.",
  ].join("\n");
  const envFiles = drill.services.map((service) => {
    const content = o.env.services[service.name];
    if (content === undefined) {
      throw wrongTarget(`The drill's env files have none for the service ${service.name}.`);
    }
    return { path: `${service.name}.env`, content };
  });
  const runtime = `${runtimeDir(drill)}/`;
  return [
    { path: "compose.yaml", content: `${header}\n${stringify(document, { lineWidth: 0 })}` },
    { path: "app.env", content: o.env.app },
    ...envFiles,
    ...renderServices(drill, { kind: "server" }).files.map((file) => ({
      path: file.path.slice(runtime.length),
      content: file.content,
    })),
  ].map((file) => ({ path: `${dir}/${file.path}`, content: file.content, kind: "runtime" }));
}

export * from "./portainer";
export * from "./record";
export {
  DRILL_RECIPE_DIGEST,
  DRILL_RECIPE_DIR,
  DRILL_RECIPE_SCHEDULE,
  DRILL_SLOT_AFTER_HOURS,
  drillRecipe,
  drillScheduleHours,
  drillSlotText,
  scheduledDrillParts,
} from "./script";
