import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
  buildStatusLines,
  type ComponentStatusOptions,
  cloudflareMoveStatus,
  componentStatusReport,
  moveInProgress,
  type PhaseDeps,
  phaseStatusLines,
  placeWords,
  sideWords,
  supplyChainLines,
  type TlsStatusOptions,
  tlsStatusReport,
} from "@opscrew/agents";
import { exists, toPosixRelative, upperFirst } from "@opscrew/core";
import {
  type DeployPlan,
  type DeployTarget,
  hasRemoteAppCopies,
  isCloudProvider,
  isServerlessProvider,
  type Retarget,
  readArtifact,
  webServers,
  workerServers,
} from "@opscrew/plan-schema";
import type { ResolvedMcpDeps } from "../deps";
import { refuseUnconfirmedOwnServer } from "./elicitation";
import {
  andApp,
  appInput,
  environmentInput,
  projectDirInput,
  runTool,
  toolEnvironment,
  withHint,
} from "./shared";

/**
 * The next planning step for the plugin flow, given which artefacts exist; `call` is how the
 * tools are called (`andApp`), `planFile` the app's plan and `flag` the app's and environment's
 * flags for the terminal command (`ToolEnvironment.flag`).
 */
function nextStep(
  have: Record<string, boolean>,
  input: { appKey: string | undefined; planFile: string; flag: string },
): string {
  const app = andApp(input.appKey, "with");
  if (!have.scanReport) return "Call opscrew_scan to check the repository for security problems.";
  if (!have.requirements) {
    return `Call opscrew_detect, then opscrew_interview_questions and opscrew_save_requirements${app}.`;
  }
  if (!have.plan) return `Call opscrew_design_options and then opscrew_select_design${app}.`;
  return `Apply the pending code changes from ${input.planFile} (opscrew-adapt skill), then provision with \`npx opscrew provision${input.flag}\` in a terminal.`;
}

/**
 * Which servers a move keeps billed. Only servers OpsCrew created at a cloud provider are: never
 * the user's own server or Portainer. A new cloud server is billed once it exists (from `created`)
 * until an abort deleted it (`new-removed` and later); an old one until `--finish` deletes it.
 */
function billing(move: Retarget, to: DeployTarget): string {
  const removed = move.abort !== undefined && move.abort.step !== "started";
  const notYet = move.step === "started" || move.step === "renamed";
  if (!isCloudProvider(to.provider)) {
    return isCloudProvider(move.from.target.provider)
      ? `The move adds no server cost: only ${sideWords(move.from.target, "old")} is billed, as before.`
      : "The move adds no server cost.";
  }
  if (!isCloudProvider(move.from.target.provider)) {
    if (removed) return "The new server was deleted by the abort; the move costs nothing any more.";
    if (notYet) return "The new server is not created yet; the move costs nothing yet.";
    return `${upperFirst(sideWords(to, "new"))} is billed from now on; ${sideWords(move.from.target, "old")} costs nothing extra.`;
  }
  if (removed) {
    return "The new server was deleted by the abort; only the previous server is billed.";
  }
  if (notYet) {
    return "The new server is not created yet; only the current server is billed.";
  }
  if (move.abort !== undefined) {
    return "Both servers are billed until the abort deletes the new one.";
  }
  return move.step === "switched"
    ? "Both servers are billed until `opscrew retarget --finish` deletes the old one."
    : "Both servers are billed until the move is finished or aborted.";
}

/** What the next step adds while a move runs. */
const TERMINAL_ONLY =
  "Moves are terminal-only: ask the user to run these commands with npx in a terminal in the project directory.";

/** Test-only collaborators for `opscrew_status` (production connects over SSH). */
export interface StatusToolOptions {
  /** The deploy user's shell on a server OpsCrew created, and own-server fakes. */
  services?: ComponentStatusOptions["services"];
  /** Reads the certificate a DNS-only hostname presents (production: `node:tls`). */
  tlsConnect?: TlsStatusOptions["tlsConnect"];
  /** The private network's WireGuard read (production: over SSH, as root through the login). */
  network?: ComponentStatusOptions["network"];
}

/** Multi-server scaling summary for `opscrew_status` when remote web or worker copies exist (033). */
function scalingOf(plan: DeployPlan):
  | {
      lines: string[];
      data: {
        webServers: string[];
        loadBalancer: { kind: "edge"; policy: string };
        workerCopies: Record<string, string[]>;
      };
    }
  | undefined {
  if (!hasRemoteAppCopies(plan)) return undefined;
  const webs = webServers(plan);
  const policy = plan.scaling?.loadBalancer?.policy ?? "round_robin";
  const workers = plan.processes.workers.filter(
    (worker) => worker.enabled && (worker.servers?.length ?? 0) > 0,
  );
  const workerCopies = Object.fromEntries(
    workers.map((worker) => [worker.name, workerServers(worker)]),
  );
  const lines = [
    webs.length > 1
      ? `Scaling: ${webs.length} web servers (${webs.join(", ")}; edge load balancer: ${policy}).`
      : `Scaling: 1 web server (${webs.join(", ")}).`,
    ...(workers.length === 0
      ? []
      : [
          `Worker copies: ${workers.map((worker) => `${worker.name} on ${workerServers(worker).join(", ")}`).join("; ")}.`,
        ]),
  ];
  return {
    lines,
    data: {
      webServers: webs,
      loadBalancer: { kind: "edge", policy },
      workerCopies,
    },
  };
}

/**
 * The server's proxy, each certificate OpsCrew manages with its expiry, and the recovery copy's
 * last update, key count and whether it is behind (FR-1462).
 */
function tlsOf(phase: PhaseDeps, plan: DeployPlan, options: StatusToolOptions) {
  return tlsStatusReport(phase, plan, {
    ...(options.tlsConnect === undefined ? {} : { tlsConnect: options.tlsConnect }),
    ...(options.services === undefined ? {} : { services: options.services }),
  });
}

/**
 * The plan's components, and once the app was deployed whether each runs, read over SSH on a
 * server or through Portainer's API (FR-1331). A server the user owns is read only with its
 * pinned host key; when the deployment cannot be read, a note says why.
 */
function componentsOf(phase: PhaseDeps, plan: DeployPlan, options: StatusToolOptions) {
  return componentStatusReport(phase, plan, {
    ...(options.services === undefined ? {} : { services: options.services }),
    ...(options.network === undefined ? {} : { network: options.network }),
    check: () =>
      refuseUnconfirmedOwnServer(
        plan,
        phase.paths,
        "status",
        "OpsCrew did not check whether the components run.",
      ),
  });
}

/**
 * `opscrew_status`: which phases have run (from `.opscrew/state.json`), which artefacts exist, the
 * plan's image builder and deploy strategy, its supply-chain settings (signing, deploy tags,
 * image retention), the app's components and whether each runs, the resource figures and the
 * scheduled check's state and alerts (`resources` and `check` in the data), the version
 * running, the one before and the deploy pause (`deploys`, FR-1913), the last snapshot (`snapshot`,
 * 024), the proxy,
 * certificates and recovery copy (`tlsStatusReport`), and the next step. Writes nothing.
 * `options` is for tests only.
 */
export function registerStatusTool(
  server: McpServer,
  deps: ResolvedMcpDeps,
  options: StatusToolOptions = {},
): void {
  server.registerTool(
    "opscrew_status",
    {
      title: "OpsCrew status",
      description:
        "Show where the project stands (phases, files, settings, component states and figures, versions, snapshots, alerts, certificates, network, moves) and the next step. Read-only. Rollbacks, VPN devices and moves stay in the user's terminal: `npx opscrew rollback`, `npx opscrew vpn add|grant`, `npx opscrew retarget`.",
      inputSchema: { ...projectDirInput, ...appInput, ...environmentInput },
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    ({ projectDir, app, environment }) =>
      runTool(deps, "opscrew_status", projectDir, async (call) => {
        const { appKey, name, flag } = await toolEnvironment(call.projectDir, app, environment);
        const phase = await call.phaseDeps({ app: appKey, environment: name });
        const { paths, state } = phase;
        const current = await state
          .read()
          .catch((error: unknown) =>
            withHint(
              error,
              `Delete ${toPosixRelative(paths.root, paths.files.state)} to reset the phase history; it is rebuilt on the next run.`,
            ),
          );
        const files = {
          scanReport: paths.files.scanReportMd,
          architecture: paths.files.architecture,
          requirements: paths.files.requirements,
          plan: paths.files.plan,
        };
        const artifacts: Record<string, { path: string; exists: boolean }> = {};
        const have: Record<string, boolean> = {};
        for (const [name, file] of Object.entries(files)) {
          const present = await exists(file);
          have[name] = present;
          artifacts[name] = { path: toPosixRelative(paths.root, file), exists: present };
        }
        const phases = current.phases;
        const lines = phaseStatusLines(phases);
        // A move in progress (`opscrew retarget`, between any two server targets): where it stands and the
        // terminal command to continue it. An unreadable plan is not this tool's concern.
        const plan = have.plan
          ? await readArtifact("plan", paths.files.plan).catch(() => undefined)
          : undefined;
        const move = plan === undefined ? undefined : moveInProgress(plan);
        const moveData =
          plan?.retarget === undefined
            ? undefined
            : {
                from: plan.retarget.from.target.provider,
                to: plan.target.provider,
                step: plan.retarget.step,
                abortStep: plan.retarget.abort?.step,
                startedAt: plan.retarget.startedAt,
              };
        const moveLines =
          plan?.retarget === undefined || moveData === undefined
            ? []
            : [
                "",
                `Move: from ${placeWords(plan.retarget.from.target)} to ${placeWords(plan.target)}, last completed step: ${moveData.step}${plan.retarget.abort === undefined ? "" : ` (being aborted, last abort step: ${plan.retarget.abort.step})`}.`,
                billing(plan.retarget, plan.target),
              ];
        // A move to another Cloudflare account: each environment's step, B's prepared apps.
        const cloudflareMove = await cloudflareMoveStatus(phase);
        const step =
          move !== undefined
            ? `${move.message} ${move.hint} ${TERMINAL_ONLY}`
            : cloudflareMove !== undefined
              ? `A move of ${cloudflareMove.zone} to another Cloudflare account is in progress: ${cloudflareMove.next}. ${TERMINAL_ONLY}`
              : nextStep(have, {
                  appKey,
                  planFile: toPosixRelative(paths.root, paths.files.plan),
                  flag,
                });
        const components =
          plan === undefined ? undefined : await componentsOf(phase, plan, options);
        const tls = plan === undefined ? undefined : await tlsOf(phase, plan, options);
        const scaling = plan === undefined ? undefined : scalingOf(plan);
        const text = [
          `OpsCrew phases in ${paths.root}:`,
          ...lines,
          "",
          "Files:",
          ...Object.values(artifacts).map(
            (a) => `  ${a.path}: ${a.exists ? "present" : "missing"}`,
          ),
          // A site on Cloudflare's hosting or GitHub Pages has no image: its version instead.
          ...(plan === undefined || isServerlessProvider(plan.target.provider)
            ? []
            : [
                "",
                ...buildStatusLines(plan),
                ...supplyChainLines(plan),
                ...(scaling?.lines ?? []),
              ]),
          ...(components === undefined ? [] : ["", ...components.lines]),
          ...(tls === undefined ? [] : ["", ...tls.lines]),
          ...moveLines,
          ...(cloudflareMove === undefined ? [] : ["", ...cloudflareMove.lines]),
          "",
          `Next: ${step}`,
        ].join("\n");
        return {
          text,
          data: {
            projectDir: paths.root,
            phases,
            artifacts,
            nextStep: step,
            move: moveData,
            ...(cloudflareMove === undefined ? {} : { cloudflareMove }),
            ...(scaling === undefined ? {} : { scaling: scaling.data }),
            ...(components?.status === undefined ? {} : { components: components.status }),
            ...(components?.resources === undefined ? {} : { resources: components.resources }),
            ...(components?.check === undefined ? {} : { check: components.check }),
            // The version running, the one before and the pause (US6 #1).
            ...(components?.deploys === undefined ? {} : { deploys: components.deploys }),
            // The last snapshot and the scheduled ones that failed (024 US8).
            ...(components?.snapshot === undefined ? {} : { snapshot: components.snapshot }),
            // With a private network: each server, each link, the devices (names and addresses
            // only, never a key) and the grants.
            ...(components?.servers === undefined ? {} : { servers: components.servers }),
            ...(components?.links === undefined ? {} : { links: components.links }),
            ...(components?.devices === undefined ? {} : { devices: components.devices }),
            ...(components?.grants === undefined ? {} : { grants: components.grants }),
            ...(tls === undefined ? {} : { tls: tls.lines }),
          },
        };
      }),
  );
}
