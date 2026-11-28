import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
  ADDON_NAMES,
  type AddonResult,
  type AddonServices,
  type AddonStatus,
  addonDisable,
  addonEnable,
  addonStatus,
  describeAddonStatus,
  describeGiteaStatus,
  describeMonitoringStatus,
  type PhaseDeps,
} from "@opscrew/agents";
import { exists, OpsCrewError } from "@opscrew/core";
import { type DeployPlan, readArtifact } from "@opscrew/plan-schema";
import { z } from "zod";
import { CollectingReporter, type ResolvedMcpDeps } from "../deps";
import { type CallExtra, dialogHandler, REQUIRES_USER, requireDialogs } from "./elicitation";
import {
  appInput,
  appliedCloudflarePlan,
  environmentInput,
  IDEMPOTENT_WRITE,
  projectDirInput,
  requireServerTarget,
  runTool,
  skipOtherAppsCheckInput,
  type ToolCall,
  toolEnvironment,
} from "./shared";

/** Test-only collaborators for the add-on tools (production uses the real ones). */
export interface AddonToolOptions {
  services?: AddonServices;
}

type AddonKind = keyof typeof ADDON_NAMES | "monitoring" | "gitea";

const KINDS: [AddonKind, ...AddonKind[]] = [
  "monitoring",
  "gitea",
  ...(Object.keys(ADDON_NAMES) as AddonKind[]),
];

const kindInput = {
  addon: z.enum(KINDS).describe("The add-on."),
};

/** What the model is told about the add-ons' secrets, in every result that names them. */
const SECRETS_NOTE =
  "Never read Beszel's secrets file or the Grafana Cloud token into this chat; to open Beszel's dashboard, the user runs `npx opscrew addon open beszel` in a terminal.";

/** What the model is told about Grafana's password, in every result that shows monitoring. */
const MONITORING_NOTE =
  "Never read OpsCrew's generated values file (it holds Grafana's password) into this chat; to open Grafana, the user runs `npx opscrew addon open monitoring` in a terminal.";

/** The app's plan and the phase deps of a call, for the app and environment it names. */
async function planOf(
  call: ToolCall,
  app: string | undefined,
  environment: string | undefined,
  extras: Parameters<ToolCall["phaseDeps"]>[0] = {},
): Promise<{ phase: PhaseDeps; plan: DeployPlan; terminal: string }> {
  const { appKey, name, flag } = await toolEnvironment(call.projectDir, app, environment);
  const phase = await call.phaseDeps({ ...extras, app: appKey, environment: name });
  const plan = await readArtifact("plan", phase.paths.files.plan);
  requireServerTarget(
    plan,
    "An add-on (Beszel, Grafana Cloud or self-hosted monitoring)",
    "The user's panel shows the account's traffic and errors (cPanel's Metrics), and opscrew_status shows the release the account runs, the agent's last attempt and the certificate.",
  );
  return { phase, plan, terminal: flag };
}

/** Each add-on's state in words, then the notes on their secrets; never a secret. */
function statusText(status: AddonStatus, app: string, now: Date): string {
  return [
    ...status.addons.map((state) => describeAddonStatus(state, app)),
    ...(status.monitoring === undefined ? [] : [describeMonitoringStatus(status.monitoring, now)]),
    ...(status.gitea === undefined ? [] : [describeGiteaStatus(status.gitea)]),
    [SECRETS_NOTE, ...(status.monitoring === undefined ? [] : [MONITORING_NOTE])].join(" "),
  ].join("\n\n");
}

/**
 * Stops before anything changes when the add-on needs a token the user gives and neither the MCP
 * server's environment nor this computer has it: the token never passes through the chat.
 */
async function requireToken(
  phase: PhaseDeps,
  kind: keyof typeof ADDON_NAMES,
  mode: "hub" | "agent" | undefined,
  terminal: string,
): Promise<void> {
  const needed =
    kind === "grafana-cloud"
      ? { variable: "OPSCREW_GRAFANA_CLOUD_TOKEN", kept: phase.paths.files.grafanaCloudToken }
      : mode === "agent"
        ? { variable: "OPSCREW_BESZEL_TOKEN", kept: phase.paths.files.beszelSecrets }
        : undefined;
  if (needed === undefined) return;
  if ((phase.env[needed.variable] ?? "").trim() !== "" || (await exists(needed.kept))) return;
  throw new OpsCrewError(
    "INVALID_INPUT",
    `${ADDON_NAMES[kind]} needs ${kind === "grafana-cloud" ? "the Grafana Cloud access policy token" : "the token your Beszel hub shows for this server"}, which OpsCrew never takes through this chat, and ${needed.variable} is not set for this MCP server. Nothing was changed.`,
    {
      hint: `Ask the user to set ${needed.variable} in the MCP server's environment and restart it, then call this tool again; or to run \`npx opscrew addon enable ${kind}${terminal}\` in a terminal, which asks for the token with hidden input.`,
    },
  );
}

/** What a change did, in plain text: the hashes approved and the add-on's state now. */
function changeText(result: AddonResult, plan: DeployPlan, now: Date): string {
  return [
    ...(result.cloudflarePlanHash !== undefined
      ? [appliedCloudflarePlan(result.cloudflarePlanHash)]
      : []),
    ...(result.applied ? [`Applied the infrastructure plan ${result.planHash}.`] : []),
    ...(result.hostApplied
      ? [`Changed the server with the host plans ${result.hostPlanHashes.join(", ")}.`]
      : ["The server needed no change."]),
    result.files.length > 0
      ? `Wrote ${result.files.join(", ")}; ask the user to commit them with opscrew/plan.yaml.`
      : "Ask the user to commit opscrew/plan.yaml.",
    "",
    statusText(result.status, plan.app.name, now),
  ].join("\n");
}

/**
 * What turning monitoring on or off did, in plain text: its summary (what it adds, costs and keeps,
 * or what provision removes), that only the plan changed, and the `provision` the user runs.
 */
function monitoringChangeText(
  call: ToolCall,
  result: AddonResult,
  plan: DeployPlan,
  sub: "enable" | "disable",
  terminal: string,
  now: Date,
): string {
  const summary = call.reporter.messages
    .filter((message) => message.level === "info")
    .map((message) => message.message);
  return [
    ...summary,
    "",
    `Nothing changed on any server, account or repository yet. Ask the user to run \`npx opscrew provision${terminal}\` in a terminal to ${sub === "enable" ? "set it up" : "remove what monitoring installed"}: it shows each change for their approval by its hash. Then they commit opscrew/plan.yaml.`,
    "",
    statusText(result.status, plan.app.name, now),
  ].join("\n");
}

/** The structured data of a change: its hashes, what it applied and the decisions. */
function changeData(result: AddonResult, approvals: unknown): Record<string, unknown> {
  return {
    cloudflarePlanHash: result.cloudflarePlanHash,
    planHash: result.planHash,
    hostPlanHashes: result.hostPlanHashes,
    applied: result.applied,
    hostApplied: result.hostApplied,
    files: result.files,
    approvals,
    status: result.status,
  };
}

/**
 * The add-on tools (FR-1711–FR-1713, FR-2027): `opscrew_addon_status` (read-only: whether Beszel,
 * Grafana Cloud and self-hosted monitoring are on, their containers' state and memory, how to open
 * them, and monitoring's last data, disk and retention; never a secret or a public address), and
 * `opscrew_addon_enable` / `opscrew_addon_disable`, whose every plan the user approves in a dialog
 * (the model never approves). Monitoring's enable and disable only write the plan, as the CLI's:
 * the user runs `npx opscrew provision` in a terminal to apply it. Tokens come only from the MCP
 * server's environment (`OPSCREW_BESZEL_TOKEN`, `OPSCREW_GRAFANA_CLOUD_TOKEN`) or this computer,
 * never from a tool input. Turning Beszel's hub off always keeps its history: deleting it needs the
 * app's name typed in a terminal. Opening Beszel's dashboard or Grafana is terminal-only.
 * `options` is for tests only.
 */
export function registerAddonTools(
  server: McpServer,
  deps: ResolvedMcpDeps,
  options: AddonToolOptions = {},
): void {
  const services = options.services === undefined ? {} : { services: options.services };

  server.registerTool(
    "opscrew_addon_status",
    {
      title: "Add-on status",
      description:
        "Show which add-ons (Beszel, Grafana Cloud, self-hosted monitoring) are on, with versions, containers' state and memory, monitoring's freshness, disk and retention, and how to open them. Read-only; never a password or token.",
      inputSchema: { ...projectDirInput, ...appInput, ...environmentInput },
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    ({ projectDir, app, environment }) =>
      runTool(deps, "opscrew_addon_status", projectDir, async (call) => {
        const { phase, plan } = await planOf(call, app, environment);
        const status = await addonStatus(
          { ...phase, reporter: new CollectingReporter(deps.redactor.redact) },
          plan,
          services,
        );
        return {
          text: statusText(status, plan.app.name, phase.clock.now()),
          data: { ...status },
        };
      }),
  );

  server.registerTool(
    "opscrew_addon_enable",
    {
      title: "Turn an add-on on",
      description:
        "Add Beszel, Grafana Cloud's collector or self-hosted monitoring to the app's servers. Tokens come only from the server's environment (OPSCREW_BESZEL_TOKEN, OPSCREW_GRAFANA_CLOUD_TOKEN). The USER approves each plan in a dialog; monitoring only writes the plan, for `npx opscrew provision` in a terminal.",
      inputSchema: {
        ...projectDirInput,
        ...appInput,
        ...environmentInput,
        ...kindInput,
        mode: z.enum(["hub", "agent"]).optional().describe("Beszel: hub (default) or agent."),
        access: z
          .enum(["local", "subdomain"])
          .optional()
          .describe("Beszel: local (SSH tunnel, default) or subdomain."),
        hostname: z
          .string()
          .optional()
          .describe("With subdomain: the dashboard's hostname or label."),
        allowEmails: z
          .array(z.string())
          .optional()
          .describe("With subdomain: the emails Access lets in."),
        hubUrl: z.string().optional().describe("Beszel agent: the user's hub address."),
        hubKey: z.string().optional().describe("Beszel agent: the hub's public key."),
        metricsUrl: z.string().optional().describe("Grafana Cloud: Prometheus remote_write URL."),
        metricsUser: z.string().optional().describe("Grafana Cloud: Prometheus user id."),
        logsUrl: z.string().optional().describe("Grafana Cloud: Loki push URL."),
        logsUser: z.string().optional().describe("Grafana Cloud: Loki user id."),
        logSampling: z
          .number()
          .int()
          .optional()
          .describe("Grafana Cloud: percent of log lines sent (default 100)."),
        on: z
          .enum(["app", "server"])
          .optional()
          .describe("Monitoring: server (default, its own) or app (needs 4 GB)."),
        newServer: z
          .boolean()
          .optional()
          .describe("Monitoring: a server for this environment alone."),
        metricsDays: z
          .number()
          .int()
          .optional()
          .describe("Monitoring: days figures are kept (default 15)."),
        logsDays: z
          .number()
          .int()
          .optional()
          .describe("Monitoring: days logs are kept (default 7)."),
        adminEmail: z.string().optional().describe("Gitea: initial admin email."),
        database: z.enum(["sqlite", "postgres"]).optional().describe("Gitea: sqlite or postgres."),
        webhookPath: z.string().optional().describe("Gitea: app webhook path."),
        ...skipOtherAppsCheckInput,
      },
      annotations: IDEMPOTENT_WRITE,
      _meta: REQUIRES_USER,
    },
    ({ projectDir, app, environment, addon, ...request }, extra: CallExtra) =>
      runTool(deps, "opscrew_addon_enable", projectDir, async (call) => {
        const given = Object.fromEntries(
          Object.entries(request).filter(([, value]) => value !== undefined),
        );
        if (addon === "monitoring") {
          // Only the plan is written, as the CLI's: there is nothing to approve here.
          const { phase, plan, terminal } = await planOf(call, app, environment);
          const result = await addonEnable(phase, plan, addon, { ...given, ...services });
          return {
            text: monitoringChangeText(call, result, plan, "enable", terminal, phase.clock.now()),
            data: changeData(result, []),
          };
        }
        requireDialogs(server, `npx opscrew addon enable ${addon}`);
        const handler = dialogHandler(server, deps, extra);
        const { phase, plan, terminal } = await planOf(call, app, environment, {
          approvalHandler: handler,
        });
        if (addon !== "gitea") {
          await requireToken(phase, addon, request.mode, terminal);
        }
        const result = await addonEnable(phase, plan, addon, { ...given, ...services });
        return {
          text: changeText(result, plan, phase.clock.now()),
          data: changeData(result, handler.decisions),
        };
      }),
  );

  server.registerTool(
    "opscrew_addon_disable",
    {
      title: "Turn an add-on off",
      description:
        "Remove an add-on from the app's server after the USER approves each plan in a dialog. Deleting Beszel's history is terminal-only (`npx opscrew addon disable beszel`); monitoring leaves the plan, for `npx opscrew provision`.",
      inputSchema: { ...projectDirInput, ...appInput, ...environmentInput, ...kindInput },
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: true,
        openWorldHint: true,
      },
      _meta: REQUIRES_USER,
    },
    ({ projectDir, app, environment, addon }, extra: CallExtra) =>
      runTool(deps, "opscrew_addon_disable", projectDir, async (call) => {
        if (addon === "monitoring") {
          const { phase, plan, terminal } = await planOf(call, app, environment);
          const result = await addonDisable(phase, plan, addon, services);
          return {
            text: monitoringChangeText(call, result, plan, "disable", terminal, phase.clock.now()),
            data: changeData(result, []),
          };
        }
        requireDialogs(server, `npx opscrew addon disable ${addon}`);
        const handler = dialogHandler(server, deps, extra);
        const { phase, plan, terminal } = await planOf(call, app, environment, {
          approvalHandler: handler,
        });
        // Beszel's hub and self-hosted Gitea keep their data here; deleting data is terminal-only.
        const keepData =
          addon === "gitea" || (addon === "beszel" && plan.observability?.beszel?.mode !== "agent");
        const result = await addonDisable(phase, plan, addon, {
          ...(keepData ? { keepData: true } : {}),
          ...services,
        });
        const kept = keepData
          ? [
              "",
              addon === "gitea"
                ? `Self-hosted Gitea data volumes stay on the server. Deleting them needs the app's name typed by the user: ask them to run \`npx opscrew addon disable gitea --delete-data${terminal}\` in a terminal.`
                : `Beszel's history stays on the server. Deleting it needs the app's name typed by the user: ask them to run \`npx opscrew addon disable beszel${terminal}\` in a terminal.`,
            ]
          : [];
        return {
          text: [changeText(result, plan, phase.clock.now()), ...kept].join("\n"),
          data: { ...changeData(result, handler.decisions), keptHistory: keepData },
        };
      }),
  );
}
