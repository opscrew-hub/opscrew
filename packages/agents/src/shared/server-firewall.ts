/**
 * In-place updates of a server's own firewall (`firewallCheck: "server"`, issue #62; Kamatera):
 * - Reads `/etc/opscrew/firewall-networks.json` over SSH (as root/docker) for existing servers
 *   before `evaluatePlanPolicies`, falling back to the first-boot script in Terraform state ONLY
 *   when SSH succeeds and confirms `/etc/opscrew/firewall-networks.json` is absent. On SSH failure,
 *   missing address/key, insufficient privilege, or damaged JSON, fails closed instead of trusting
 *   the first-boot script (which may be stale after an earlier in-place update).
 * - When the planned networks differ from the server's current networks, builds a SHA-256
 *   hash-approved `connector-ssh-host` host plan (`planServerFirewall`) that rewrites
 *   `/etc/opscrew/firewall.nft`, reloads `opscrew-firewall.service`, and atomically writes
 *   `/etc/opscrew/firewall-networks.json` (0600, root-owned) under the dead-man rollback.
 */
import {
  applyHostPlan,
  type HostFacts,
  type HostPrivilege,
  inspectHost,
  planServerFirewall,
  probePrivilege,
  readServerFirewallNetworks,
  SERVER_FIREWALL_NETWORKS_FILE,
  type ServerFirewallNetworksRecord,
} from "@opscrew/connector-ssh-host";
import type { PhaseName, RemoteExec } from "@opscrew/contracts";
import { errorText, exists, OpsCrewError } from "@opscrew/core";
import { IMAGES } from "@opscrew/iac-templates";
import { APP_SERVER, type DeployPlan } from "@opscrew/plan-schema";
import {
  existingOwnFirewallServers,
  type ServerFirewallNetworks,
  serverFirewallUpdates,
} from "@opscrew/secops";
import type { PhaseDeps } from "../context";
import { approveAndApplyHostPlan, type HostAdapterApi, type HostPlanOutcome } from "./host-plan";
import { SshRemoteExec } from "./remote";
import { serverRemote } from "./server-address";
import { readServerAddresses } from "./server-record";

/** Host adapter operations needed for in-place server firewall updates (fakes in tests). */
export interface ServerFirewallHostApi {
  inspect(remote: RemoteExec, options: { rootImage?: string }): Promise<HostFacts>;
  apply: HostAdapterApi["apply"];
  readNetworks?: (
    remote: RemoteExec,
    privilege: HostPrivilege,
    rootImage?: string,
  ) => Promise<ServerFirewallNetworksRecord | undefined>;
}

/** Collaborators for reading and updating a server's own firewall in place during `planAndApply`. */
export interface ServerFirewallRun {
  /** Plan used to reach the servers (e.g. `beforeApply(plan)`). */
  plan: DeployPlan;
  /**
   * Optional SSH shell override by host address and OpsCrew server name (`app`, `<extra>`,
   * `previous`). Returning `undefined` falls back to the real SSH shell for that server.
   */
  remote?: ((host: string, server: string) => RemoteExec | undefined) | undefined;
  /** Optional host adapter override (tests). */
  host?: ServerFirewallHostApi | undefined;
  /** Optional host IP of `module.server_previous` during `opscrew retarget`. */
  previousHost?: string | undefined;
  /** Optional fresh-login check override after updating the firewall (tests). */
  verifyLogin?: ((server: string) => Promise<boolean>) | undefined;
}

/** Result of probing existing `firewallCheck: "server"` servers before policy evaluation. */
export interface ExistingServerFirewallsRead {
  /** Applied networks from `/etc/opscrew/firewall-networks.json`, keyed by Terraform address. */
  networks: Record<string, ServerFirewallNetworks>;
  /** Raw parsed records from `/etc/opscrew/firewall-networks.json`, keyed by Terraform address. */
  records: Record<string, ServerFirewallNetworksRecord>;
  /** Terraform addresses of existing servers reachable with root/sudo/docker privilege. */
  reachable: Set<string>;
  /**
   * Read/connection failures per Terraform address: whenever an entry is present, SecOps fails
   * `server-firewall-as-planned` closed instead of falling back to the first-boot script.
   */
  errors: Record<string, string>;
}

interface ResolvedServer {
  remote: RemoteExec;
  privilege: HostPrivilege;
  verifyLogin: () => Promise<boolean>;
}

type ProbeOutcome = { ok: true; server: ResolvedServer } | { ok: false; reason: string };

function isRootPrivilege(privilege: HostFacts["privilege"]): privilege is HostPrivilege {
  return privilege === "root" || privilege === "sudo" || privilege === "docker";
}

function recordToSecops(record: ServerFirewallNetworksRecord): ServerFirewallNetworks {
  return {
    ssh: [...record.ssh],
    web: [...record.web],
    wireguard: record.wireguardPort === undefined ? "" : String(record.wireguardPort),
  };
}

/** Converts SecOps firewall networks into validated `ServerFirewallParams`; throws on bad port. */
export function secopsToServerFirewallParams(networks: ServerFirewallNetworks) {
  if (networks.wireguard === "") {
    return { ssh: [...networks.ssh], web: [...networks.web] };
  }
  if (!/^\d{1,5}$/.test(networks.wireguard)) {
    throw new OpsCrewError(
      "INVALID_INPUT",
      `The planned WireGuard port "${networks.wireguard}" is not a valid UDP port number.`,
      { hint: "Check `network.members[].port` in opscrew/plan.yaml, then try again." },
    );
  }
  const wireguardPort = Number(networks.wireguard);
  if (!Number.isInteger(wireguardPort) || wireguardPort < 1 || wireguardPort > 65535) {
    throw new OpsCrewError(
      "INVALID_INPUT",
      `The planned WireGuard port "${networks.wireguard}" must be between 1 and 65535.`,
      { hint: "Check `network.members[].port` in opscrew/plan.yaml, then try again." },
    );
  }
  return {
    ssh: [...networks.ssh],
    web: [...networks.web],
    wireguardPort,
  };
}

/** Resolves an SSH shell + fresh-login verifier for `server` (`app`, `<extra>`, or `previous`). */
async function resolveServerShell(
  deps: PhaseDeps,
  run: ServerFirewallRun,
  server: string,
): Promise<
  | { ok: true; remote: RemoteExec; verifyLogin: () => Promise<boolean> }
  | { ok: false; reason: string }
> {
  const addresses = await readServerAddresses(deps.paths);
  const customVerify = run.verifyLogin;
  const customRemote = run.remote;
  if (server === "previous") {
    // Never fall back to `addresses.deployment?.ipv4`: that is the current deployment's server,
    // not `module.server_previous`. Fail closed when no previous-server address is known.
    const host = run.previousHost ?? addresses.retarget?.from?.ipv4;
    if (host === undefined) {
      return {
        ok: false,
        reason: "the previous server's address is not recorded in .opscrew/server.json",
      };
    }
    const provided = customRemote?.(host, server);
    if (provided !== undefined) {
      return {
        ok: true,
        remote: provided,
        verifyLogin:
          customVerify !== undefined
            ? () => customVerify(server)
            : async () =>
                (
                  await (customRemote?.(host, server) ?? provided)
                    .run("true", { timeoutMs: 30_000 })
                    .catch(() => undefined)
                )?.exitCode === 0,
      };
    }
    if (!(await exists(deps.paths.files.deployKey))) {
      return { ok: false, reason: "the deploy SSH key is not present on this computer" };
    }
    const make = (fresh: boolean) =>
      new SshRemoteExec({
        host,
        user: "deploy",
        keyFile: deps.paths.files.deployKey,
        knownHostsFile: deps.paths.files.knownHosts,
        runner: deps.runner,
        ...(fresh ? { fresh: true } : {}),
      });
    return {
      ok: true,
      remote: make(false),
      verifyLogin:
        customVerify !== undefined
          ? () => customVerify(server)
          : async () =>
              (
                await make(true)
                  .run("true", { timeoutMs: 30_000 })
                  .catch(() => undefined)
              )?.exitCode === 0,
    };
  }

  const host =
    server === APP_SERVER ? addresses.deployment?.ipv4 : addresses.servers?.[server]?.ipv4;
  if (host === undefined) {
    return {
      ok: false,
      reason: `the address of server ${server} is not recorded in .opscrew/server.json`,
    };
  }
  const provided = customRemote?.(host, server);
  if (provided !== undefined) {
    return {
      ok: true,
      remote: provided,
      verifyLogin:
        customVerify !== undefined
          ? () => customVerify(server)
          : async () =>
              (
                await (customRemote?.(host, server) ?? provided)
                  .run("true", { timeoutMs: 30_000 })
                  .catch(() => undefined)
              )?.exitCode === 0,
    };
  }
  if (!(await exists(deps.paths.files.deployKey))) {
    return { ok: false, reason: "the deploy SSH key is not present on this computer" };
  }
  let remote: RemoteExec;
  try {
    remote = await serverRemote(deps, run.plan, server);
  } catch (error) {
    return { ok: false, reason: deps.redactor.redact(errorText(error)) };
  }
  return {
    ok: true,
    remote,
    verifyLogin:
      customVerify !== undefined
        ? () => customVerify(server)
        : async () =>
            (
              await serverRemote(deps, run.plan, server, { fresh: true })
                .then((fresh) => fresh.run("true", { timeoutMs: 30_000 }))
                .catch(() => undefined)
            )?.exitCode === 0,
  };
}

/** Connects to `server` and verifies it has root, sudo, or docker privilege. */
async function probeServer(
  deps: PhaseDeps,
  run: ServerFirewallRun,
  server: string,
): Promise<ProbeOutcome> {
  const shell = await resolveServerShell(deps, run, server);
  if (!shell.ok) return shell;
  let privilege: HostFacts["privilege"];
  try {
    privilege = await probePrivilege(shell.remote);
  } catch (error) {
    return { ok: false, reason: deps.redactor.redact(errorText(error)) };
  }
  if (!isRootPrivilege(privilege)) {
    return {
      ok: false,
      reason: `the SSH login on server ${server} does not have root, passwordless sudo, or Docker access`,
    };
  }
  return { ok: true, server: { remote: shell.remote, verifyLogin: shell.verifyLogin, privilege } };
}

/**
 * Reads `/etc/opscrew/firewall-networks.json` over SSH (read-only) for every existing server on a
 * `firewallCheck: "server"` provider in `planJson`.
 * - When SSH succeeds and the file exists and is valid, records it in `networks[address]` and marks
 *   `address` reachable.
 * - When SSH succeeds and confirms the file does not exist yet (`absent`), omits
 *   `networks[address]` (allowing SecOps to fall back to the first-boot script in Terraform state)
 *   and marks `address` reachable.
 * - When SSH fails, privilege probing fails, or reading/parsing `/etc/opscrew/firewall-networks.json`
 *   fails (including damaged JSON), records `errors[address]` and leaves `address` out of
 *   `reachable` so SecOps fails closed instead of trusting a potentially stale first-boot script.
 */
export async function readExistingServerFirewalls(
  deps: PhaseDeps,
  run: ServerFirewallRun,
  planJson: unknown,
  phase: PhaseName,
): Promise<ExistingServerFirewallsRead> {
  const networks: Record<string, ServerFirewallNetworks> = {};
  const records: Record<string, ServerFirewallNetworksRecord> = {};
  const reachable = new Set<string>();
  const errors: Record<string, string> = {};
  const servers = existingOwnFirewallServers(planJson);
  if (servers.length === 0) return { networks, records, reachable, errors };

  const readNetworks = run.host?.readNetworks ?? readServerFirewallNetworks;
  for (const item of servers) {
    const probed = await probeServer(deps, run, item.server);
    if (!probed.ok) {
      errors[item.address] = probed.reason;
      continue;
    }
    try {
      const record = await readNetworks(
        probed.server.remote,
        probed.server.privilege,
        IMAGES.caddy.ref,
      );
      reachable.add(item.address);
      if (record !== undefined) {
        records[item.address] = record;
        networks[item.address] = recordToSecops(record);
      }
      await deps.audit.append({
        kind: "remote-exec",
        actor: "opscrew",
        action: "read server firewall networks (read-only)",
        phase,
        target: `server ${item.server}`,
        decision: "allow",
        detail: record === undefined ? "absent (first-boot fallback)" : "present",
      });
    } catch (error) {
      errors[item.address] = deps.redactor.redact(errorText(error));
    }
  }
  return { networks, records, reachable, errors };
}

/**
 * Emits (and unless `planOnly`, approves by SHA-256 hash and applies under the dead-man rollback)
 * a `server-firewall` host plan for every existing `firewallCheck: "server"` server in `planJson`
 * whose current networks differ from the plan's networks.
 */
export async function applyServerFirewallUpdates(
  deps: PhaseDeps,
  input: {
    run: ServerFirewallRun;
    planJson: unknown;
    read?: ExistingServerFirewallsRead | undefined;
    planOnly: boolean;
    command: string;
    phase: PhaseName;
  },
): Promise<HostPlanOutcome[]> {
  const read =
    input.read ?? (await readExistingServerFirewalls(deps, input.run, input.planJson, input.phase));
  const readErrors = Object.entries(read.errors);
  if (readErrors.length > 0) {
    const [, reason] = readErrors[0] ?? ["", "unknown error"];
    throw new OpsCrewError(
      "PHASE_PRECONDITION",
      `OpsCrew could not read ${SERVER_FIREWALL_NETWORKS_FILE} on the server (${reason}), so it cannot safely update the server's firewall. Nothing on the server was changed.`,
      {
        hint: `Check that the server is reachable over SSH and ${SERVER_FIREWALL_NETWORKS_FILE} is valid, then run \`${input.command}\` again.`,
      },
    );
  }
  const updates = serverFirewallUpdates(input.planJson, {
    serverFirewallNetworks: read.networks,
  });
  if (updates.length === 0) return [];

  const host = input.run.host ?? { inspect: inspectHost, apply: applyHostPlan };
  const outcomes: HostPlanOutcome[] = [];
  for (const update of updates) {
    const probed = await probeServer(deps, input.run, update.server);
    if (!probed.ok) {
      throw new OpsCrewError(
        "PHASE_PRECONDITION",
        `OpsCrew could not reach server ${update.server} over SSH to update its own firewall (${update.differences.join("; ")}): ${probed.reason}. Nothing on the server was changed.`,
        {
          hint: `Check that server ${update.server} is reachable over SSH, then run \`${input.command}\` again.`,
        },
      );
    }
    const { remote, privilege, verifyLogin } = probed.server;
    const rootImage = privilege === "docker" ? IMAGES.caddy.ref : undefined;
    deps.reporter.step(`Inspecting server ${update.server} for its firewall update (read-only)`);
    const facts = await host.inspect(remote, rootImage === undefined ? {} : { rootImage });
    const hostPlan = planServerFirewall(
      facts,
      {
        app: input.run.plan.app.name,
        serverFirewall: secopsToServerFirewallParams(update.planned),
        current: read.records[update.address],
      },
      input.command,
    );
    const where = update.server === "previous" ? "the previous server" : `server ${update.server}`;
    const outcome = await approveAndApplyHostPlan(deps, {
      plan: hostPlan,
      remote,
      apply:
        rootImage === undefined
          ? (shell, applied, options) => host.apply(shell, applied, options)
          : (shell, applied, options) => host.apply(shell, applied, { ...options, rootImage }),
      verifyLogin,
      title: `Update the server's own firewall on ${where}`,
      intro: [
        `The plan's networks for ${where} differ from its current firewall (${update.differences.join("; ")}).`,
      ],
      server: where,
      planOf: where,
      upToDate: `The firewall on ${where} already has the plan's networks.`,
      command: input.command,
      phase: input.phase,
      ...(input.planOnly ? { planOnly: true } : {}),
      secrets: async () => ({}),
      applying: `Updating the server's own firewall on ${where} under the automatic undo`,
    });
    outcomes.push(outcome);
  }
  return outcomes;
}
