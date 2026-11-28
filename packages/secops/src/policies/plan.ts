import type {
  PlannedFirewallRule,
  PlannedResourceJson,
  PolicyResult,
  ProviderSecOps,
  Severity,
} from "@opscrew/contracts";
import { isRecord, listText } from "@opscrew/core";
import { edgeProvider } from "@opscrew/edge-providers";
import type { DeployPlan } from "@opscrew/plan-schema";
import { CLOUD_PROVIDERS } from "@opscrew/providers";
import { z } from "zod";

const OPEN_TO_ALL = new Set(["0.0.0.0/0", "::/0"]);
const PUBLIC_TCP_PORTS = new Set(["22", "80", "443"]);
const PUBLIC_UDP_PORTS = new Set(["443"]);

/**
 * True when the plan asks for the provider's automated backups of the server it creates; never
 * for a server the user owns (or a Portainer target, which has no server).
 */
function planWantsBackups(target: { provider: string; backups?: boolean }): boolean {
  return CLOUD_PROVIDERS.some((p) => p.id === target.provider) && target.backups === true;
}

/**
 * True when the plan asks for backups of the server at `address`: an extra server's module
 * (`module.server_<name>`) follows its own entry in `servers` (the monitoring server keeps none),
 * a move's old app server (`module.server_previous`) the old side's target as the move recorded
 * it, and the app's server the plan's target.
 */
function serverWantsBackups(deployPlan: DeployPlan, address: string): boolean {
  const name = /^module.server_([^.]+)./.exec(address)?.[1];
  // The new side's target says nothing of the old server (found live: a move from a server whose
  // backups the user had turned off was refused for them).
  if (name === "previous" && deployPlan.retarget !== undefined) {
    return planWantsBackups(deployPlan.retarget.from.target);
  }
  const extra = deployPlan.servers?.find((server) => server.name === name);
  return planWantsBackups(extra?.target ?? deployPlan.target);
}

/** Flattens `planned_values` (root and child modules) and merges `after_unknown` from changes. */
export function plannedResources(planJson: unknown): PlannedResourceJson[] {
  if (!isRecord(planJson)) return [];
  const unknownByAddress = new Map<string, Record<string, unknown>>();
  const changes = Array.isArray(planJson.resource_changes) ? planJson.resource_changes : [];
  for (const change of changes) {
    if (!isRecord(change) || typeof change.address !== "string" || !isRecord(change.change))
      continue;
    const afterUnknown = change.change.after_unknown;
    if (isRecord(afterUnknown)) unknownByAddress.set(change.address, afterUnknown);
  }
  const out: PlannedResourceJson[] = [];
  const walk = (module: unknown) => {
    if (!isRecord(module)) return;
    for (const resource of Array.isArray(module.resources) ? module.resources : []) {
      if (!isRecord(resource) || resource.mode === "data") continue;
      if (typeof resource.address !== "string" || typeof resource.type !== "string") continue;
      out.push({
        address: resource.address,
        type: resource.type,
        name: typeof resource.name === "string" ? resource.name : resource.address,
        values: isRecord(resource.values) ? resource.values : {},
        unknown: unknownByAddress.get(resource.address) ?? {},
      });
    }
    for (const child of Array.isArray(module.child_modules) ? module.child_modules : [])
      walk(child);
  };
  const planned = planJson.planned_values;
  if (isRecord(planned)) walk(planned.root_module);
  return out;
}

/** True when an attribute has a non-empty known value or will be set during apply. */
function isSet(resource: PlannedResourceJson, attribute: string): boolean {
  const value = resource.values[attribute];
  if (Array.isArray(value)) return value.length > 0 || resource.unknown[attribute] !== undefined;
  if (value !== undefined && value !== null && value !== "") return true;
  const unknown = resource.unknown[attribute];
  return unknown === true || (Array.isArray(unknown) && unknown.length > 0);
}

function result(
  policyId: string,
  title: string,
  severity: Severity,
  passed: boolean,
  message: string,
  resource?: string,
): PolicyResult {
  return { policyId, title, severity, passed, message, ...(resource ? { resource } : {}) };
}

/**
 * Ports open to the whole internet: ones that must never be public, web ports, SSH and the private
 * network's WireGuard ports (`wireguard`, the UDP ports the plan's network members listen on).
 */
function openPorts(
  rules: PlannedFirewallRule[],
  wireguard: ReadonlySet<string> = new Set(),
): { admin: string[]; web: string[]; ssh: boolean; wireguard: string[] } {
  const admin: string[] = [];
  const web: string[] = [];
  const network: string[] = [];
  let ssh = false;
  for (const rule of rules) {
    if ((rule.direction ?? "in") !== "in") continue;
    const open = (rule.source_ips ?? []).some((ip) => OPEN_TO_ALL.has(ip));
    if (!open) continue;
    const protocol = (rule.protocol ?? "").toLowerCase();
    const port = rule.port ?? "";
    if (protocol === "icmp") continue;
    const allowed =
      protocol === "tcp"
        ? PUBLIC_TCP_PORTS
        : protocol === "udp"
          ? PUBLIC_UDP_PORTS
          : new Set<string>();
    if (protocol === "udp" && wireguard.has(port)) network.push(port);
    else if (!allowed.has(port)) admin.push(`${protocol}/${port || "any"}`);
    else if (port === "80" || port === "443") web.push(`${protocol}/${port}`);
    else ssh = true;
  }
  return { admin, web, ssh, wireguard: network };
}

/** SSH (port 22) may be open to the whole internet only when the plan allows it. */
function sshPolicyResult(
  firewall: PlannedResourceJson,
  rules: PlannedFirewallRule[],
  deployPlan: DeployPlan,
): PolicyResult {
  const planned = deployPlan.security.sshAllowedCidrs.some((cidr) => OPEN_TO_ALL.has(cidr));
  const open = openPorts(rules).ssh;
  return result(
    "ssh-not-public",
    "SSH is open only as planned",
    "high",
    !open || planned,
    !open
      ? "SSH (port 22) accepts only the planned address ranges."
      : planned
        ? "SSH (port 22) is open to the internet as the plan allows; only key logins are accepted."
        : "SSH (port 22) is open to the whole internet, but the plan limits it to specific address ranges. Restrict the firewall rule to those ranges.",
    firewall.address,
  );
}

/** `no-open-admin-ports` and, behind Cloudflare, `origin-cloudflare-only` for one firewall. */
function openPortResults(
  firewall: PlannedResourceJson,
  rules: PlannedFirewallRule[],
  proxiedBehindCloudflare: boolean,
  deployPlan: DeployPlan,
): PolicyResult[] {
  const networkPorts = new Set((deployPlan.network?.members ?? []).map((m) => String(m.port)));
  const open = openPorts(rules, networkPorts);
  const { admin: openAdminPorts, web: openWebPorts } = open;
  const wireguard = [...new Set(open.wireguard)];
  const tunnel =
    wireguard.length === 0
      ? ""
      : `, and the private network's WireGuard ${wireguard.length === 1 ? "port" : "ports"} (UDP ${wireguard.join(", ")}),`;
  const out = [
    result(
      "no-open-admin-ports",
      "Only SSH and web ports are open to the internet",
      "critical",
      openAdminPorts.length === 0,
      openAdminPorts.length === 0
        ? `Only ports 22, 80 and 443${tunnel} accept traffic from anywhere.`
        : `These ports are open to the whole internet: ${openAdminPorts.join(", ")}. Databases, caches and admin panels must never be public; remove those rules.`,
      firewall.address,
    ),
  ];
  if (proxiedBehindCloudflare) {
    out.push(
      result(
        "origin-cloudflare-only",
        "Web ports accept only Cloudflare",
        "medium",
        openWebPorts.length === 0,
        openWebPorts.length === 0
          ? "Ports 80 and 443 accept only Cloudflare's IP ranges, so attackers cannot bypass the proxy."
          : `Ports ${openWebPorts.join(", ")} are open to everyone even though traffic should come through Cloudflare. Restrict them to Cloudflare's IP ranges.`,
        firewall.address,
      ),
    );
  }
  return out;
}

/** What differs between the providers whose servers the policies check. */
interface ProviderChecks extends ProviderSecOps {
  /** Resource type of the server, and of its cloud firewall (or `<type>.<name>`). */
  server: string;
  firewall: string;
  /** Whether the server has delete and rebuild protection to check. */
  deleteProtection: boolean;
}

/** The registry's providers, in its order: the order the results are reported in. */
const PROVIDERS: readonly ProviderChecks[] = CLOUD_PROVIDERS.map((provider) => ({
  ...provider.texts.secops,
  server: provider.terraform.serverResourceType,
  firewall: provider.terraform.firewallResourceType,
  deleteProtection: provider.offering.deleteProtection,
}));

/**
 * The server firewall's step in a server's first-boot script, as iac-templates renders
 * `server-firewall.sh.tftpl` (`firewallCheck` `server`): its first line, and the input chain's
 * default drop it writes.
 */
const SERVER_FIREWALL_MARKER = "# opscrew-server-firewall:";
const SERVER_FIREWALL_DROP = "type filter hook input priority filter; policy drop;";

/** A server's first-boot script with the server firewall's step (whichever attribute). */
function serverFirewallScript(values: Record<string, unknown>): string | undefined {
  return Object.values(values).find(
    (value): value is string => typeof value === "string" && value.includes(SERVER_FIREWALL_MARKER),
  );
}

/** The networks a server's own firewall lets in: SSH's, the web ports' and WireGuard's port. */
export interface ServerFirewallNetworks {
  ssh: string[];
  web: string[];
  /** The UDP port, or `""` for none. */
  wireguard: string;
}

/**
 * Extra context for {@link evaluatePlanPolicies} on providers whose firewall is the server's own
 * (`firewallCheck: "server"`, issue #62).
 */
export interface EvaluatePlanPoliciesOptions {
  /**
   * Applied networks read from `/etc/opscrew/firewall-networks.json` over SSH for existing servers,
   * keyed by Terraform resource address (e.g. `module.server.kamatera_server.this`). When present
   * for a server, `server-firewall-as-planned` compares the plan against this record instead of
   * the first-boot script in Terraform state (falling back to the first-boot script only when SSH
   * succeeded and confirmed no record exists yet for that server).
   */
  serverFirewallNetworks?: Readonly<Record<string, ServerFirewallNetworks | undefined>>;
  /**
   * Read failures from trying to inspect `/etc/opscrew/firewall-networks.json` over SSH, keyed by
   * Terraform resource address. Whenever an entry is present for a server,
   * `server-firewall-as-planned` fails closed (critical) instead of falling back to the first-boot
   * script in Terraform state, which may be stale after an earlier in-place firewall update.
   */
  serverFirewallReadErrors?: Readonly<Record<string, string | undefined>>;
  /**
   * Terraform resource addresses of existing servers that are reachable for an in-place
   * `server-firewall` host plan update: when networks differ on one of these addresses,
   * `server-firewall-as-planned` passes (noting the SHA-256 hash-approved host plan update) while
   * still enforcing port and SSH policies on the planned networks.
   */
  inPlaceServerFirewallAddresses?: ReadonlySet<string>;
}

/** One existing server on a `firewallCheck: "server"` provider found in a Terraform plan JSON. */
export interface ExistingOwnFirewallServer {
  address: string;
  moduleCall: string;
  /** OpsCrew server name: `app`, an extra server's name, or `previous` during a retarget. */
  server: string;
  planned: ServerFirewallNetworks | undefined;
}

/** One existing server on a `firewallCheck: "server"` provider whose own firewall needs updating. */
export interface PlannedServerFirewallUpdate {
  address: string;
  moduleCall: string;
  server: string;
  current: ServerFirewallNetworks;
  planned: ServerFirewallNetworks;
  differences: string[];
}

/** The words of `text` (a script's space-separated networks). */
const words = (text: string) => text.split(" ").filter((word) => word !== "");

/**
 * The networks of the step in a first-boot script: its `ssh_sources`, `web_sources` and
 * `wireguard_port` lines. Undefined when no script holds the step or its networks can't be read.
 */
function scriptNetworks(script: string | undefined): ServerFirewallNetworks | undefined {
  if (script === undefined || !script.includes(SERVER_FIREWALL_DROP)) return undefined;
  const value = (name: string) => new RegExp(`^${name}='([^']*)'$`, "m").exec(script)?.[1];
  const [ssh, web, wireguard] = ["ssh_sources", "web_sources", "wireguard_port"].map(value);
  if (ssh === undefined || web === undefined || wireguard === undefined) return undefined;
  return { ssh: words(ssh), web: words(web), wireguard };
}

/** Converts {@link ServerFirewallNetworks} into {@link PlannedFirewallRule}s for port/SSH checks. */
function serverFirewallRulesFromNetworks(networks: ServerFirewallNetworks): PlannedFirewallRule[] {
  const { ssh, web, wireguard } = networks;
  const rule = (protocol: string, port: string, sources: string[]) =>
    sources.length === 0 ? [] : [{ direction: "in", protocol, port, source_ips: sources }];
  return [
    ...rule("tcp", "22", ssh),
    ...rule("tcp", "80", web),
    ...rule("tcp", "443", web),
    ...rule("udp", "443", web),
    ...(wireguard === "" ? [] : rule("udp", wireguard, [...OPEN_TO_ALL])),
  ];
}

/**
 * The inbound rules of the server's own firewall, read from the step in the planned server's
 * first-boot script: SSH from `ssh_sources`, the web ports from `web_sources`, the WireGuard port
 * from everywhere. Undefined when no script holds the step or its networks can't be read.
 */
function serverFirewallRules(server: PlannedResourceJson): PlannedFirewallRule[] | undefined {
  const networks = scriptNetworks(serverFirewallScript(server.values));
  if (networks === undefined) return undefined;
  return serverFirewallRulesFromNetworks(networks);
}

/** The `change` of the resource at `address` in the plan's `resource_changes`. */
function resourceChange(planJson: unknown, address: string): Record<string, unknown> | undefined {
  if (!isRecord(planJson) || !Array.isArray(planJson.resource_changes)) return undefined;
  const entry = planJson.resource_changes.find((e) => isRecord(e) && e.address === address);
  return isRecord(entry) && isRecord(entry.change) ? entry.change : undefined;
}

/**
 * True when the plan keeps the server at `address` (`no-op` or `update`): its startup script is the
 * one it was created with, since the module ignores changes to it, so the plan's networks aren't
 * in it. False when the plan creates or replaces it, or says nothing of it.
 */
function serverExists(planJson: unknown, address: string): boolean {
  const actions = resourceChange(planJson, address)?.actions;
  return Array.isArray(actions) && actions.length > 0 && !actions.includes("create");
}

/**
 * True when the plan imports the server at `address` (its change's `importing`, a takeover): its
 * provider never gives back the script it was created with, so there is none to read.
 */
function serverImported(planJson: unknown, address: string): boolean {
  const importing = resourceChange(planJson, address)?.importing;
  return importing !== undefined && importing !== null;
}

/**
 * The first-boot script a server that exists was created with: in its change's `before`, which the
 * masked plan keeps (it drops `prior_state`).
 */
function storedServerScript(planJson: unknown, address: string): string | undefined {
  const before = resourceChange(planJson, address)?.before;
  return isRecord(before) ? serverFirewallScript(before) : undefined;
}

const Networks = z.array(z.string());
/**
 * What the plan JSON says of the networks a server module gets: the root's variables, and the
 * module calls, each read on its own ({@link ModuleCallSchema}) so that another module's call
 * never decides whether this one's can be read.
 */
const PlannedNetworksSchema = z.object({
  variables: z.object({
    ssh_allowed_cidrs: z.object({ value: Networks }),
    http_allowed_cidrs: z.object({ value: Networks }).optional(),
  }),
  configuration: z.object({
    root_module: z.object({ module_calls: z.record(z.string(), z.unknown()) }),
  }),
});
/** What a server module's call says of its web ports and its WireGuard port. */
const ModuleCallSchema = z.object({
  expressions: z
    .object({
      web: z.object({ constant_value: z.boolean() }).optional(),
      wireguard_port: z.object({ constant_value: z.union([z.number(), z.string()]) }).optional(),
    })
    .optional(),
});

/**
 * The networks the plan gives the server at `address` (`module.<call>.<type>.<name>`): the root's
 * `ssh_allowed_cidrs`, its `http_allowed_cidrs` unless the module call closes the web ports
 * (`web = false`, an extra server), and the module call's `wireguard_port`. Undefined when the plan
 * JSON doesn't say them.
 */
function plannedNetworks(planJson: unknown, address: string): ServerFirewallNetworks | undefined {
  const call = /^module\.([^.]+)\./.exec(address)?.[1];
  const parsed = PlannedNetworksSchema.safeParse(planJson);
  if (call === undefined || !parsed.success) return undefined;
  const { variables, configuration } = parsed.data;
  const parsedCall = ModuleCallSchema.safeParse(configuration.root_module.module_calls[call]);
  if (!parsedCall.success) return undefined;
  const module = parsedCall.data;
  const closed = module.expressions?.web?.constant_value === false;
  const web = closed ? [] : variables.http_allowed_cidrs?.value;
  if (web === undefined) return undefined;
  const port = module.expressions?.wireguard_port?.constant_value;
  return {
    ssh: variables.ssh_allowed_cidrs.value,
    web,
    wireguard: port === undefined ? "" : String(port),
  };
}

/** Up to six of `items` in a sentence, the rest counted. */
function some(items: readonly string[]): string {
  return items.length <= 6
    ? listText(items)
    : `${items.slice(0, 5).join(", ")} and ${items.length - 5} more`;
}

/** How the networks of `kind` on the server (`live`) differ from the plan's; none when equal. */
function networkDifference(
  kind: string,
  noun: string,
  live: readonly string[],
  planned: readonly string[],
): string[] {
  const stray = live.filter((network) => !planned.includes(network));
  const lacking = planned.filter((network) => !live.includes(network));
  const said = [
    ...(stray.length === 0 ? [] : [`the ${noun} accepts ${some(stray)}, which the plan doesn't`]),
    ...(lacking.length === 0 ? [] : [`the plan adds ${some(lacking)}`]),
  ];
  return said.length === 0 ? [] : [`${kind}: ${said.join(", and ")}`];
}

/** How the WireGuard port on the server (`live`, `""` for none) differs from the plan's. */
function portDifference(noun: string, live: string, planned: string): string[] {
  if (live === planned) return [];
  const said =
    live === ""
      ? `the plan opens UDP port ${planned}, which the ${noun} doesn't`
      : planned === ""
        ? `the ${noun} opens UDP port ${live}, which the plan doesn't`
        : `the ${noun} opens UDP port ${live} and the plan ${planned}`;
  return [`WireGuard: ${said}`];
}

/** Maps a server module call name (`server`, `server_db`, `server_previous`) to its OpsCrew server name. */
function serverNameOfModule(moduleCall: string): string {
  if (moduleCall === "server") return "app";
  if (moduleCall.startsWith("server_")) return moduleCall.slice("server_".length);
  return moduleCall;
}

/** True when `options` allows updating the server at `address` in place via a host plan. */
function allowsInPlaceUpdate(address: string, options?: EvaluatePlanPoliciesOptions): boolean {
  return options?.inPlaceServerFirewallAddresses?.has(address) === true;
}

/**
 * Lists every existing server in `planJson` on a `firewallCheck: "server"` provider (excluding
 * servers being imported in this plan): its address, module call, OpsCrew server name (`app`,
 * `<extra>`, or `previous`), and the networks the plan gives it. Callers use this to read
 * `/etc/opscrew/firewall-networks.json` over SSH before calling {@link evaluatePlanPolicies}.
 */
export function existingOwnFirewallServers(planJson: unknown): ExistingOwnFirewallServer[] {
  const resources = plannedResources(planJson);
  const out: ExistingOwnFirewallServer[] = [];
  for (const provider of PROVIDERS) {
    if (provider.firewallCheck !== "server") continue;
    for (const server of resources.filter((r) => r.type === provider.server)) {
      if (!serverExists(planJson, server.address) || serverImported(planJson, server.address)) {
        continue;
      }
      const moduleCall = /^module\.([^.]+)\./.exec(server.address)?.[1];
      if (moduleCall === undefined) continue;
      out.push({
        address: server.address,
        moduleCall,
        server: serverNameOfModule(moduleCall),
        planned: plannedNetworks(planJson, server.address),
      });
    }
  }
  return out;
}

/**
 * Lists every existing server in `planJson` on a `firewallCheck: "server"` provider whose current
 * networks (from `options.serverFirewallNetworks[address]`, falling back to the first-boot script
 * in Terraform state when no record exists yet) differ from the plan's networks and therefore need
 * an in-place `server-firewall` host plan.
 */
export function serverFirewallUpdates(
  planJson: unknown,
  options?: Pick<EvaluatePlanPoliciesOptions, "serverFirewallNetworks">,
): PlannedServerFirewallUpdate[] {
  const resources = plannedResources(planJson);
  const out: PlannedServerFirewallUpdate[] = [];
  for (const provider of PROVIDERS) {
    if (provider.firewallCheck !== "server") continue;
    for (const server of resources.filter((r) => r.type === provider.server)) {
      if (!serverExists(planJson, server.address) || serverImported(planJson, server.address)) {
        continue;
      }
      const moduleCall = /^module\.([^.]+)\./.exec(server.address)?.[1];
      if (moduleCall === undefined) continue;
      const current =
        options?.serverFirewallNetworks?.[server.address] ??
        scriptNetworks(storedServerScript(planJson, server.address));
      const planned = plannedNetworks(planJson, server.address);
      if (current === undefined || planned === undefined) continue;
      const differences = [
        ...networkDifference("SSH", provider.noun, current.ssh, planned.ssh),
        ...networkDifference("the web ports", provider.noun, current.web, planned.web),
        ...portDifference(provider.noun, current.wireguard, planned.wireguard),
      ];
      if (differences.length === 0) continue;
      out.push({
        address: server.address,
        moduleCall,
        server: serverNameOfModule(moduleCall),
        current,
        planned,
        differences,
      });
    }
  }
  return out;
}

/**
 * `server-firewall-as-planned` for a server that already exists on a provider whose firewall is
 * the server's own: compares the plan's networks against `/etc/opscrew/firewall-networks.json`
 * (read over SSH and supplied in `options.serverFirewallNetworks`), falling back to the first-boot
 * script in Terraform state only when no record exists yet. When networks differ and an in-place
 * host plan is available (`allowsInPlaceUpdate`), passes and records that OpsCrew updates the
 * firewall through a hash-approved host plan; otherwise fails critical.
 */
function storedFirewallResult(
  noun: string,
  planJson: unknown,
  server: PlannedResourceJson,
  options?: EvaluatePlanPoliciesOptions,
): { policy: PolicyResult; inPlacePlanned?: ServerFirewallNetworks } {
  const recorded = options?.serverFirewallNetworks?.[server.address];
  const stored = recorded ?? scriptNetworks(storedServerScript(planJson, server.address));
  const planned = plannedNetworks(planJson, server.address);
  const check = (passed: boolean, message: string) =>
    result(
      "server-firewall-as-planned",
      "The server's own firewall has the plan's networks",
      "critical",
      passed,
      message,
      server.address,
    );
  const live = `\`opscrew secure\` reads the rules live on the ${noun}`;
  if (serverImported(planJson, server.address)) {
    return {
      policy: check(
        true,
        `The plan imports the ${noun}, which OpsCrew didn't create: its provider doesn't give back the script it started with, so this plan can't hold its firewall to the plan's networks. After the apply, ${live} and fails on any rule that differs from the plan's, or on no firewall of OpsCrew's at all.`,
      ),
    };
  }
  const readError = options?.serverFirewallReadErrors?.[server.address];
  if (readError !== undefined) {
    return {
      policy: check(
        false,
        `OpsCrew could not read /etc/opscrew/firewall-networks.json on the ${noun} over SSH (${readError}), so it will not fall back to the first-boot script in Terraform state (which may be stale after an earlier in-place firewall update). Nothing was changed: check that the ${noun} is reachable over SSH and try again; ${live}.`,
      ),
    };
  }
  if (stored === undefined) {
    return {
      policy: check(
        false,
        `The ${noun} already exists, and OpsCrew can't read the networks its own firewall was set at its first boot with (neither /etc/opscrew/firewall-networks.json nor a readable firewall step in its startup script was found), so it can't tell whether this plan changes them. Nothing was changed: ${live}.`,
      ),
    };
  }
  if (planned === undefined) {
    return {
      policy: check(
        false,
        `OpsCrew can't read the networks this plan gives the ${noun} (the root's \`ssh_allowed_cidrs\` and \`http_allowed_cidrs\`, or its module's \`wireguard_port\`), so it can't hold them to the ones on the ${noun}. Run \`opscrew provision\` again, which writes them; ${live}.`,
      ),
    };
  }
  const differences = [
    ...networkDifference("SSH", noun, stored.ssh, planned.ssh),
    ...networkDifference("the web ports", noun, stored.web, planned.web),
    ...portDifference(noun, stored.wireguard, planned.wireguard),
  ];
  if (differences.length === 0) {
    return {
      policy: check(
        true,
        recorded !== undefined
          ? `The ${noun}'s own firewall (recorded in /etc/opscrew/firewall-networks.json) has this plan's networks.`
          : `The ${noun}'s own firewall, set at its first boot, has this plan's networks.`,
      ),
    };
  }
  if (allowsInPlaceUpdate(server.address, options)) {
    return {
      policy: check(
        true,
        `The ${noun}'s own firewall differs from this plan's networks (${differences.join("; ")}), and OpsCrew updates /etc/opscrew/firewall.nft and /etc/opscrew/firewall-networks.json in place through a SHA-256 hash-approved host plan under the automatic undo.`,
      ),
      inPlacePlanned: planned,
    };
  }
  const source =
    recorded !== undefined
      ? "recorded in /etc/opscrew/firewall-networks.json"
      : "set at its first boot";
  return {
    policy: check(
      false,
      `The ${noun} already exists, and its own firewall was ${source} with networks this plan changes (${differences.join("; ")}). Applying this infrastructure plan alone would leave the old rules on the ${noun}: run \`opscrew provision\` while the ${noun} is reachable over SSH to update /etc/opscrew/firewall.nft and /etc/opscrew/firewall-networks.json in place with a hash-approved host plan, or change opscrew/plan.yaml back; ${live}.`,
    ),
  };
}

/**
 * Whether `resource` is a provider's firewall: of its `firewallResourceType`, or for `<type>.<name>`
 * (a general type, such as `terraform_data.firewall`) of that type and that name.
 */
function isFirewall(resource: PlannedResourceJson, firewallType: string): boolean {
  const [type, name] = firewallType.split(".");
  return resource.type === type && (name === undefined || resource.name === name);
}

/**
 * The server and firewall policies of one provider (spec 004 plan "Security checks"). A provider
 * whose firewall is the server's own (`firewallCheck` `server`) has no firewall resource: the rules
 * of each server the plan creates are read from its first-boot script and checked as a cloud
 * firewall's are. A server that already exists keeps the script it was created with (the module
 * ignores changes to it), so the plan may not change the networks that script set
 * (`server-firewall-as-planned`), and `opscrew secure` checks the live rules.
 */
function providerPolicies(
  provider: ProviderChecks,
  planJson: unknown,
  resources: PlannedResourceJson[],
  deployPlan: DeployPlan,
  proxiedBehindCloudflare: boolean,
  options?: EvaluatePlanPoliciesOptions,
): PolicyResult[] {
  const results: PolicyResult[] = [];
  const servers = resources.filter((r) => r.type === provider.server);
  const onServer = provider.firewallCheck === "server";
  const firewalls = onServer ? [] : resources.filter((r) => isFirewall(r, provider.firewall));
  const { noun } = provider;

  for (const server of servers) {
    const existing = onServer && serverExists(planJson, server.address);
    const serverRules = onServer && !existing ? serverFirewallRules(server) : undefined;
    const imported = existing && serverImported(planJson, server.address);
    const hasFirewall = !onServer
      ? provider.attached(server, firewalls, planJson)
      : imported ||
        (existing
          ? options?.serverFirewallNetworks?.[server.address] !== undefined ||
            storedServerScript(planJson, server.address) !== undefined
          : serverRules !== undefined);
    const hasKeys = isSet(server, provider.sshKeyAttribute ?? "ssh_keys");
    const attachedText = imported
      ? `The plan imports the ${noun}, which OpsCrew didn't create, so the firewall its first boot set can't be read from the plan: after the apply, \`opscrew secure\` checks the rules live on the ${noun}, and fails when there are none of OpsCrew's.`
      : existing
        ? `${provider.attachedText} The ${noun} already exists, so its first boot ran when it was created and this plan doesn't change its firewall: \`opscrew secure\` checks the rules live on the ${noun}.`
        : provider.attachedText;
    results.push(
      result(
        "firewall-attached",
        "Server has a firewall",
        "high",
        hasFirewall,
        hasFirewall ? attachedText : provider.unattachedText,
        server.address,
      ),
      result(
        "ssh-keys-set",
        "Server uses SSH keys",
        "high",
        hasKeys,
        hasKeys
          ? `The ${noun} is created with an SSH key, so no root password is emailed or used.`
          : provider.keylessText,
        server.address,
      ),
    );
    let inPlaceRules: PlannedFirewallRule[] | undefined;
    if (existing) {
      const checked = storedFirewallResult(noun, planJson, server, options);
      results.push(checked.policy);
      if (checked.inPlacePlanned !== undefined) {
        inPlaceRules = serverFirewallRulesFromNetworks(checked.inPlacePlanned);
      }
    }
    const checkedRules = serverRules ?? inPlaceRules;
    if (checkedRules !== undefined) {
      results.push(
        ...openPortResults(server, checkedRules, proxiedBehindCloudflare, deployPlan),
        sshPolicyResult(server, checkedRules, deployPlan),
      );
    }
    if (provider.deleteProtection) {
      const protectedServer = server.values.delete_protection === true;
      results.push(
        result(
          "delete-protection",
          "Server is protected against accidental deletion",
          "medium",
          protectedServer,
          protectedServer
            ? "Delete and rebuild protection are on."
            : "Delete protection is off, so one wrong command could delete the server and its data. Turn it on.",
          server.address,
        ),
      );
    }
    if (serverWantsBackups(deployPlan, server.address)) {
      // A provider whose connector turns them on reads them from the module (Contabo).
      const backups = provider.backups?.(server, resources) ?? server.values.backups === true;
      results.push(
        result(
          "backups-for-critical-data",
          "Automated backups are on",
          "high",
          backups,
          backups
            ? provider.backupsText
            : `The plan requires automated backups but the ${noun} has them turned off.`,
          server.address,
        ),
      );
    }
  }

  for (const firewall of firewalls) {
    const rules = provider.rules(firewall);
    results.push(...openPortResults(firewall, rules, proxiedBehindCloudflare, deployPlan));
    results.push(sshPolicyResult(firewall, rules, deployPlan));
  }

  if (!onServer && servers.length > 0 && firewalls.length === 0) {
    results.push(
      result(
        "firewall-attached",
        "Server has a firewall",
        "high",
        false,
        `The plan creates a ${noun} but no firewall. Every port would be reachable from the internet.`,
      ),
    );
  }
  return results;
}

/**
 * Policy checks on an engine plan (`show -json`) before the user is asked to approve it. Returns
 * passing and failing results; callers stop on any failed `critical` or `high` result. A Portainer
 * target's root (Cloudflare Tunnels, their routes and Access, no server) is evaluated like any
 * other: the server and firewall policies find nothing to check there.
 */
export function evaluatePlanPolicies(
  planJson: unknown,
  deployPlan: DeployPlan,
  options?: EvaluatePlanPoliciesOptions,
): PolicyResult[] {
  const resources = plannedResources(planJson);
  const proxiedBehindCloudflare =
    deployPlan.dns.provider === "cloudflare" &&
    deployPlan.dns.proxied &&
    deployPlan.security.httpAllowedFrom === "edge";
  const results = PROVIDERS.flatMap((provider) =>
    providerPolicies(provider, planJson, resources, deployPlan, proxiedBehindCloudflare, options),
  );

  if (deployPlan.dns.provider === "cloudflare" && deployPlan.dns.proxied && deployPlan.dns.domain) {
    const domain = deployPlan.dns.domain;
    const recordType = edgeProvider(deployPlan.dns.provider).terraform.dnsRecordResourceType;
    const appRecords = resources.filter(
      (r) =>
        r.type === recordType &&
        (r.values.type === "A" || r.values.type === "AAAA") &&
        r.values.name === domain,
    );
    for (const record of appRecords) {
      results.push(
        result(
          "dns-proxied",
          "DNS record goes through Cloudflare",
          "low",
          record.values.proxied === true,
          record.values.proxied === true
            ? `${domain} is proxied through Cloudflare (hides the server IP, adds the WAF).`
            : `${domain} points straight at the server; turn on Cloudflare proxying.`,
          record.address,
        ),
      );
    }
  }
  return results;
}
/** Failed results at or above `high`; provisioning stops before approval when any exist. */
export function blockingPolicyFailures(results: PolicyResult[]): PolicyResult[] {
  return results.filter((r) => !r.passed && (r.severity === "critical" || r.severity === "high"));
}
