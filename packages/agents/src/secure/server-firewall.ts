/**
 * `secure`'s check of the server's own firewall, on a server whose provider has no cloud firewall
 * (`firewallCheck` `server`, issue #13; Kamatera): the nftables table the first boot loads,
 * read live from the server and held to the plan. Read-only.
 */
import { canonicalSshSource } from "@opscrew/connector-ssh-host";
import type { CheckResult, CommandResult } from "@opscrew/contracts";
import { listText } from "@opscrew/core";
import {
  IMAGES,
  SERVER_FIREWALL_TABLE,
  serverFirewallTable,
  webOnlyFromCloudflare,
} from "@opscrew/iac-templates";
import { APP_SERVER, type DeployPlan, isCloudProvider } from "@opscrew/plan-schema";
import { cloudProvider } from "@opscrew/providers";
import type { HostCheck } from "@opscrew/secops";
import { z } from "zod";
import { committedTfvars } from "../provision/render";

/**
 * Lists OpsCrew's table as root, run as `deploy` (who has no sudo but is in the docker group): the
 * host's own `nft`, in the host's network, with only the rights it needs to read the rules.
 */
const READ_TABLE = `docker run --rm --network host --cap-drop ALL --cap-add NET_ADMIN --cap-add SYS_CHROOT --volume /:/host:ro ${IMAGES.caddy.ref} chroot /host nft list table ${SERVER_FIREWALL_TABLE}`;

/** The rules file the first boot writes, and the oneshot unit that loads it at every boot. */
const FIREWALL_RULES = "/etc/opscrew/firewall.nft";
const FIREWALL_UNIT = "opscrew-firewall.service";

/** Every address of each family, as the module's networks write it. */
const WORLD = ["0.0.0.0/0", "::/0"];

/** A network as nft lists it (`/32` and `/128` left out); `/0` as it is. */
function listed(network: string): string {
  return canonicalSshSource(network) ?? network.trim();
}

/** The table's lines without their indentation; older nft prints a chain's priority as 0. */
function tableLines(stdout: string): string[] {
  return stdout
    .split("\n")
    .map((line) => line.trim().replace(" priority 0;", " priority filter;"))
    .filter((line) => line !== "");
}

/**
 * The networks the live table lets reach the web ports, as {@link listed} writes them: one network
 * (`<family> saddr <network>`), or a family's every address (`meta nfproto <family>`).
 */
function webSources(lines: readonly string[]): string[] {
  return lines.flatMap((line) => {
    const match =
      /^(?:ip6? saddr (\S+)|meta nfproto (ipv4|ipv6)) tcp dport \{ 80, 443 \} accept$/.exec(line);
    if (match === null) return [];
    return match[1] ?? (match[2] === "ipv4" ? "0.0.0.0/0" : "::/0");
  });
}

/**
 * The networks the plan lets reach the web ports: `http_allowed_cidrs` of the environment's
 * committed `terraform.tfvars.json`, which provision wrote for the server's module. Undefined when
 * the file or the value is missing, or the value is not a list of networks.
 */
export async function plannedWebSources(
  root: string,
  plan: Pick<DeployPlan, "infra">,
): Promise<string[] | undefined> {
  const values = await committedTfvars(root, plan);
  const parsed = z.array(z.string()).safeParse(values?.http_allowed_cidrs);
  return parsed.success ? parsed.data : undefined;
}

/** The cloud provider of server `server` of `plan`, when OpsCrew creates it. */
function serverProvider(plan: DeployPlan, server: string) {
  const id =
    server === APP_SERVER
      ? plan.target.provider
      : plan.servers?.find((s) => s.name === server)?.target.provider;
  return isCloudProvider(id) ? cloudProvider(id) : undefined;
}

/** Up to six of `items` in a sentence, the rest counted. */
function some(items: readonly string[]): string {
  return items.length <= 6
    ? listText(items)
    : `${items.slice(0, 5).join(", ")} and ${items.length - 5} more`;
}

/**
 * The check of the firewall on server `server` (the app's or an extra one) of `plan`, or undefined
 * when its provider has a cloud firewall. It passes only when the live table is the one the first
 * boot writes for the plan: default drop, SSH from `security.sshAllowedCidrs`, the web ports on the
 * app's server from `httpAllowedCidrs` (the plan's networks, {@link plannedWebSources}: Cloudflare's
 * ranges when proxied), the network's WireGuard port where the server has one, and Docker's other
 * published ports dropped from outside. The app's server fails without `httpAllowedCidrs`, since
 * nothing then says which networks its web ports may accept.
 */
export function serverFirewallCheck(
  plan: DeployPlan,
  server: string,
  httpAllowedCidrs: readonly string[] | undefined,
): HostCheck | undefined {
  const provider = serverProvider(plan, server);
  if (provider?.texts.secops.firewallCheck !== "server") return undefined;
  const web = server === APP_SERVER;
  const plannedWeb = web ? httpAllowedCidrs?.map(listed) : [];
  const open = plannedWeb?.some((network) => WORLD.includes(network)) === true;
  const cloudflare = web && !open && webOnlyFromCloudflare(plan);
  const sshSources = plan.security.sshAllowedCidrs.map(listed);
  const wireguardPort = plan.network?.members.find((member) => member.name === server)?.port;
  const tfvars = `${plan.infra.dir}/terraform.tfvars.json`;
  const remediation = `${provider.name} has no cloud firewall, so this is the server's only one. If the plan's networks changed (the web ports' are \`http_allowed_cidrs\` in ${tfvars}), run \`opscrew provision\` to update ${FIREWALL_RULES} and reload ${FIREWALL_UNIT} in place with a hash-approved host plan. If the rules on the server changed outside OpsCrew, as root on the server (from ${provider.texts.runbook.console}), \`systemctl restart ${FIREWALL_UNIT}\` loads them again as written in ${FIREWALL_RULES}. Then run \`opscrew secure\` again.`;
  const base = {
    id: "server-firewall",
    title: "The server's own firewall lets in only what the plan allows",
    severity: "critical",
  } as const;
  const check = (status: CheckResult["status"], message: string): CheckResult => ({
    ...base,
    status,
    message,
    ...(status === "pass" ? {} : { remediation }),
  });
  return {
    ...base,
    command: READ_TABLE,
    evaluate(result: CommandResult): CheckResult {
      if (result.exitCode !== 0) {
        const said = `${result.stderr}\n${result.stdout}`;
        if (/No such file or directory/.test(said)) {
          return check(
            "fail",
            `The server has no firewall of OpsCrew's (no nftables table ${SERVER_FIREWALL_TABLE}), and ${provider.name} has no cloud firewall, so nothing filters its ports.`,
          );
        }
        const reason = said.trim().split("\n")[0]?.slice(0, 200) ?? "";
        return check("fail", `OpsCrew could not read the server's firewall: ${reason}`);
      }
      if (plannedWeb === undefined) {
        return {
          ...check(
            "fail",
            `OpsCrew could not read which networks the plan lets reach the web ports (\`http_allowed_cidrs\` in ${tfvars}), so it can't hold the server's own firewall to them.`,
          ),
          remediation: `Run \`opscrew provision\`, which writes ${tfvars} again (or restore it from Git), then run \`opscrew secure\` again.`,
        };
      }
      const live = tableLines(result.stdout);
      const expected = serverFirewallTable({ sshSources, webSources: plannedWeb, wireguardPort });
      if (live.join("\n") === expected.join("\n")) {
        const from = open ? "everyone" : cloudflare ? "Cloudflare only" : "the plan's networks";
        const allowed = [
          sshSources.length === 0 ? "no SSH from outside" : "SSH from the plan's networks",
          ...(web ? [`the web ports from ${from}`] : []),
          ...(wireguardPort === undefined ? [] : [`WireGuard's port ${wireguardPort}`]),
        ];
        return check(
          "pass",
          `The server's own firewall drops by default and lets in only ${listText(allowed)} (cloud firewall: none; server firewall: on).`,
        );
      }
      const problems: string[] = [];
      if (!live.includes("type filter hook input priority filter; policy drop;")) {
        problems.push("it doesn't drop by default");
      }
      const liveWeb = webSources(live);
      const stray = liveWeb.filter((network) => !plannedWeb.includes(network));
      const lacking = plannedWeb.filter((network) => !liveWeb.includes(network));
      if (stray.length > 0) {
        const only = cloudflare ? " (it lets only Cloudflare's ranges reach them)" : "";
        problems.push(`ports 80 and 443 accept ${some(stray)}, which the plan doesn't${only}`);
      }
      if (lacking.length > 0) {
        problems.push(`ports 80 and 443 don't accept ${some(lacking)}, which the plan does`);
      }
      const quoted = (lines: string[]) => listText(lines.slice(0, 6).map((line) => `\`${line}\``));
      const extra = live.filter((line) => !expected.includes(line));
      const missing = expected.filter((line) => !live.includes(line));
      if (extra.length > 0) problems.push(`it has rules the plan doesn't: ${quoted(extra)}`);
      if (missing.length > 0) problems.push(`it lacks the plan's rules ${quoted(missing)}`);
      if (problems.length === 0) problems.push("its rules are not in the plan's order");
      return check(
        "fail",
        `The server's own firewall differs from the plan's: ${problems.join("; ")}.`,
      );
    },
  };
}
