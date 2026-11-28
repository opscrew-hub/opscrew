// biome-ignore-all lint/suspicious/noTemplateCurlyInString: these strings are shell, not JavaScript templates.
/**
 * OpsCrew's in-place update for a server's own firewall (`firewallCheck: "server"`, issue #62;
 * Kamatera): rewrites `/etc/opscrew/firewall.nft` in the exact form `server-firewall.sh.tftpl`
 * writes at first boot, reloads `opscrew-firewall.service` (which replaces only the table
 * `inet opscrew-firewall` in one transaction), and atomically writes the applied networks record
 * `/etc/opscrew/firewall-networks.json` (0600, root-owned) beside it. Runs under the dead-man
 * switch so SSH stays reachable if new rules lock OpsCrew out, restoring both
 * `/etc/opscrew/firewall.nft` and `/etc/opscrew/firewall-networks.json` on rollback.
 */
import type { RemoteExec } from "@opscrew/contracts";
import { OpsCrewError, sha256Hex } from "@opscrew/core";
import { z } from "zod";
import { OPSCREW_DIR } from "./constants";
import { canonicalSshSource, linesOf } from "./parse";
import { type HostPrivilege, readAsRoot, readFailure } from "./privilege";
import { buildScript } from "./shell";
import { spaceList } from "./types";

/** OpsCrew's nftables table on a server with no cloud firewall (family and name). */
export const SERVER_FIREWALL_TABLE = "inet opscrew-firewall";
/** The rules file loaded at boot and reloaded on in-place updates. */
export const SERVER_FIREWALL_RULES = `${OPSCREW_DIR}/firewall.nft`;
/** The applied networks record stored next to the rules file (0600, owned by root). */
export const SERVER_FIREWALL_NETWORKS_FILE = `${OPSCREW_DIR}/firewall-networks.json`;
/** The oneshot systemd unit that loads {@link SERVER_FIREWALL_RULES} without flushing other tables. */
export const SERVER_FIREWALL_SERVICE = "opscrew-firewall.service";

/** Every IPv4 address, and every IPv6 address. */
const ANY_IPV4 = "0.0.0.0/0";
const ANY_IPV6 = "::/0";

/** Maximum networks per family list (well above Cloudflare's range list and any SSH allow-list). */
const MAX_FIREWALL_NETWORKS = 128;

/**
 * One network or host allowed by the server's own firewall: `0.0.0.0/0`, `::/0`, or any valid
 * IPv4/IPv6 host or CIDR network (`canonicalSshSource`). Rejects shell metacharacters and
 * whitespace.
 */
export const ServerFirewallNetworkSchema = z
  .string()
  .min(1)
  .max(64)
  .refine(
    (text) =>
      text === text.trim() &&
      !/\s/.test(text) &&
      (text === ANY_IPV4 || text === ANY_IPV6 || canonicalSshSource(text) !== null),
    {
      message:
        "must be an IPv4 or IPv6 address or CIDR network such as 203.0.113.7/32 or 0.0.0.0/0",
    },
  );

/** Deduplicates `items` while preserving their first-seen order. */
function uniqueOrdered(items: readonly string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const item of items) {
    if (!seen.has(item)) {
      seen.add(item);
      out.push(item);
    }
  }
  return out;
}

/**
 * Parameters for the `server-firewall` host step: the networks that reach SSH, the web ports
 * (80/tcp, 443/tcp, 443/udp), and the optional WireGuard UDP port.
 */
export const ServerFirewallParamsSchema = z.strictObject({
  ssh: z.array(ServerFirewallNetworkSchema).max(MAX_FIREWALL_NETWORKS),
  web: z.array(ServerFirewallNetworkSchema).max(MAX_FIREWALL_NETWORKS),
  wireguardPort: z.number().int().min(1).max(65535).optional(),
});
export type ServerFirewallParams = z.infer<typeof ServerFirewallParamsSchema>;

/** What `/etc/opscrew/firewall-networks.json` holds on the server. */
export const ServerFirewallNetworksRecordSchema = z.strictObject({
  schemaVersion: z.literal(1),
  ssh: z.array(ServerFirewallNetworkSchema).max(MAX_FIREWALL_NETWORKS),
  web: z.array(ServerFirewallNetworkSchema).max(MAX_FIREWALL_NETWORKS),
  wireguardPort: z.number().int().min(1).max(65535).optional(),
});
export type ServerFirewallNetworksRecord = z.infer<typeof ServerFirewallNetworksRecordSchema>;

/** The `server-firewall` step's parameters as a host plan keeps them (flat scalars). */
export function serverFirewallFields(
  params: ServerFirewallParams,
): Record<string, string | number | boolean> {
  const ssh = uniqueOrdered(params.ssh);
  const web = uniqueOrdered(params.web);
  return {
    ssh: ssh.join(" "),
    web: web.join(" "),
    ...(params.wireguardPort !== undefined ? { wireguardPort: params.wireguardPort } : {}),
  };
}

/** A host plan's `server-firewall` parameters ({@link serverFirewallFields}) read back and checked. */
export const ServerFirewallFieldsSchema = z
  .strictObject({
    ssh: spaceList,
    web: spaceList,
    wireguardPort: z.number().int().min(1).max(65535).optional(),
  })
  .pipe(ServerFirewallParamsSchema);

/**
 * Canonicalizes a network CIDR (masking any host bits on non-`/32` IPv4 or non-`/128` IPv6 CIDRs)
 * while preserving `/32` or `/128` notation when present in `network` so `firewall.nft` stays
 * byte-for-byte identical to `server-firewall.sh.tftpl` and matches what `nft` loads.
 */
function canonicalFirewallNetwork(network: string): string {
  if (network === ANY_IPV4 || network === ANY_IPV6) return network;
  const canonical = canonicalSshSource(network);
  if (canonical === null) return network;
  if (!canonical.includes("/")) {
    if (network.endsWith("/32")) return `${canonical}/32`;
    if (network.endsWith("/128")) return `${canonical}/128`;
  }
  return canonical;
}

/** A rule's source as `server-firewall.sh.tftpl` and nft write it (with host bits masked). */
function nftSource(network: string): string {
  if (network === ANY_IPV4) return "meta nfproto ipv4";
  if (network === ANY_IPV6) return "meta nfproto ipv6";
  const canonical = canonicalFirewallNetwork(network);
  return `${canonical.includes(":") ? "ip6" : "ip"} saddr ${canonical}`;
}

/** A rule's source as `nft list table` prints it (`/32` and `/128` stripped, host bits masked). */
function nftListedSource(network: string): string {
  if (network === ANY_IPV4) return "meta nfproto ipv4";
  if (network === ANY_IPV6) return "meta nfproto ipv6";
  const listed = canonicalSshSource(network) ?? network;
  return `${listed.includes(":") ? "ip6" : "ip"} saddr ${listed}`;
}

const DNAT_WEB_SPECS = [
  "tcp ct original proto-dst 80",
  "tcp ct original proto-dst 443",
  "udp ct original proto-dst 443",
] as const;

/**
 * Renders `/etc/opscrew/firewall.nft` in the exact form `server-firewall.sh.tftpl` writes at first
 * boot. Loading it replaces only `inet opscrew-firewall` in one transaction without touching
 * Docker's or ufw's tables.
 */
export function serverFirewallRulesFile(params: ServerFirewallParams): string {
  const ssh = uniqueOrdered(params.ssh);
  const web = uniqueOrdered(params.web);
  const wg = params.wireguardPort;
  const inside = [
    '\t\tiifname "docker0" accept',
    '\t\tiifname "br-*" accept',
    ...(wg === undefined ? [] : ['\t\tiifname "wg-opscrew*" accept']),
  ];
  const lines = [
    "#!/usr/sbin/nft -f",
    "# Managed by OpsCrew: the firewall of this server, which has no cloud firewall.",
    "# opscrew-firewall.service loads it at every boot; it replaces only the table inet opscrew-firewall.",
    `add table ${SERVER_FIREWALL_TABLE}`,
    `delete table ${SERVER_FIREWALL_TABLE}`,
    `table ${SERVER_FIREWALL_TABLE} {`,
    "\tchain input {",
    "\t\ttype filter hook input priority filter; policy drop;",
    '\t\tiifname "lo" accept',
    "\t\tct state established,related accept",
    ...inside,
    "\t\tmeta l4proto icmp accept",
    "\t\tmeta l4proto ipv6-icmp accept",
    ...ssh.map((net) => `\t\t${nftSource(net)} tcp dport 22 accept`),
    ...web.flatMap((net) => [
      `\t\t${nftSource(net)} tcp dport { 80, 443 } accept`,
      `\t\t${nftSource(net)} udp dport 443 accept`,
    ]),
    ...(wg === undefined ? [] : [`\t\tudp dport ${wg} accept`]),
    "\t}",
    "\tchain forward {",
    "\t\ttype filter hook forward priority filter; policy accept;",
    ...inside,
    ...web.flatMap((net) =>
      DNAT_WEB_SPECS.map(
        (dnat) =>
          `\t\tct direction original ct status dnat meta l4proto ${dnat} ${nftSource(net)} accept`,
      ),
    ),
    "\t\tct direction original ct status dnat drop",
    "\t\tct state established,related accept",
    '\t\toifname "docker0" drop',
    '\t\toifname "br-*" drop',
    "\t}",
    "}",
    "",
  ];
  return lines.join("\n");
}

/**
 * The live table as {@link SERVER_FIREWALL_FUNCTIONS}' `nft_server_table` prints it once the rules
 * are loaded (one statement per line without indentation, joined with `|`, older `priority 0;`
 * normalised to `priority filter;`, and `/32`/`/128` host masks stripped as nft prints them).
 */
export function serverFirewallListing(params: ServerFirewallParams): string {
  const ssh = uniqueOrdered(params.ssh);
  const web = uniqueOrdered(params.web);
  const wg = params.wireguardPort;
  const inside = [
    'iifname "docker0" accept',
    'iifname "br-*" accept',
    ...(wg === undefined ? [] : ['iifname "wg-opscrew*" accept']),
  ];
  const lines = [
    `table ${SERVER_FIREWALL_TABLE} {`,
    "chain input {",
    "type filter hook input priority filter; policy drop;",
    'iifname "lo" accept',
    "ct state established,related accept",
    ...inside,
    "meta l4proto icmp accept",
    "meta l4proto ipv6-icmp accept",
    ...ssh.map((net) => `${nftListedSource(net)} tcp dport 22 accept`),
    ...web.flatMap((net) => [
      `${nftListedSource(net)} tcp dport { 80, 443 } accept`,
      `${nftListedSource(net)} udp dport 443 accept`,
    ]),
    ...(wg === undefined ? [] : [`udp dport ${wg} accept`]),
    "}",
    "chain forward {",
    "type filter hook forward priority filter; policy accept;",
    ...inside,
    ...web.flatMap((net) =>
      DNAT_WEB_SPECS.map(
        (dnat) =>
          `ct direction original ct status dnat meta l4proto ${dnat} ${nftListedSource(net)} accept`,
      ),
    ),
    "ct direction original ct status dnat drop",
    "ct state established,related accept",
    'oifname "docker0" drop',
    'oifname "br-*" drop',
    "}",
    "}",
  ];
  return `${lines.join("|")}|`;
}

/** Renders `/etc/opscrew/firewall-networks.json` for `params`. */
export function serverFirewallNetworksJson(params: ServerFirewallParams): string {
  const record: ServerFirewallNetworksRecord = {
    schemaVersion: 1,
    ssh: uniqueOrdered(params.ssh),
    web: uniqueOrdered(params.web),
    ...(params.wireguardPort !== undefined ? { wireguardPort: params.wireguardPort } : {}),
  };
  return `${JSON.stringify(record, null, 2)}\n`;
}

/** SHA-256 of the two files the `server-firewall` step writes. */
export function serverFirewallFileHashes(params: ServerFirewallParams): {
  rules: string;
  networks: string;
} {
  return {
    rules: sha256Hex(serverFirewallRulesFile(params)),
    networks: sha256Hex(serverFirewallNetworksJson(params)),
  };
}

/** True when two network sets represent the same SSH, web and WireGuard rules (in any order). */
export function sameServerFirewallNetworks(
  a: ServerFirewallParams,
  b: ServerFirewallParams,
): boolean {
  const sameList = (left: readonly string[], right: readonly string[]) => {
    const l = new Set(left);
    const r = new Set(right);
    return l.size === r.size && [...l].every((item) => r.has(item));
  };
  return (
    sameList(a.ssh, b.ssh) &&
    sameList(a.web, b.web) &&
    (a.wireguardPort ?? undefined) === (b.wireguardPort ?? undefined)
  );
}

/**
 * Shell helper for `server-firewall`: `nft_server_table` prints `inet opscrew-firewall` as nft
 * lists it, one statement per line without indentation, joined with `|` (older nft prints
 * `priority 0;`, newer `priority filter;`; empty when the table is missing).
 */
export const SERVER_FIREWALL_FUNCTIONS = `nft_server_table() {
  nft list table ${SERVER_FIREWALL_TABLE} 2>/dev/null | sed -e 's/^[[:space:]]*//' -e 's/ priority 0;/ priority filter;/' -e '/^$/d' | tr '\\n' '|'
}`;

/**
 * Read-only script that reads `/etc/opscrew/firewall-networks.json`: prints `present` followed by
 * the file's contents when it exists, or `absent` when it does not exist yet.
 */
export function readServerFirewallNetworksScript(): string {
  return buildScript(
    "server-firewall.networks.read",
    { NETWORKS_FILE: SERVER_FIREWALL_NETWORKS_FILE },
    `if [ -f "$NETWORKS_FILE" ]; then
  printf 'present\\n'
  cat "$NETWORKS_FILE"
else
  printf 'absent\\n'
fi`,
  );
}

/**
 * Parses the output of {@link readServerFirewallNetworksScript}: `undefined` when the record does
 * not exist yet (`absent`), or the validated {@link ServerFirewallNetworksRecord}. Throws
 * `COMMAND_FAILED` on a damaged record (fail closed).
 */
export function parseServerFirewallNetworks(
  stdout: string,
): ServerFirewallNetworksRecord | undefined {
  const lines = linesOf(stdout);
  const first = lines[0]?.trim();
  if (first === "absent") return undefined;
  if (first !== "present") {
    throw new OpsCrewError(
      "COMMAND_FAILED",
      `OpsCrew received an unexpected answer while reading ${SERVER_FIREWALL_NETWORKS_FILE} on the server.`,
      { hint: "Check that the server is reachable over SSH, then try again." },
    );
  }
  const body = stdout.slice(stdout.indexOf("\n") + 1).trim();
  let raw: unknown;
  try {
    raw = JSON.parse(body);
  } catch {
    throw new OpsCrewError(
      "COMMAND_FAILED",
      `${SERVER_FIREWALL_NETWORKS_FILE} on the server is not valid JSON, so OpsCrew will not guess its firewall networks.`,
      {
        hint: `Inspect ${SERVER_FIREWALL_NETWORKS_FILE} on the server (or remove the damaged file so OpsCrew falls back to the first-boot record), then try again.`,
      },
    );
  }
  const parsed = ServerFirewallNetworksRecordSchema.safeParse(raw);
  if (!parsed.success) {
    throw new OpsCrewError(
      "COMMAND_FAILED",
      `${SERVER_FIREWALL_NETWORKS_FILE} on the server is damaged or incomplete, so OpsCrew will not guess its firewall networks.`,
      {
        hint: `Inspect ${SERVER_FIREWALL_NETWORKS_FILE} on the server (or remove the damaged file so OpsCrew falls back to the first-boot record), then try again.`,
      },
    );
  }
  return parsed.data;
}

/**
 * Reads `/etc/opscrew/firewall-networks.json` over SSH as root (`privilege`; `rootImage` for the
 * `docker` privilege). Returns `undefined` when the file does not exist yet on the server (so
 * callers can fall back to the first-boot script in Terraform state).
 */
export async function readServerFirewallNetworks(
  remote: RemoteExec,
  privilege: HostPrivilege,
  rootImage?: string,
): Promise<ServerFirewallNetworksRecord | undefined> {
  const result = await readAsRoot(
    remote,
    privilege,
    rootImage,
    readServerFirewallNetworksScript(),
    `OpsCrew could not read ${SERVER_FIREWALL_NETWORKS_FILE} on the server.`,
  );
  if (result.exitCode !== 0) {
    throw readFailure(
      result,
      `OpsCrew could not read ${SERVER_FIREWALL_NETWORKS_FILE} on the server.`,
      "Check that the server is reachable over SSH and Docker/root access works, then try again.",
    );
  }
  return parseServerFirewallNetworks(result.stdout);
}
