// biome-ignore-all lint/suspicious/noTemplateCurlyInString: templatefile's placeholders, not JavaScript templates.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { FakeHost } from "./__fixtures__/fake-host";
import { BASH_AVAILABLE, ShellHarness } from "./__fixtures__/shell-harness";
import { applyHostPlan } from "./apply";
import { DEAD_MAN_DIR } from "./constants";
import { hostPlanHash } from "./hash";
import { inspectHost } from "./inspect";
import { planServerFirewall } from "./plan";
import {
  parseServerFirewallNetworks,
  readServerFirewallNetworks,
  SERVER_FIREWALL_NETWORKS_FILE,
  SERVER_FIREWALL_RULES,
  SERVER_FIREWALL_SERVICE,
  serverFirewallFileHashes,
  serverFirewallListing,
  serverFirewallNetworksJson,
  serverFirewallRulesFile,
} from "./server-firewall";
import { armScript, cancelScript, stepScripts, triggerScript } from "./steps";

const WORLD = ["0.0.0.0/0", "::/0"];
const CLOUDFLARE = ["173.245.48.0/20", "2400:cb00::/32"];
const NARROWED = ["203.0.113.7/32"];
const COMMAND = "opscrew provision";

describe("serverFirewallRulesFile and serverFirewallNetworksJson", () => {
  it("writes the exact same nftables rules as first-boot server-firewall.sh.tftpl", () => {
    const params = { ssh: NARROWED, web: CLOUDFLARE, wireguardPort: 51820 };
    const rules = serverFirewallRulesFile(params);
    expect(rules).toContain("#!/usr/sbin/nft -f\n");
    expect(rules).toContain(
      "add table inet opscrew-firewall\ndelete table inet opscrew-firewall\n",
    );
    expect(rules).toContain('\t\tiifname "wg-opscrew*" accept\n');
    expect(rules).toContain("\t\tip saddr 203.0.113.7/32 tcp dport 22 accept\n");
    expect(rules).toContain("\t\tip saddr 173.245.48.0/20 tcp dport { 80, 443 } accept\n");
    expect(rules).toContain("\t\tip6 saddr 2400:cb00::/32 udp dport 443 accept\n");
    expect(rules).toContain("\t\tudp dport 51820 accept\n");
    expect(rules).toContain(
      "\t\tct direction original ct status dnat meta l4proto tcp ct original proto-dst 80 ip saddr 173.245.48.0/20 accept\n",
    );

    // Every /0 uses meta nfproto ipv4/ipv6 as server-firewall.sh.tftpl does.
    const open = serverFirewallRulesFile({ ssh: WORLD, web: WORLD });
    expect(open).toContain("\t\tmeta nfproto ipv4 tcp dport 22 accept\n");
    expect(open).toContain("\t\tmeta nfproto ipv6 tcp dport 22 accept\n");
    expect(open).not.toContain("wg-opscrew*");
    expect(open).not.toContain("udp dport 51820");

    // Listing strips /32 as nft list table does.
    const listing = serverFirewallListing(params);
    expect(listing).toContain("|ip saddr 203.0.113.7 tcp dport 22 accept|");
    expect(listing).toContain("|udp dport 51820 accept|");

    // CIDRs with host bits set are canonicalized in both firewall.nft and the expected listing.
    const nonCanonical = { ssh: ["198.51.100.7/24", "2001:db8::1/64"], web: [] };
    const nonCanonicalRules = serverFirewallRulesFile(nonCanonical);
    const nonCanonicalListing = serverFirewallListing(nonCanonical);
    expect(nonCanonicalRules).toContain("\t\tip saddr 198.51.100.0/24 tcp dport 22 accept\n");
    expect(nonCanonicalRules).toContain("\t\tip6 saddr 2001:db8::/64 tcp dport 22 accept\n");
    expect(nonCanonicalListing).toContain("|ip saddr 198.51.100.0/24 tcp dport 22 accept|");
    expect(nonCanonicalListing).toContain("|ip6 saddr 2001:db8::/64 tcp dport 22 accept|");

    // Networks JSON is schemaVersion 1 with exact networks.
    const json = serverFirewallNetworksJson(params);
    expect(JSON.parse(json)).toEqual({
      schemaVersion: 1,
      ssh: NARROWED,
      web: CLOUDFLARE,
      wireguardPort: 51820,
    });
    expect(JSON.parse(serverFirewallNetworksJson({ ssh: WORLD, web: [] }))).toEqual({
      schemaVersion: 1,
      ssh: WORLD,
      web: [],
    });
  });

  it.skipIf(!BASH_AVAILABLE)(
    "matches opscrew_firewall_rules in packages/iac-templates/shared/server-firewall.sh.tftpl byte-for-byte",
    () => {
      const templatePath = fileURLToPath(
        new URL("../../../iac-templates/shared/server-firewall.sh.tftpl", import.meta.url),
      );
      const template = readFileSync(templatePath, "utf8").replace(/\r\n/g, "\n");
      const cases = [
        { ssh: WORLD, web: WORLD },
        { ssh: NARROWED, web: CLOUDFLARE, wireguardPort: 51820 },
        { ssh: [], web: [], wireguardPort: 51821 },
      ];
      for (const params of cases) {
        const rendered = template
          .replace("${ssh_sources}", params.ssh.join(" "))
          .replace("${web_sources}", params.web.join(" "))
          .replace("${wireguard_port}", params.wireguardPort ? String(params.wireguardPort) : "")
          .replace(/\nopscrew_server_firewall\s*$/, "\nopscrew_firewall_rules\n");
        const h = new ShellHarness();
        const res = h.run(rendered);
        expect(res.status, res.stderr).toBe(0);
        expect(res.stdout).toBe(serverFirewallRulesFile(params));
      }
    },
  );
});

function dockerFake(): FakeHost {
  const fake = new FakeHost({ login: "deploy", sudo: "none" });
  fake.dockerAccess = true;
  return fake;
}

describe("readServerFirewallNetworks", () => {
  it("returns undefined when /etc/opscrew/firewall-networks.json is absent", async () => {
    const fake = dockerFake();
    expect(
      await readServerFirewallNetworks(fake, "docker", `caddy@sha256:${"a".repeat(64)}`),
    ).toBeUndefined();
  });

  it("reads and validates /etc/opscrew/firewall-networks.json when present", async () => {
    const fake = dockerFake();
    const params = { ssh: NARROWED, web: CLOUDFLARE, wireguardPort: 51820 };
    fake.files.set(SERVER_FIREWALL_NETWORKS_FILE, serverFirewallNetworksJson(params));
    expect(
      await readServerFirewallNetworks(fake, "docker", `caddy@sha256:${"a".repeat(64)}`),
    ).toEqual({
      schemaVersion: 1,
      ssh: NARROWED,
      web: CLOUDFLARE,
      wireguardPort: 51820,
    });
  });

  it("fails closed when /etc/opscrew/firewall-networks.json is damaged JSON or invalid", () => {
    expect(parseServerFirewallNetworks("absent\n")).toBeUndefined();
    expect(() => parseServerFirewallNetworks("present\n{not json")).toThrow(/not valid JSON/);
    expect(() =>
      parseServerFirewallNetworks('present\n{"schemaVersion":1,"ssh":["$(rm -rf /)"],"web":[]}'),
    ).toThrow(/damaged or incomplete/);
  });
});

describe("planServerFirewall and applyHostPlan", () => {
  const ROOT_IMAGE = `caddy:2.9.1@sha256:${"a".repeat(64)}`;

  it("plans a change, applies under dead-man switch, writes 0600 files, and is idempotent", async () => {
    const fake = dockerFake();
    fake.nftInstalled = true;
    const before = { ssh: WORLD, web: WORLD };
    fake.files.set(SERVER_FIREWALL_RULES, serverFirewallRulesFile(before));
    fake.serverFirewall.table = serverFirewallListing(before);

    const facts = await inspectHost(fake, { rootImage: ROOT_IMAGE });
    const wanted = { ssh: NARROWED, web: CLOUDFLARE, wireguardPort: 51820 };
    const plan = planServerFirewall(facts, { app: "shop", serverFirewall: wanted }, COMMAND);
    expect(plan.findings).toEqual([]);
    expect(plan.steps).toHaveLength(1);
    expect(plan.steps[0]).toMatchObject({ id: "server-firewall", state: "change" });

    // Refuses wrong hash (ADR 0011, Constitution I).
    await expect(
      applyHostPlan(fake, plan, {
        approvedHash: "0".repeat(64),
        command: COMMAND,
        verifyLogin: async () => true,
        rootImage: ROOT_IMAGE,
      }),
    ).rejects.toMatchObject({ code: "PLAN_HASH_MISMATCH" });

    // Applies with approved SHA-256 hash.
    const hash = hostPlanHash(plan);
    const applied = await applyHostPlan(fake, plan, {
      approvedHash: hash,
      command: COMMAND,
      verifyLogin: async () => true,
      rootImage: ROOT_IMAGE,
    });
    expect(applied.applied).toEqual(["server-firewall"]);
    expect(fake.files.get(SERVER_FIREWALL_RULES)).toBe(serverFirewallRulesFile(wanted));
    expect(fake.files.get(SERVER_FIREWALL_NETWORKS_FILE)).toBe(serverFirewallNetworksJson(wanted));
    expect(fake.fileModes.get(SERVER_FIREWALL_RULES)).toBe("0:0:600");
    expect(fake.fileModes.get(SERVER_FIREWALL_NETWORKS_FILE)).toBe("0:0:600");
    expect(fake.serverFirewall.table).toBe(serverFirewallListing(wanted));
    expect(fake.serverFirewall.reloads).toBe(1);
    expect(fake.timers.has("server-firewall")).toBe(false);

    // Dead-man was armed and cancelled.
    const names = fake.calls.map((entry) => entry.name);
    expect(names).toContain("deadman.arm.server-firewall");
    expect(names).toContain("deadman.cancel.server-firewall");

    // Re-applying is idempotent (skipped by check).
    const rerun = await applyHostPlan(fake, plan, {
      approvedHash: hash,
      command: COMMAND,
      verifyLogin: async () => true,
      rootImage: ROOT_IMAGE,
    });
    expect(rerun.applied).toEqual([]);
    expect(rerun.skipped).toEqual(["server-firewall"]);

    // Planning again with the read networks record marks the step in-place.
    const current = await readServerFirewallNetworks(fake, "docker", ROOT_IMAGE);
    const secondPlan = planServerFirewall(
      facts,
      { app: "shop", serverFirewall: wanted, current },
      COMMAND,
    );
    expect(secondPlan.steps[0]?.state).toBe("in-place");
  });

  it("rolls back both firewall.nft and firewall-networks.json when verifyLogin fails", async () => {
    const fake = dockerFake();
    fake.nftInstalled = true;
    const before = { ssh: WORLD, web: WORLD };
    const beforeRules = serverFirewallRulesFile(before);
    const beforeNetworks = serverFirewallNetworksJson(before);
    fake.files.set(SERVER_FIREWALL_RULES, beforeRules);
    fake.files.set(SERVER_FIREWALL_NETWORKS_FILE, beforeNetworks);
    fake.serverFirewall.table = serverFirewallListing(before);

    const facts = await inspectHost(fake, { rootImage: ROOT_IMAGE });
    const wanted = { ssh: NARROWED, web: CLOUDFLARE };
    const plan = planServerFirewall(facts, { app: "shop", serverFirewall: wanted }, COMMAND);

    await expect(
      applyHostPlan(fake, plan, {
        approvedHash: hostPlanHash(plan),
        command: COMMAND,
        verifyLogin: async () => false,
        rootImage: ROOT_IMAGE,
      }),
    ).rejects.toMatchObject({
      code: "COMMAND_FAILED",
      message: expect.stringContaining("put the previous server firewall settings back"),
    });

    // Both firewall.nft and firewall-networks.json were restored!
    expect(fake.files.get(SERVER_FIREWALL_RULES)).toBe(beforeRules);
    expect(fake.files.get(SERVER_FIREWALL_NETWORKS_FILE)).toBe(beforeNetworks);
    expect(fake.serverFirewall.table).toBe(serverFirewallListing(before));
    expect(fake.calls.map((e) => e.name)).toContain("deadman.trigger.server-firewall");
  });

  it("removes firewall-networks.json on rollback if it did not exist before the update", async () => {
    const fake = dockerFake();
    fake.nftInstalled = true;
    const before = { ssh: WORLD, web: WORLD };
    fake.files.set(SERVER_FIREWALL_RULES, serverFirewallRulesFile(before));
    fake.serverFirewall.table = serverFirewallListing(before);

    const facts = await inspectHost(fake, { rootImage: ROOT_IMAGE });
    const plan = planServerFirewall(
      facts,
      { app: "shop", serverFirewall: { ssh: NARROWED, web: WORLD } },
      COMMAND,
    );

    await expect(
      applyHostPlan(fake, plan, {
        approvedHash: hostPlanHash(plan),
        command: COMMAND,
        verifyLogin: async () => false,
        rootImage: ROOT_IMAGE,
      }),
    ).rejects.toMatchObject({ code: "COMMAND_FAILED" });

    expect(fake.files.get(SERVER_FIREWALL_RULES)).toBe(serverFirewallRulesFile(before));
    expect(fake.files.has(SERVER_FIREWALL_NETWORKS_FILE)).toBe(false);
  });

  it("rejects unsafe network inputs before creating a host plan", async () => {
    const fake = new FakeHost({ login: "root" });
    const facts = await inspectHost(fake);
    expect(() =>
      planServerFirewall(
        facts,
        { app: "shop", serverFirewall: { ssh: ["1.2.3.4; id"], web: WORLD } },
        COMMAND,
      ),
    ).toThrow(/not valid/);
  });

  it.skipIf(!BASH_AVAILABLE)(
    "runs arm, apply, cancel, verify, and dead-man undo scripts cleanly in a real POSIX shell",
    async () => {
      const fake = new FakeHost({ login: "root" });
      const facts = await inspectHost(fake);
      const before = { ssh: WORLD, web: WORLD };
      const wanted = { ssh: NARROWED, web: CLOUDFLARE, wireguardPort: 51820 };
      const plan = planServerFirewall(facts, { app: "shop", serverFirewall: wanted }, COMMAND);
      const step = plan.steps[0];
      if (!step) throw new Error("missing step");
      const scripts = stepScripts(plan, step);
      if (!scripts.deadMan) throw new Error("missing deadMan");

      const h = new ShellHarness();
      const rulesPosix = h.posix(SERVER_FIREWALL_RULES);
      const networksPosix = h.posix(SERVER_FIREWALL_NETWORKS_FILE);
      const tableState = h.posix("/state/nft-table");
      const tableBefore = h.posix("/state/nft-before");
      const tableWanted = h.posix("/state/nft-wanted");
      h.write(SERVER_FIREWALL_RULES, serverFirewallRulesFile(before));
      h.write(SERVER_FIREWALL_NETWORKS_FILE, serverFirewallNetworksJson(before));
      h.write("/state/nft-before", serverFirewallListing(before).replaceAll("|", "\n"));
      h.write("/state/nft-wanted", serverFirewallListing(wanted).replaceAll("|", "\n"));
      h.write("/state/nft-table", serverFirewallListing(before).replaceAll("|", "\n"));

      // Stub nft, systemctl, systemd-run, flock.
      h.stub(
        "nft",
        `if [ "$1" = "list" ] && [ "$2" = "table" ]; then cat "${tableState}"; exit 0; fi
if [ "$1" = "-f" ]; then
  if grep -q '203.0.113.7/32' "$2"; then cp "${tableWanted}" "${tableState}"; else cp "${tableBefore}" "${tableState}"; fi
  exit 0
fi`,
      );
      h.stub(
        "systemctl",
        `case "$1" in
  cat) [ "$2" = "${SERVER_FIREWALL_SERVICE}" ] && exit 0; exit 1 ;;
  restart)
    if [ "$2" = "${SERVER_FIREWALL_SERVICE}" ]; then
      if grep -q '203.0.113.7/32' "${rulesPosix}"; then cp "${tableWanted}" "${tableState}"; else cp "${tableBefore}" "${tableState}"; fi
      exit 0
    fi ;;
  is-active)
    shift; [ "$1" = "--quiet" ] && shift
    [ -f "${h.posix("/state/active.")}$1" ] && exit 0 || exit 3 ;;
  stop)
    rm -f "${h.posix("/state/active.")}$2" ;;
  reset-failed) exit 0 ;;
esac`,
      );
      h.stub(
        "systemd-run",
        `for a in "$@"; do case "$a" in --unit=*) u=\${a#--unit=}; touch "${h.posix("/state/active.")}$u.timer" ;; esac; done`,
      );
      h.stub("flock", "exit 0");

      // 1. Arm dead-man, apply, cancel, verify.
      const armed = h.run(armScript(scripts.deadMan, 180));
      expect(armed.status, armed.stderr).toBe(0);
      expect(armed.stdout.trim()).toBe("armed");
      expect(h.exists(`${DEAD_MAN_DIR}/server-firewall.prev`)).toBe(true);
      expect(h.exists(`${DEAD_MAN_DIR}/server-firewall.networks.prev`)).toBe(true);

      const applied = h.run(scripts.apply);
      expect(applied.status, applied.stderr).toBe(0);
      expect(h.read(SERVER_FIREWALL_RULES)).toBe(serverFirewallRulesFile(wanted));
      expect(h.read(SERVER_FIREWALL_NETWORKS_FILE)).toBe(serverFirewallNetworksJson(wanted));

      // Verify dead-man undo restores BOTH files if triggered before cancel!
      const triggered = h.run(triggerScript("server-firewall"));
      expect(triggered.status, triggered.stderr).toBe(0);
      expect(h.read(SERVER_FIREWALL_RULES)).toBe(serverFirewallRulesFile(before));
      expect(h.read(SERVER_FIREWALL_NETWORKS_FILE)).toBe(serverFirewallNetworksJson(before));

      // 2. Arm again, apply, cancel, and verify succeeds.
      expect(h.run(armScript(scripts.deadMan, 180)).status).toBe(0);
      expect(h.run(scripts.apply).status).toBe(0);
      const cancelled = h.run(cancelScript("server-firewall"));
      expect(cancelled.status, cancelled.stderr).toBe(0);
      expect(cancelled.stdout.trim()).toBe("cancelled");
      expect(h.exists(`${DEAD_MAN_DIR}/server-firewall.networks.prev`)).toBe(false);

      const verified = h.run(scripts.verify);
      expect(verified.status, verified.stderr).toBe(0);

      // File hashes helper matches.
      const hashes = serverFirewallFileHashes(wanted);
      expect(hashes.rules).toMatch(/^[0-9a-f]{64}$/);
      expect(hashes.networks).toMatch(/^[0-9a-f]{64}$/);
      expect(networksPosix).toContain("firewall-networks.json");
    },
  );
});
