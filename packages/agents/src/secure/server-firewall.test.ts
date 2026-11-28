import { randomBytes } from "node:crypto";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { CommandResult, RemoteExec } from "@opscrew/contracts";
import { IMAGES, type ServerFirewallRules, serverFirewallTable } from "@opscrew/iac-templates";
import { APP_SERVER, type DeployPlan, DeployPlanSchema, writeArtifact } from "@opscrew/plan-schema";
import { runHostChecks } from "@opscrew/secops";
import { describe, expect, it, vi } from "vitest";
import { recordServerAddress } from "../shared";
import { createTestPhaseDeps } from "../testing";
import { SERVER, type TestPlanOptions, testPlan } from "../verify/__fixtures__/plan";
import { runSecure } from "./run";
import { plannedWebSources, serverFirewallCheck } from "./server-firewall";
import { hostChecksFor } from "./servers";

// Hetzner as a provider with no cloud firewall, whose server has its own (as Kamatera's has),
// so a plan the schema takes reaches the check; every other provider stays as it is.
vi.mock("@opscrew/providers", async (importActual) => {
  const actual = await importActual<typeof import("@opscrew/providers")>();
  const withServerFirewall = (id: string) => {
    const provider = actual.cloudProvider(id);
    if (id !== "hetzner") return provider;
    const secops = { ...provider.texts.secops, firewallCheck: "server" as const };
    return { ...provider, texts: { ...provider.texts, secops } };
  };
  return {
    ...actual,
    cloudProvider: withServerFirewall,
    CLOUD_PROVIDERS: actual.CLOUD_PROVIDERS.map(({ id }) => withServerFirewall(id)),
  };
});

const SSH = ["203.0.113.7/32", "2001:db8:1::/48"];
/** The same networks as nft lists them: an address without its `/32`. */
const SSH_LISTED = ["203.0.113.7", "2001:db8:1::/48"];
const CLOUDFLARE = ["173.245.48.0/20", "103.21.244.0/22", "2400:cb00::/32"];
const WORLD = ["0.0.0.0/0", "::/0"];

/** A plan with the app's server on the mocked provider, and a private network when `port`. */
function plan(o: TestPlanOptions = {}, port?: number): DeployPlan {
  const base = testPlan({ sshAllowedCidrs: SSH, ...o });
  if (port === undefined) return base;
  return DeployPlanSchema.parse({
    ...base,
    network: {
      range: "10.200.4.0/24",
      members: [
        { name: "app", address: "10.200.4.1", port, publicKey: randomBytes(32).toString("base64") },
      ],
    },
  });
}

/**
 * `nft list table` of the table the first boot loads for `rules`: indented as nft prints it, a
 * blank line between the chains, and the chains' priority as `priority` (older nft prints 0).
 */
function listing(rules: ServerFirewallRules, priority = "filter"): string {
  let depth = 0;
  const lines: string[] = [];
  for (const line of serverFirewallTable(rules)) {
    if (line === "}") depth -= 1;
    if (line.startsWith("chain ") && depth === 1 && lines.length > 1) lines.push("");
    lines.push(
      `${"\t".repeat(depth)}${line.replace(" priority filter;", ` priority ${priority};`)}`,
    );
    if (line.endsWith("{")) depth += 1;
  }
  return `${lines.join("\n")}\n`;
}

/** The server's answer to the check's command. */
function answer(stdout: string, exitCode = 0, stderr = ""): CommandResult {
  return { exitCode, stdout, stderr };
}

/**
 * The check of the app's server, with `web` the networks the plan lets reach the web ports (its
 * committed `http_allowed_cidrs`), evaluated on `result`.
 */
function evaluate(
  deployPlan: DeployPlan,
  web: readonly string[] | undefined,
  result: CommandResult,
) {
  const check = serverFirewallCheck(deployPlan, APP_SERVER, web);
  if (check === undefined) throw new Error("no server firewall check");
  return check.evaluate(result);
}

/** The rules the first boot writes for the app's server of `plan()`, web open to everyone. */
const OPEN: ServerFirewallRules = { sshSources: SSH_LISTED, webSources: WORLD };
/** The same with the web ports held to Cloudflare's ranges. */
const BEHIND: ServerFirewallRules = { sshSources: SSH_LISTED, webSources: CLOUDFLARE };

/** Writes `values` as the environment's committed `terraform.tfvars.json` under `root`. */
async function commitTfvars(root: string, deployPlan: DeployPlan, values: unknown) {
  const file = join(root, deployPlan.infra.dir, "terraform.tfvars.json");
  await mkdir(dirname(file), { recursive: true });
  await writeFile(file, `${JSON.stringify(values, null, 2)}\n`);
}

describe("the server firewall's check", () => {
  it("is a host check only on a server whose provider has no cloud firewall", () => {
    const own = hostChecksFor(plan(), APP_SERVER, undefined, CLOUDFLARE);
    expect(own.filter((check) => check.id === "server-firewall")).toHaveLength(1);
    const cloud = hostChecksFor(plan({ provider: "digitalocean" }), APP_SERVER, undefined, WORLD);
    expect(cloud.map((check) => check.id)).not.toContain("server-firewall");
    expect(serverFirewallCheck(plan({ provider: "contabo" }), APP_SERVER, WORLD)).toBeUndefined();
  });

  it("reads the live table as root through Docker, with only the rights nft needs", () => {
    const check = serverFirewallCheck(plan(), APP_SERVER, CLOUDFLARE);
    expect(check?.command).toBe(
      `docker run --rm --network host --cap-drop ALL --cap-add NET_ADMIN --cap-add SYS_CHROOT --volume /:/host:ro ${IMAGES.caddy.ref} chroot /host nft list table inet opscrew-firewall`,
    );
    expect(check?.severity).toBe("critical");
  });

  it("passes a server whose rules are the plan's, over a fake SSH runner", async () => {
    const deployPlan = plan({ httpAllowedFrom: "any" });
    const commands: string[] = [];
    const remote: RemoteExec = {
      host: "203.0.113.10",
      async run(command) {
        commands.push(command);
        return command.includes("nft list table")
          ? answer(listing(OPEN))
          : answer("", 127, "not in this test");
      },
    };
    const [result] = await runHostChecks(
      remote,
      hostChecksFor(deployPlan, APP_SERVER, undefined, WORLD).filter(
        (c) => c.id === "server-firewall",
      ),
    );
    expect(result).toMatchObject({ id: "server-firewall", status: "pass", severity: "critical" });
    expect(result?.message).toContain("cloud firewall: none; server firewall: on");
    expect(commands).toHaveLength(1);
  });

  it("passes the listing of an older nft, which prints the priority as 0", () => {
    const result = evaluate(plan({ httpAllowedFrom: "any" }), WORLD, answer(listing(OPEN, "0")));
    expect(result.status).toBe("pass");
  });

  it("passes the web ports held to the plan's Cloudflare ranges", () => {
    const passed = evaluate(plan(), CLOUDFLARE, answer(listing(BEHIND)));
    expect(passed.status).toBe("pass");
    expect(passed.message).toContain("the web ports from Cloudflare only");
    // Open to everyone although the plan says Cloudflare only.
    const open = evaluate(plan(), CLOUDFLARE, answer(listing(OPEN)));
    expect(open.status).toBe("fail");
    expect(open.message).toContain("Cloudflare");
    expect(open.message).toContain("0.0.0.0/0");
  });

  it("fails a range on the web ports that the plan doesn't have, naming it and saying what to do", () => {
    const stray = "198.51.100.0/24";
    const result = evaluate(
      plan(),
      CLOUDFLARE,
      answer(listing({ ...BEHIND, webSources: [...CLOUDFLARE, stray] })),
    );
    expect(result).toMatchObject({ status: "fail", severity: "critical" });
    expect(result.message).toContain(
      `ports 80 and 443 accept ${stray}, which the plan doesn't (it lets only Cloudflare's ranges reach them)`,
    );
    expect(result.remediation).toContain(
      `http_allowed_cidrs\` in ${plan().infra.dir}/terraform.tfvars.json`,
    );
    // Points to `opscrew provision` when the plan's networks changed, and `systemctl restart` when
    // the rules on the server changed outside OpsCrew.
    expect(result.remediation).toContain(
      "run `opscrew provision` to update /etc/opscrew/firewall.nft and reload opscrew-firewall.service in place with a hash-approved host plan.",
    );
    const provision = result.remediation?.indexOf("run `opscrew provision`") ?? -1;
    const restart = result.remediation?.indexOf("systemctl restart opscrew-firewall.service") ?? -1;
    expect(provision).toBeGreaterThan(-1);
    expect(restart).toBeGreaterThan(provision);
    expect(result.remediation).toContain(
      "), `systemctl restart opscrew-firewall.service` loads them again as written in /etc/opscrew/firewall.nft. Then run `opscrew secure` again.",
    );
    expect(result.remediation).not.toContain("edit /etc/opscrew/firewall.nft");
    expect(result.remediation).not.toContain("nft -f");
    expect(result.remediation).not.toContain("nftables.conf");
  });

  it("fails a range of the plan's that the live table lacks", () => {
    // The server was set up before Cloudflare added a range the plan has now.
    const added = "104.16.0.0/13";
    const result = evaluate(plan(), [...CLOUDFLARE, added], answer(listing(BEHIND)));
    expect(result.status).toBe("fail");
    expect(result.message).toContain(`ports 80 and 443 don't accept ${added}, which the plan does`);
  });

  it("fails when the plan's web networks can't be read", () => {
    const result = evaluate(plan(), undefined, answer(listing(BEHIND)));
    expect(result.status).toBe("fail");
    expect(result.message).toContain(`${plan().infra.dir}/terraform.tfvars.json`);
    expect(result.remediation).toContain("opscrew provision");
  });

  it("reads the plan's web networks from the environment's committed tfvars", async () => {
    const root = await mkdtemp(join(tmpdir(), "opscrew-server-firewall-"));
    const deployPlan = plan();
    expect(await plannedWebSources(root, deployPlan)).toBeUndefined();
    await commitTfvars(root, deployPlan, { http_allowed_cidrs: CLOUDFLARE });
    expect(await plannedWebSources(root, deployPlan)).toEqual(CLOUDFLARE);
    for (const wrong of [{}, { http_allowed_cidrs: "0.0.0.0/0" }, { http_allowed_cidrs: [1] }]) {
      await commitTfvars(root, deployPlan, wrong);
      expect(await plannedWebSources(root, deployPlan)).toBeUndefined();
    }
  });

  it("is held by `opscrew secure` to the committed networks, not the live ones", async () => {
    const root = await mkdtemp(join(tmpdir(), "opscrew-secure-firewall-"));
    const deps = await createTestPhaseDeps({ root });
    const deployPlan = plan();
    await writeArtifact("plan", deps.paths.files.plan, deployPlan);
    await recordServerAddress(deps.paths, SERVER);
    await commitTfvars(root, deployPlan, { http_allowed_cidrs: CLOUDFLARE });
    const firewall = async (rules: ServerFirewallRules) => {
      const remote: RemoteExec = {
        host: SERVER.ipv4,
        async run(command) {
          return command.includes("nft list table")
            ? answer(listing(rules))
            : answer("", 127, "not in this test");
        },
      };
      const result = await runSecure(deps, {
        scanners: [],
        remote,
        tcpConnect: async () => false,
      });
      return result.hostChecks.find((check) => check.id === "server-firewall");
    };
    expect(await firewall(BEHIND)).toMatchObject({ status: "pass" });
    const stray = await firewall({ ...BEHIND, webSources: [...CLOUDFLARE, "198.51.100.0/24"] });
    expect(stray).toMatchObject({ status: "fail" });
    expect(stray?.message).toContain("198.51.100.0/24");
  });

  it("fails a server whose rules were changed, naming what differs and saying what to do", () => {
    const deployPlan = plan({ httpAllowedFrom: "any" });
    // A database port opened at the end of the input chain.
    const added = evaluate(
      deployPlan,
      WORLD,
      answer(
        listing(OPEN).replace(
          "\t}\n\n\tchain forward",
          "\t\ttcp dport 3306 accept\n\t}\n\n\tchain forward",
        ),
      ),
    );
    expect(added).toMatchObject({ status: "fail", severity: "critical" });
    expect(added.message).toContain("tcp dport 3306 accept");
    expect(added.remediation).toContain("systemctl restart opscrew-firewall.service");
    expect(added.remediation).toContain("opscrew secure");

    // SSH from everywhere although the plan allows two networks.
    const ssh = evaluate(deployPlan, WORLD, answer(listing({ ...OPEN, sshSources: WORLD })));
    expect(ssh.status).toBe("fail");
    expect(ssh.message).toContain("meta nfproto ipv4 tcp dport 22 accept");
    expect(ssh.message).toContain("ip saddr 203.0.113.7 tcp dport 22 accept");

    // Default accept instead of default drop.
    const accepting = evaluate(
      deployPlan,
      WORLD,
      answer(listing(OPEN).replace("policy drop;", "policy accept;")),
    );
    expect(accepting.status).toBe("fail");
    expect(accepting.message).toContain("doesn't drop by default");

    // Docker's published ports no longer dropped from outside.
    const forward = evaluate(
      deployPlan,
      WORLD,
      answer(listing(OPEN).replace("\t\tct direction original ct status dnat drop\n", "")),
    );
    expect(forward.status).toBe("fail");
    expect(forward.message).toContain("ct direction original ct status dnat drop");
  });

  it("opens WireGuard's port only where the plan uses it", () => {
    const deployPlan = plan({ httpAllowedFrom: "any" }, 51820);
    const rules = { ...OPEN, wireguardPort: 51820 };
    expect(evaluate(deployPlan, WORLD, answer(listing(rules))).status).toBe("pass");
    expect(evaluate(deployPlan, WORLD, answer(listing(OPEN))).status).toBe("fail");
    const without = evaluate(plan({ httpAllowedFrom: "any" }), WORLD, answer(listing(rules)));
    expect(without.status).toBe("fail");
    expect(without.message).toContain("udp dport 51820 accept");
  });

  it("fails a server without OpsCrew's table, or whose table can't be read", () => {
    const missing = evaluate(
      plan(),
      CLOUDFLARE,
      answer(
        "",
        1,
        "Error: No such file or directory\nlist table inet opscrew-firewall\n^^^^^^^^^^^^^^\n",
      ),
    );
    expect(missing.status).toBe("fail");
    expect(missing.message).toContain("no firewall of OpsCrew's");
    expect(missing.remediation).toContain("systemctl restart opscrew-firewall.service");
    const unread = evaluate(
      plan(),
      CLOUDFLARE,
      answer("", 125, "docker: Cannot connect to the Docker daemon\n"),
    );
    expect(unread.status).toBe("fail");
    expect(unread.message).toContain("Cannot connect to the Docker daemon");
  });
});
