// biome-ignore-all lint/suspicious/noTemplateCurlyInString: templatefile's placeholders, not JavaScript templates.
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { DeployPlanSchema } from "@opscrew/plan-schema";
import { describe, expect, it, vi } from "vitest";
import {
  blockingPolicyFailures,
  evaluatePlanPolicies,
  existingOwnFirewallServers,
  serverFirewallUpdates,
} from "./index";

// A provider with no cloud firewall whose server's own firewall is the first step of its
// startup-script first boot, as Kamatera's is; built on Hetzner's definition so every other fact
// stays real, and alone in the registry so no other provider's checks run.
vi.mock("@opscrew/providers", async (importActual) => {
  const actual = await importActual<typeof import("@opscrew/providers")>();
  const hetzner = actual.cloudProvider("hetzner");
  const own = {
    ...hetzner,
    offering: { ...hetzner.offering, deleteProtection: false },
    terraform: { ...hetzner.terraform, serverResourceType: "own_server", firewallResourceType: "" },
    texts: {
      ...hetzner.texts,
      secops: {
        ...hetzner.texts.secops,
        firewallCheck: "server",
        rules: () => [],
        attached: () => false,
        attachedText: "Cloud firewall: none; server firewall: on.",
        unattachedText: "Cloud firewall: none; server firewall: off.",
      },
    },
  };
  return { ...actual, CLOUD_PROVIDERS: [own] };
});

/** OpsCrew's shared first-boot templates, as iac-templates adds them to the server's module. */
const shared = (name: string) =>
  readFileSync(
    fileURLToPath(new URL(`../../../iac-templates/shared/${name}`, import.meta.url)),
    "utf8",
  ).replace(/\r\n/g, "\n");

const WORLD = ["0.0.0.0/0", "::/0"];
const CLOUDFLARE = ["173.245.48.0/20", "2400:cb00::/32"];

/** The networks the module passes the server firewall's step. */
interface Networks {
  ssh?: string[];
  web?: string[];
  wireguard?: number;
}

/**
 * The startup script the module renders with `templatefile`: the wrapper with the server
 * firewall's step first, or without it (`firewall: false`), as a provider with a cloud firewall
 * would have it.
 */
function startupScript({ ssh = WORLD, web = WORLD, wireguard }: Networks, firewall = true) {
  const step = shared("server-firewall.sh.tftpl")
    .replace("${ssh_sources}", ssh.join(" "))
    .replace("${web_sources}", web.join(" "))
    .replace("${wireguard_port}", wireguard === undefined ? "" : String(wireguard));
  return shared("first-boot.sh.tftpl")
    .replace("${server_firewall}", firewall ? step : "")
    .replace("${cloud_config_b64}", Buffer.from("#cloud-config\n").toString("base64"));
}

/** What the plan gives a server that already exists: the root's networks and its module call. */
interface Planned extends Networks {
  /** The module call's `web` (an extra server's is false); none for the app's server. */
  webServer?: boolean;
  /** The module call's name: `server`, the app's, by default. */
  module?: string;
}

/**
 * A plan's JSON with a server, its startup script `script` (none: no script at all), and what the
 * plan does to it (`actions`: created by default). A server the plan keeps has the script it was
 * created with in its change's `before` too (the module ignores changes to it). `planned` gives the
 * root's `ssh_allowed_cidrs` and `http_allowed_cidrs` and the module call's `wireguard_port` and
 * `web`; `null` leaves the root's variables and module calls out.
 */
function planJson(script?: string, actions: string[] = ["create"], planned: Planned | null = {}) {
  const module = planned?.module ?? "server";
  const address = `module.${module}.own_server.this`;
  const values: Record<string, unknown> = {
    name: "shop",
    ssh_keys: ["deploy"],
    ...(script === undefined ? {} : { startup_script: script }),
  };
  const existing = !actions.includes("create");
  const expressions = {
    ssh_allowed_cidrs: { references: ["var.ssh_allowed_cidrs"] },
    ...(planned?.wireguard === undefined
      ? {}
      : { wireguard_port: { constant_value: planned.wireguard } }),
    ...(planned?.webServer === undefined ? {} : { web: { constant_value: planned.webServer } }),
  };
  return {
    ...(planned === null
      ? {}
      : {
          variables: {
            ssh_allowed_cidrs: { value: planned.ssh ?? WORLD },
            http_allowed_cidrs: { value: planned.web ?? WORLD },
          },
          configuration: {
            root_module: { module_calls: { [module]: { source: "../modules/own", expressions } } },
          },
        }),
    planned_values: {
      root_module: {
        child_modules: [
          {
            address: `module.${module}`,
            resources: [{ address, mode: "managed", type: "own_server", name: "this", values }],
          },
        ],
      },
    },
    resource_changes: [
      {
        address,
        change: {
          actions,
          ...(existing ? { before: { ...values } } : {}),
          after_unknown: existing ? {} : { id: true },
        },
      },
    ],
  };
}

/** A deploy plan: SSH from `sshAllowedCidrs`, proxied through Cloudflare or not, a network. */
function deployPlan(o: { sshAllowedCidrs?: string[]; proxied?: boolean; wireguard?: number } = {}) {
  return DeployPlanSchema.parse({
    schemaVersion: 1,
    createdAt: "2026-11-27T12:00:00.000Z",
    updatedAt: "2026-11-27T12:00:00.000Z",
    app: { name: "shop", port: 3000, healthPath: "/health", env: [] },
    target: {
      provider: "hetzner",
      mode: "vps-compose",
      location: "nbg1",
      serverType: "cx23",
      backups: false,
    },
    services: [],
    externalServices: [],
    cost: {
      monthly: { amount: 7.59, currency: "EUR" },
      breakdown: [{ item: "server", monthly: { amount: 7.59, currency: "EUR" } }],
      pricesIncludeVat: false,
      source: "static",
      asOf: "2026-11-27T00:00:00.000Z",
    },
    codeChanges: [],
    infra: {},
    dns: {
      provider: "cloudflare",
      domain: "shop.example.com",
      zone: "example.com",
      proxied: o.proxied ?? false,
    },
    cicd: { provider: "github-actions", registry: "ghcr", branch: "main" },
    security: o.sshAllowedCidrs === undefined ? {} : { sshAllowedCidrs: o.sshAllowedCidrs },
    ...(o.wireguard === undefined
      ? {}
      : {
          network: {
            range: "10.200.4.0/24",
            members: [
              {
                name: "app",
                address: "10.200.4.1",
                port: o.wireguard,
                publicKey: randomBytes(32).toString("base64"),
              },
            ],
          },
        }),
  });
}

function result(results: ReturnType<typeof evaluatePlanPolicies>, policyId: string) {
  return results.find((r) => r.policyId === policyId);
}

describe("a provider whose firewall is the server's own", () => {
  it("passes a server whose first boot starts with OpsCrew's firewall and the plan's networks", () => {
    const plan = deployPlan({ sshAllowedCidrs: ["203.0.113.7/32"], wireguard: 51820 });
    const results = evaluatePlanPolicies(
      planJson(startupScript({ ssh: ["203.0.113.7/32"], wireguard: 51820 })),
      plan,
    );
    expect(result(results, "firewall-attached")).toMatchObject({
      passed: true,
      severity: "high",
      message: "Cloud firewall: none; server firewall: on.",
      resource: "module.server.own_server.this",
    });
    expect(result(results, "ssh-not-public")?.passed).toBe(true);
    expect(result(results, "no-open-admin-ports")).toMatchObject({ passed: true });
    expect(result(results, "no-open-admin-ports")?.message).toContain("UDP 51820");
    expect(blockingPolicyFailures(results)).toEqual([]);
    // No cloud firewall is looked for: no finding says the plan creates a server without one.
    expect(results.filter((r) => r.policyId === "firewall-attached")).toHaveLength(1);
  });

  it("fails a server whose first boot doesn't set up the firewall, or that has no first boot", () => {
    for (const json of [planJson(startupScript({}, false)), planJson()]) {
      const results = evaluatePlanPolicies(json, deployPlan());
      expect(result(results, "firewall-attached")).toMatchObject({
        passed: false,
        message: "Cloud firewall: none; server firewall: off.",
      });
      expect(blockingPolicyFailures(results).map((r) => r.policyId)).toEqual(["firewall-attached"]);
      // Nothing to read the ports from.
      expect(result(results, "no-open-admin-ports")).toBeUndefined();
    }
  });

  it("fails a firewall step whose networks can't be read", () => {
    const script = startupScript({}).replace(/^web_sources=.*\n/m, "");
    const results = evaluatePlanPolicies(planJson(script), deployPlan());
    expect(result(results, "firewall-attached")?.passed).toBe(false);
  });

  it("holds SSH to the plan's networks", () => {
    const results = evaluatePlanPolicies(
      planJson(startupScript({ ssh: WORLD })),
      deployPlan({ sshAllowedCidrs: ["203.0.113.7/32"] }),
    );
    expect(result(results, "ssh-not-public")).toMatchObject({ passed: false, severity: "high" });
    // Public SSH closed: no SSH rule at all.
    const closed = evaluatePlanPolicies(
      planJson(startupScript({ ssh: [] })),
      deployPlan({ sshAllowedCidrs: [] }),
    );
    expect(result(closed, "ssh-not-public")?.passed).toBe(true);
  });

  it("holds the web ports to Cloudflare's ranges when the site is proxied", () => {
    const proxied = deployPlan({ proxied: true });
    const open = evaluatePlanPolicies(planJson(startupScript({ web: WORLD })), proxied);
    expect(result(open, "origin-cloudflare-only")).toMatchObject({ passed: false });
    expect(result(open, "origin-cloudflare-only")?.message).toContain("tcp/80, tcp/443, udp/443");
    const held = evaluatePlanPolicies(planJson(startupScript({ web: CLOUDFLARE })), proxied);
    expect(result(held, "origin-cloudflare-only")?.passed).toBe(true);
    expect(blockingPolicyFailures(held)).toEqual([]);
  });

  it("opens WireGuard's port only where the plan uses it", () => {
    const results = evaluatePlanPolicies(
      planJson(startupScript({ wireguard: 51820 })),
      deployPlan(),
    );
    expect(result(results, "no-open-admin-ports")).toMatchObject({ passed: false });
    expect(result(results, "no-open-admin-ports")?.message).toContain("udp/51820");
  });

  // The module ignores changes to the startup script, so a server that exists keeps the script it
  // was created with: the plan can't change its firewall, so it may not change its networks.
  it("passes a server that already exists when its first boot's networks are the plan's", () => {
    const networks = { ssh: ["203.0.113.7/32"], web: CLOUDFLARE, wireguard: 51820 };
    const plan = deployPlan({ sshAllowedCidrs: networks.ssh, proxied: true, wireguard: 51820 });
    for (const actions of [["no-op"], ["update"]]) {
      const results = evaluatePlanPolicies(
        planJson(startupScript(networks), actions, networks),
        plan,
      );
      expect(blockingPolicyFailures(results), actions[0]).toEqual([]);
      const attached = result(results, "firewall-attached");
      expect(attached).toMatchObject({ passed: true, resource: "module.server.own_server.this" });
      expect(attached?.message).toContain("Cloud firewall: none; server firewall: on.");
      expect(attached?.message).toContain("`opscrew secure`");
      expect(result(results, "server-firewall-as-planned")).toMatchObject({
        passed: true,
        severity: "critical",
        resource: "module.server.own_server.this",
      });
      // Its rules are its first boot's, held to the plan's networks, not checked as new ones.
      for (const policy of ["ssh-not-public", "no-open-admin-ports", "origin-cloudflare-only"]) {
        expect(result(results, policy), policy).toBeUndefined();
      }
    }
  });

  it("holds the networks in any order, as the firewall's rules don't depend on it", () => {
    const stored = startupScript({ ssh: ["203.0.113.7/32", "198.51.100.0/24"] });
    const json = planJson(stored, ["no-op"], { ssh: ["198.51.100.0/24", "203.0.113.7/32"] });
    expect(blockingPolicyFailures(evaluatePlanPolicies(json, deployPlan()))).toEqual([]);
  });

  it("fails critical when the plan changes the networks of a server that already exists", () => {
    const stored = startupScript({ ssh: WORLD, web: WORLD });
    const cases: [Planned, string[]][] = [
      // SSH narrowed to one network.
      [
        { ssh: ["203.0.113.7/32"] },
        [
          "SSH: the server accepts 0.0.0.0/0 and ::/0, which the plan doesn't, and the plan adds 203.0.113.7/32",
        ],
      ],
      // The web ports held to Cloudflare's ranges.
      [
        { web: CLOUDFLARE },
        [
          "the web ports: the server accepts 0.0.0.0/0 and ::/0, which the plan doesn't, and the plan adds 173.245.48.0/20 and 2400:cb00::/32",
        ],
      ],
      // A private network added: its WireGuard port.
      [
        { wireguard: 51820 },
        ["WireGuard: the plan opens UDP port 51820, which the server doesn't"],
      ],
    ];
    for (const [planned, said] of cases) {
      const results = evaluatePlanPolicies(planJson(stored, ["no-op"], planned), deployPlan());
      const failed = result(results, "server-firewall-as-planned");
      expect(failed).toMatchObject({
        passed: false,
        severity: "critical",
        title: "The server's own firewall has the plan's networks",
        resource: "module.server.own_server.this",
      });
      for (const text of said) expect(failed?.message).toContain(text);
      expect(failed?.message).toContain("set at its first boot");
      expect(failed?.message).toContain("/etc/opscrew/firewall-networks.json");
      expect(failed?.message).toContain("opscrew/plan.yaml");
      expect(blockingPolicyFailures(results).map((r) => r.policyId)).toEqual([
        "server-firewall-as-planned",
      ]);
    }
    // The private network's port the plan no longer gives the server, or another port.
    const networked = startupScript({ wireguard: 51820 });
    const gone = result(
      evaluatePlanPolicies(planJson(networked, ["update"], {}), deployPlan()),
      "server-firewall-as-planned",
    );
    expect(gone?.message).toContain(
      "WireGuard: the server opens UDP port 51820, which the plan doesn't",
    );
    const moved = result(
      evaluatePlanPolicies(planJson(networked, ["update"], { wireguard: 51821 }), deployPlan()),
      "server-firewall-as-planned",
    );
    expect(moved?.message).toContain(
      "WireGuard: the server opens UDP port 51820 and the plan 51821",
    );
  });

  it("holds an extra server, whose module call closes the web ports, to no web networks", () => {
    const extra = { module: "server_db", webServer: false, wireguard: 51820 };
    const closed = startupScript({ web: [], wireguard: 51820 });
    const results = evaluatePlanPolicies(planJson(closed, ["no-op"], extra), deployPlan());
    expect(result(results, "server-firewall-as-planned")).toMatchObject({
      passed: true,
      resource: "module.server_db.own_server.this",
    });
    const open = startupScript({ web: WORLD, wireguard: 51820 });
    const failed = evaluatePlanPolicies(planJson(open, ["no-op"], extra), deployPlan());
    expect(result(failed, "server-firewall-as-planned")?.passed).toBe(false);
  });

  it("reads the first boot's networks from the change's `before`, which the masked plan keeps", () => {
    const narrowed = { ssh: ["203.0.113.7/32"] };
    const json = planJson(startupScript({ ssh: WORLD }), ["no-op"], narrowed);
    // Whatever the planned values hold, the server keeps the script it was created with.
    const planned = json.planned_values.root_module.child_modules[0]?.resources[0];
    if (planned !== undefined) planned.values.startup_script = startupScript(narrowed);
    const results = evaluatePlanPolicies(json, deployPlan());
    expect(result(results, "server-firewall-as-planned")?.passed).toBe(false);
  });

  it("fails critical when the first boot's script or the plan's networks can't be read", () => {
    const unreadable = startupScript({}).replace(/^web_sources=.*\n/m, "");
    for (const json of [
      planJson(undefined, ["no-op"]),
      planJson(startupScript({}, false), ["no-op"]),
      planJson(unreadable, ["update"]),
    ]) {
      const failed = result(evaluatePlanPolicies(json, deployPlan()), "server-firewall-as-planned");
      expect(failed).toMatchObject({ passed: false, severity: "critical" });
      expect(failed?.message).toContain("can't read the networks its own firewall");
      expect(failed?.message).toContain("`opscrew secure`");
    }
    const unplanned = result(
      evaluatePlanPolicies(planJson(startupScript({}), ["no-op"], null), deployPlan()),
      "server-firewall-as-planned",
    );
    expect(unplanned).toMatchObject({ passed: false, severity: "critical" });
    expect(unplanned?.message).toContain("can't read the networks this plan gives");
  });

  it("passes a server the plan imports, whose script its provider never gives back, and says secure checks it", () => {
    const json = planJson(undefined, ["no-op"]);
    const change = json.resource_changes[0]?.change as Record<string, unknown>;
    change.importing = { id: "imported-server-id" };
    const results = evaluatePlanPolicies(json, deployPlan());
    for (const id of ["server-firewall-as-planned", "firewall-attached"]) {
      const imported = result(results, id);
      expect(imported, id).toMatchObject({ passed: true });
      expect(imported?.message, id).toContain("imports the server");
      expect(imported?.message, id).toMatch(/`opscrew secure` (checks|reads) the rules live/);
    }
    // Without `importing`, the same plan fails as before.
    delete change.importing;
    const kept = evaluatePlanPolicies(json, deployPlan());
    expect(result(kept, "server-firewall-as-planned")?.passed).toBe(false);
  });

  it("reads only the server's own module call, whatever another call's expressions say", () => {
    const json = planJson(startupScript({}), ["no-op"]);
    const calls = json.configuration?.root_module.module_calls as Record<string, unknown>;
    // An unrelated module whose `web` and `wireguard_port` are references, not constants.
    calls.other = {
      source: "../modules/other",
      expressions: { web: { references: ["var.web"] }, wireguard_port: { references: ["x"] } },
    };
    const results = evaluatePlanPolicies(json, deployPlan());
    expect(result(results, "server-firewall-as-planned")?.passed).toBe(true);
  });

  it("still fails a server that exists without the firewall's step", () => {
    for (const json of [
      planJson(startupScript({}, false), ["no-op"]),
      planJson(undefined, ["update"]),
    ]) {
      const results = evaluatePlanPolicies(json, deployPlan());
      expect(result(results, "firewall-attached")).toMatchObject({
        passed: false,
        message: "Cloud firewall: none; server firewall: off.",
      });
    }
  });

  it("checks the script of a server the plan creates, or replaces, as the plan's", () => {
    const narrowed = deployPlan({ sshAllowedCidrs: ["203.0.113.7/32"] });
    for (const actions of [["create"], ["delete", "create"], ["create", "delete"]]) {
      const results = evaluatePlanPolicies(
        planJson(startupScript({ ssh: WORLD }), actions),
        narrowed,
      );
      expect(result(results, "ssh-not-public"), actions.join()).toMatchObject({ passed: false });
      expect(blockingPolicyFailures(results).map((r) => r.policyId)).toEqual(["ssh-not-public"]);
    }
  });

  it("compares against /etc/opscrew/firewall-networks.json when supplied, falling back to first-boot otherwise", () => {
    const narrowed = ["203.0.113.7/32"];
    const address = "module.server.own_server.this";
    // First-boot script still has WORLD, but /etc/opscrew/firewall-networks.json records narrowed SSH.
    const json = planJson(startupScript({ ssh: WORLD, web: WORLD }), ["no-op"], {
      ssh: narrowed,
      web: WORLD,
    });
    const matched = evaluatePlanPolicies(json, deployPlan({ sshAllowedCidrs: narrowed }), {
      serverFirewallNetworks: { [address]: { ssh: narrowed, web: WORLD, wireguard: "" } },
    });
    expect(blockingPolicyFailures(matched)).toEqual([]);
    expect(result(matched, "server-firewall-as-planned")).toMatchObject({
      passed: true,
      message: expect.stringContaining("/etc/opscrew/firewall-networks.json"),
    });
    expect(
      serverFirewallUpdates(json, {
        serverFirewallNetworks: { [address]: { ssh: narrowed, web: WORLD, wireguard: "" } },
      }),
    ).toEqual([]);

    // When /etc/opscrew/firewall-networks.json differs from the plan, serverFirewallUpdates lists it.
    const stale = serverFirewallUpdates(json, {
      serverFirewallNetworks: {
        [address]: { ssh: ["198.51.100.1/32"], web: WORLD, wireguard: "" },
      },
    });
    expect(stale).toHaveLength(1);
    expect(stale[0]).toMatchObject({
      address,
      moduleCall: "server",
      server: "app",
      planned: { ssh: narrowed, web: WORLD, wireguard: "" },
    });

    // Without serverFirewallNetworks, falls back to first-boot script and detects the difference.
    const fallback = serverFirewallUpdates(json);
    expect(fallback).toHaveLength(1);
    expect(fallback[0]?.current).toEqual({ ssh: WORLD, web: WORLD, wireguard: "" });
  });

  it("passes server-firewall-as-planned when in-place host plan is enabled, while still enforcing port and SSH policies", () => {
    const narrowed = ["203.0.113.7/32"];
    const address = "module.server.own_server.this";
    const json = planJson(startupScript({ ssh: WORLD, web: WORLD }), ["no-op"], {
      ssh: narrowed,
      web: CLOUDFLARE,
      wireguard: 51820,
    });
    const plan = deployPlan({ sshAllowedCidrs: narrowed, proxied: true, wireguard: 51820 });
    const passed = evaluatePlanPolicies(json, plan, {
      inPlaceServerFirewallAddresses: new Set([address]),
    });
    expect(result(passed, "server-firewall-as-planned")).toMatchObject({
      passed: true,
      message: expect.stringContaining("SHA-256 hash-approved host plan"),
    });
    expect(result(passed, "ssh-not-public")?.passed).toBe(true);
    expect(result(passed, "origin-cloudflare-only")?.passed).toBe(true);
    expect(result(passed, "no-open-admin-ports")?.passed).toBe(true);
    expect(blockingPolicyFailures(passed)).toEqual([]);

    // Still fails ssh-not-public if the planned networks open SSH to the world against plan.yaml.
    const tampered = planJson(startupScript({ ssh: narrowed, web: WORLD }), ["no-op"], {
      ssh: WORLD,
      web: WORLD,
    });
    const refused = evaluatePlanPolicies(tampered, deployPlan({ sshAllowedCidrs: narrowed }), {
      inPlaceServerFirewallAddresses: new Set([address]),
    });
    expect(result(refused, "server-firewall-as-planned")?.passed).toBe(true);
    expect(result(refused, "ssh-not-public")?.passed).toBe(false);
    expect(blockingPolicyFailures(refused).map((r) => r.policyId)).toEqual(["ssh-not-public"]);
  });

  it("fails closed when serverFirewallReadErrors is set, even if the first-boot script matches the plan", () => {
    const address = "module.server.own_server.this";
    const json = planJson(startupScript({ ssh: WORLD, web: WORLD }), ["no-op"], {
      ssh: WORLD,
      web: WORLD,
    });
    const failed = evaluatePlanPolicies(json, deployPlan(), {
      serverFirewallReadErrors: { [address]: "SSH timed out" },
    });
    const check = result(failed, "server-firewall-as-planned");
    expect(check).toMatchObject({
      passed: false,
      severity: "critical",
      resource: address,
    });
    expect(check?.message).toContain("SSH timed out");
    expect(check?.message).toContain("will not fall back to the first-boot script");
    expect(blockingPolicyFailures(failed).map((r) => r.policyId)).toEqual([
      "server-firewall-as-planned",
    ]);
  });

  it("lists existing own-firewall servers for app, extra servers, and retarget previous", () => {
    expect(existingOwnFirewallServers(planJson(startupScript({}), ["no-op"]))).toEqual([
      {
        address: "module.server.own_server.this",
        moduleCall: "server",
        server: "app",
        planned: { ssh: WORLD, web: WORLD, wireguard: "" },
      },
    ]);
    expect(
      existingOwnFirewallServers(
        planJson(startupScript({ web: [] }), ["no-op"], {
          module: "server_db",
          webServer: false,
          wireguard: 51820,
        }),
      ),
    ).toEqual([
      {
        address: "module.server_db.own_server.this",
        moduleCall: "server_db",
        server: "db",
        planned: { ssh: WORLD, web: [], wireguard: "51820" },
      },
    ]);
    expect(
      existingOwnFirewallServers(
        planJson(startupScript({}), ["no-op"], { module: "server_previous" }),
      ),
    ).toEqual([
      {
        address: "module.server_previous.own_server.this",
        moduleCall: "server_previous",
        server: "previous",
        planned: { ssh: WORLD, web: WORLD, wireguard: "" },
      },
    ]);
  });
});
