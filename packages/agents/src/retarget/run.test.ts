import { existsSync } from "node:fs";
import { readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { FAKE_ZONE_ID } from "@opscrew/connector-cloudflare/testing";
import type { CommandResult } from "@opscrew/contracts";
import {
  findExecutable,
  fingerprintSha256,
  generateP256,
  selfSignedClientCertificate,
} from "@opscrew/core";
import { fakeSecret } from "@opscrew/core/testing";
import { DeployPlanSchema, readArtifact, writeArtifact } from "@opscrew/plan-schema";
import { describe, expect, it } from "vitest";
import { ROLLING_NOTE } from "../design/strategy";
import { staleServerFirewallPlanJson } from "../provision/__fixtures__/stale-server-firewall";
import { STORAGE_KEY_VARS } from "../provision/storage";
import { readServerAddresses, serverAddressesFile } from "../shared";
import {
  APP,
  BUILT_IMAGE,
  DOMAIN,
  HOST_KEY,
  type MoveHarness,
  makeFacts,
  moveHarness,
  NEW_SERVERS,
  OLD_IPV4,
  OLD_IPV6,
  planJsonFor,
  STRIPE,
  TOKENS,
} from "../testing";
import { sitePlan } from "../testing/serverless";
import { withBucket } from "../testing/storage";
import {
  caught,
  crashAfter,
  crashOn,
  drive,
  everythingPrinted,
  expectGated,
  moveOnDisk as move,
  run,
  trail,
} from "./__fixtures__/assert";
import { abortRetarget } from "./abort";
import type { MoveSession } from "./session";
import type { RetargetSummary } from "./types";
import { maintenanceWindow } from "./window";

const applies = (h: MoveHarness) => h.events.filter((e) => e.type === "apply");
const ops = (h: MoveHarness, host: string, op: string) =>
  h.events.filter((e) => e.type === "remote" && e.host === host && e.op === op).length;
/** How often the fakes saw `op` on `host` once the maintenance window was asked for. */
const windowOps = (h: MoveHarness, host: string, op: string) => {
  const asked = h.events.findIndex(
    (e) => e.type === "approval" && e.kind === "remote-exec" && e.title.startsWith("Maintenance"),
  );
  return h.events
    .slice(asked === -1 ? h.events.length : asked)
    .filter((e) => e.type === "remote" && e.host === host && e.op === op).length;
};

const fail = (stderr = "boom"): CommandResult => ({ exitCode: 1, stdout: "", stderr });

function windowStarted(h: MoveHarness): boolean {
  return h.events.some(
    (e) => e.type === "approval" && e.kind === "remote-exec" && e.title.startsWith("Maintenance"),
  );
}

describe.skipIf(!findExecutable("git"))("runRetarget", () => {
  it("US1: moves a Hetzner deployment with Cloudflare and Postgres to DigitalOcean", async () => {
    const h = await moveHarness();
    let summary: RetargetSummary | undefined;
    const result = await run(h, {
      confirmStart: async (s) => {
        summary = s;
        return true;
      },
    });
    expect(result).toMatchObject({ step: "switched", done: true });
    expect(result.next.join(" ")).toContain("opscrew retarget --finish");
    expect(summary).toMatchObject({
      from: { provider: "hetzner" },
      to: { provider: "digitalocean", location: "fra1" },
      data: [{ owner: "db", key: "/var/lib/postgresql/data", bytes: 52_428_800, copy: true }],
      // The first copy and the deploy that starts the app on it (FR-3027) while the app serves;
      // the window: a minute, and the database's dump and restore.
      preCopyMinutes: 8,
      expectedDowntimeMinutes: 2,
    });
    expect(summary?.extraMonthly.currency).toBe("USD");
    expect(summary?.steps).toHaveLength(7);
    expect(summary?.steps[3]).toBe(
      "While your app serves (about 8 minutes): copy its data (50.0 MB) to the new Droplet on DigitalOcean, then start the app there on that copy with the deploy workflow and check it.",
    );
    expect(summary?.steps[4]).toBe(
      "Maintenance window (about 2 minutes): stop the app on the old server on Hetzner Cloud, copy what changed in its data since to the new Droplet on DigitalOcean and start the app there again.",
    );

    const n = h.newServer.ipv4;
    expect(trail(h.events)).toEqual([
      "approve iac-apply",
      "apply moves=3",
      "approve iac-apply",
      "apply creates=4",
      // FR-3027: the new server's deploys wait for the data, from before the secrets point there.
      `${n} mark waiting`,
      "approve github-secrets",
      "dispatch main",
      `${n} stop caddy`,
      // While the old app serves: the database copied by its dump (the new server's Postgres keeps
      // running: its database is restored, not copied), then the image deployed there, without a
      // build, on that copy, the check from outside left to the move: its edge stopped again;
      // once it answered, the app, its workers and cron stop and wait for the window.
      `${n} stop app`,
      `${OLD_IPV4} dump`,
      `${n} empty db`,
      `${n} restore`,
      `${n} mark copied`,
      `dispatch main sha256:${"e".repeat(12)}`,
      `${n} stop caddy`,
      `${n} stop app`,
      `${n} mark waiting`,
      // The window: the database dumped and restored again, the app started again in place, no
      // workflow run; once it answers, the marker goes.
      "approve remote-exec",
      `${OLD_IPV4} stop app`,
      `${OLD_IPV4} dump`,
      `${OLD_IPV4} stop db`,
      `${n} stop app`,
      `${n} empty db`,
      `${n} restore`,
      `${n} start app`,
      `${n} remove marker`,
      "approve iac-apply",
      "apply updates=2",
      `${n} start caddy`,
    ]);
    // No push deploy ran during the first copy or the window: they were paused, and resumed
    // after each; no workflow ran inside the window.
    const actions = h.audit.entries.map((e) => e.action);
    const pauses = actions.flatMap((a, i) => (a.startsWith("pause the deploys of") ? [i] : []));
    const resumes = actions.flatMap((a, i) => (a.startsWith("resume the deploys of") ? [i] : []));
    expect(pauses).toHaveLength(2);
    expect(resumes).toHaveLength(2);
    expect(pauses[0]).toBeLessThan(actions.indexOf("dump database"));
    expect(resumes[0]).toBeGreaterThan(actions.indexOf("deploy workflow"));
    const opened = actions.indexOf("maintenance window");
    expect(opened).toBeGreaterThan(resumes[0] ?? Infinity);
    expect(actions.slice(opened)).not.toContain("dispatch workflow");
    expect(h.github.variables.has("OPSCREW_DEPLOY_PAUSED")).toBe(false);
    // The dump volume is gone from both servers.
    for (const ip of [OLD_IPV4, n]) {
      expect(h.hosts.docker(ip).volumes.has("opscrew-move-dump-shop")).toBe(false);
    }
    // Without a release service in the new server's compose file, no release runs in the window.
    expect(ops(h, n, "release")).toBe(0);
    const window = h.handler.requests.find((r) => r.title.startsWith("Maintenance window"));
    expect(window?.details).not.toContain("release");
    expect(window?.details).not.toContain("--clean");
    expectGated(h.events);
    // The DNS switch was planned before the maintenance window (no plan fails while offline).
    const planned = h.events.findLastIndex((e) => e.type === "plan");
    const windowAt = h.events.findIndex((e) => e.type === "remote" && e.op === "dump");
    expect(planned).toBeLessThan(windowAt);

    const plan = await readArtifact("plan", h.paths.files.plan);
    expect(plan.target).toMatchObject({ provider: "digitalocean", location: "fra1" });
    expect(plan.cost.monthly.currency).toBe("USD");
    expect(plan.retarget).toMatchObject({
      step: "switched",
      from: { target: { provider: "hetzner", serverType: "cx23" } },
    });
    expect(plan.retarget?.oldAppStoppedAt).toBeDefined();
    expect(plan.deployment).toMatchObject({ url: `https://${DOMAIN}` });
    // Both servers' addresses are in OpsCrew's local state, never in opscrew/plan.yaml.
    const fresh = { ipv4: n, ipv6: h.newServer.ipv6 };
    expect(await readServerAddresses(h.paths)).toEqual({
      schemaVersion: 1,
      deployment: fresh,
      retarget: { from: { ipv4: OLD_IPV4, ipv6: OLD_IPV6 }, next: fresh },
    });
    const committed = await readFile(h.paths.files.plan, "utf8");
    for (const ip of [OLD_IPV4, OLD_IPV6, n, h.newServer.ipv6]) {
      expect(committed).not.toContain(ip);
    }
    expect(plan.approvals).toHaveLength(3);
    // Honest cost: the plan that creates the new server shows its price; rename and switch none.
    const applyRequests = h.handler.requests.filter((r) => r.kind === "iac-apply");
    expect(applyRequests.map((r) => r.costDelta)).toEqual([
      undefined,
      plan.cost.monthly,
      undefined,
    ]);
    expect(applyRequests[2]?.details).toContain("Cost: unchanged");
    expect(h.hosts.host(n)).toMatchObject({ app: true, caddy: true, db: "orders before the move" });
    expect(h.hosts.host(OLD_IPV4)).toMatchObject({ app: false, caddy: true });
    expect(h.hosts.host(OLD_IPV4).dump).toBeUndefined();
    expect(h.hosts.host(n).dump).toBeUndefined();
    expect(h.engine.dnsServer()?.ipv4).toBe(n);

    expect(h.github.secrets.get("OPSCREW_HOST")).toBe(n);
    expect(h.github.secrets.get("OPSCREW_SSH_KNOWN_HOSTS")).toBe(`${n} ${HOST_KEY}\n`);
    expect(h.github.secrets.get("OPSCREW_APP_ENV")).toContain(STRIPE);
    expect(h.github.runs).toEqual([
      { workflowFile: "opscrew-deploy.yml", ref: "main" },
      {
        workflowFile: "opscrew-deploy.yml",
        ref: "main",
        inputs: { digest: BUILT_IMAGE.slice(BUILT_IMAGE.indexOf("@") + 1), rollback: "false" },
      },
    ]);
    await expect(readFile(h.paths.files.knownHosts, "utf8")).resolves.toContain(n);
    const main = await readFile(join(h.root, "opscrew/infra/prod/main.tf"), "utf8");
    expect(main).toContain('module "server_previous"');
    expect(main).toContain("module.server.ipv4_address");

    const printed = everythingPrinted(h);
    for (const secret of [STRIPE, TOKENS.hetzner, TOKENS.digitalocean, TOKENS.cloudflare]) {
      expect(printed).not.toContain(secret);
    }
    expect(h.audit.entries.map((e) => e.action)).toEqual(
      expect.arrayContaining([
        "retarget started",
        "retarget renamed",
        "retarget created",
        "retarget deployed",
        "retarget migrated",
        "retarget switched",
      ]),
    );
    expect(
      h.audit.entries.filter((e) => e.action.startsWith("retarget ")).map((e) => e.phase),
    ).toEqual(expect.arrayContaining(["retarget"]));
  });

  it("US1: moves a DigitalOcean deployment to Hetzner Cloud", async () => {
    const h = await moveHarness({ from: "digitalocean" });
    const result = await run(h);
    expect(result).toMatchObject({ step: "switched", done: true });
    const n = h.newServer.ipv4;
    expect(trail(h.events).filter((line) => line.startsWith("apply"))).toEqual([
      "apply moves=4",
      "apply creates=3",
      "apply updates=2",
    ]);
    expectGated(h.events);
    const plan = await readArtifact("plan", h.paths.files.plan);
    expect(plan.target).toMatchObject({ provider: "hetzner", image: "ubuntu-24.04" });
    expect(plan.cost.monthly.currency).toBe("EUR");
    expect(plan.retarget?.from.target.provider).toBe("digitalocean");
    expect(h.engine.state.servers.server).toMatchObject({ provider: "hetzner", protected: true });
    expect(h.hosts.host(n).db).toBe("orders before the move");
    const variables = await readFile(join(h.root, "opscrew/infra/prod/variables.tf"), "utf8");
    expect(variables).toContain('variable "delete_protection"');
    expect(variables).not.toContain('variable "previous_delete_protection"');
  });

  it("gives the new server the old server's reverse proxy", async () => {
    const h = await moveHarness();
    const before = await readArtifact("plan", h.paths.files.plan);
    const target = { ...before.target, edge: "nginx" };
    await writeArtifact("plan", h.paths.files.plan, DeployPlanSchema.parse({ ...before, target }));
    crashAfter(h, "started");
    await expect(run(h)).rejects.toThrow("interrupted");
    const moving = await readArtifact("plan", h.paths.files.plan);
    expect(moving.target).toMatchObject({ provider: "digitalocean", edge: "nginx" });
    expect(moving.retarget?.from.target).toMatchObject({ provider: "hetzner", edge: "nginx" });
  });

  it("keeps the provider's backups off on the new server when the user turned them off on the old one", async () => {
    // Found live: a move from a server without backups planned them on at the new provider.
    for (const backups of [false, true]) {
      const h = await moveHarness();
      const before = await readArtifact("plan", h.paths.files.plan);
      const target = { ...before.target, backups };
      await writeArtifact(
        "plan",
        h.paths.files.plan,
        DeployPlanSchema.parse({ ...before, target }),
      );
      crashAfter(h, "started");
      await expect(run(h)).rejects.toThrow("interrupted");
      const moving = await readArtifact("plan", h.paths.files.plan);
      expect(moving.target).toMatchObject({ provider: "digitalocean", backups });
    }
  });

  it.each(["started", "renamed", "created", "deployed", "migrated", "switched"])(
    "SC-503: an interruption after %s resumes and completes the move",
    async (step) => {
      const h = await moveHarness();
      crashAfter(h, step);
      await expect(run(h)).rejects.toThrow("interrupted");
      expect((await move(h))?.step).toBe(step);
      const result = await run(h);
      expect(result).toMatchObject({ step: "switched", done: true });
      // Nothing done twice: one rename, one create, one DNS switch, one copy while the app serves
      // and one in the window, one deploy.
      expect(trail(h.events).filter((line) => line.startsWith("apply"))).toEqual([
        "apply moves=3",
        "apply creates=4",
        "apply updates=2",
      ]);
      expect(ops(h, OLD_IPV4, "dump")).toBe(2);
      // The deploy before the copy, and the one on the data copied while the app serves.
      expect(h.github.runs).toHaveLength(2);
      expectGated(h.events);
      const n = h.newServer.ipv4;
      expect(h.hosts.host(n)).toMatchObject({
        app: true,
        caddy: true,
        db: "orders before the move",
      });
      expect(h.engine.dnsServer()?.ipv4).toBe(n);
    },
  );

  it("an interrupted maintenance window starts the old side first and repeats the copy", async () => {
    const h = await moveHarness();
    const n = h.newServer.ipv4;
    // Killed once the window began (oldAppStoppedAt recorded); it had stopped the app and dumped.
    crashOn(h, "maintenance window");
    await expect(run(h)).rejects.toThrow("interrupted");
    const interrupted = await move(h);
    expect(interrupted).toMatchObject({ step: "deployed" });
    expect(interrupted?.oldAppStoppedAt).toBeDefined();
    Object.assign(h.hosts.host(OLD_IPV4), { app: false });
    h.hosts.docker(OLD_IPV4).addVolume("opscrew-move-dump-shop");
    h.hosts.docker(n).addVolume("opscrew-move-dump-shop");
    h.events.length = 0;

    const result = await run(h);
    expect(result).toMatchObject({ step: "switched", done: true });
    const lines = trail(h.events);
    // The old side's services and app start first; the leftover dump volumes go.
    expect(lines.slice(0, 2)).toEqual([`${OLD_IPV4} start db`, `${OLD_IPV4} start app`]);
    expect(lines).toContain("approve remote-exec");
    expect(ops(h, OLD_IPV4, "dump")).toBe(1);
    expect(h.reporter.text()).toContain("stopped during the maintenance window");
    expect(h.hosts.host(n).db).toBe("orders before the move");
    for (const ip of [OLD_IPV4, n]) {
      expect(h.hosts.docker(ip).volumes.has("opscrew-move-dump-shop")).toBe(false);
    }
  });

  /** A failure of the window at a server operation (`op` on the old or new side), or in Docker. */
  const WINDOW_FAILURES = [
    { what: "stopping the old app", on: "old", op: "stop app" },
    { what: "the dump", on: "old", op: "dump" },
    { what: "stopping the old services", on: "old", op: "stop db" },
    { what: "stopping the new app", on: "new", op: "stop app" },
    { what: "the copy of the dump", on: "new", op: "PUT archive" },
    { what: "emptying the new database", on: "new", op: "empty db" },
    { what: "the restore", on: "new", op: "restore" },
    { what: "deleting the old dump volume", on: "old", op: "DELETE volume" },
    { what: "starting the new app again", on: "new", op: "start app" },
    { what: "the health check", on: "new", op: "health" },
    { what: "removing the move's marker", on: "new", op: "remove marker" },
  ] as const;

  it.each(WINDOW_FAILURES)(
    "FR-506 and SC-2302: a failure of $what rolls back to the old side, its data unchanged; a re-run repeats the window",
    async ({ on, op }) => {
      const h = await moveHarness();
      const n = h.newServer.ipv4;
      const host = on === "old" ? OLD_IPV4 : n;
      let failed = false;
      if (op === "PUT archive" || op === "DELETE volume") {
        // Docker refuses once the window began: a full disk, a lost connection.
        h.hosts.fail = (ip, o) => {
          if (!failed && ip === host && o === "stop app" && windowStarted(h)) {
            failed = true;
            const [method, path] =
              op === "PUT archive" ? ["PUT", /\/archive/] : ["DELETE", /^\/volumes\//];
            h.hosts.docker(host).fail(method, path, 500, `${op} failed`);
          }
          return undefined;
        };
      } else {
        h.hosts.fail = (ip, o) => {
          if (ip !== host || o !== op || !windowStarted(h)) return undefined;
          if (failed && op !== "health") return undefined;
          failed = true;
          return fail(`${op} failed`);
        };
      }
      const oldFiles = [
        ...(h.hosts.docker(OLD_IPV4).folders.get("/srv/data/shop/db")?.files ?? []),
      ];
      const error = await caught(run(h));
      expect(error.message).toContain("The maintenance window failed");
      expect(error.message).toContain("The app on the old server on Hetzner Cloud runs again");
      expect(error.hint).toContain("opscrew retarget");
      const state = await move(h);
      expect(state?.step).toBe("deployed");
      expect(state?.oldAppStoppedAt).toBeUndefined();
      // SC-2302: the old side serves again, with its data as it was.
      expect(h.hosts.host(OLD_IPV4).app).toBe(true);
      expect(h.hosts.host(OLD_IPV4).db).toBe("orders before the move");
      expect([...(h.hosts.docker(OLD_IPV4).folders.get("/srv/data/shop/db")?.files ?? [])]).toEqual(
        oldFiles,
      );
      const running = (ip: string) =>
        [...h.hosts.docker(ip).containers.values()]
          .filter((c) => c.labels["com.docker.compose.service"] === "db")
          .map((c) => c.state);
      expect(running(OLD_IPV4)).toEqual(["running"]);
      // The new side stays stopped, nothing of a part copy on it, until the window runs again;
      // its deploys wait for the data again (FR-3027).
      expect(h.hosts.host(n)).toMatchObject({ app: false, marker: "waiting" });
      expect(applies(h)).toHaveLength(2);
      expect(h.engine.dnsServer()?.ipv4).toBe(OLD_IPV4);
      expect(h.audit.entries).toContainEqual(
        expect.objectContaining({ action: "maintenance window", decision: "refused" }),
      );

      h.hosts.fail = undefined;
      const result = await run(h);
      expect(result).toMatchObject({ step: "switched", done: true });
      expect(h.hosts.host(n).db).toBe("orders before the move");
      expectGated(h.events);
    },
  );

  it("T2306: a service Docker killed when it stopped fails the window before its files are copied", async () => {
    const h = await moveHarness();
    const n = h.newServer.ipv4;
    h.hosts.killed.add(`${OLD_IPV4} db`);
    const error = await caught(run(h));
    expect(error.message).toContain("db did not stop cleanly on the old server on Hetzner Cloud");
    expect(error.message).toContain("The app on the old server on Hetzner Cloud runs again");
    // Stopped with 120 seconds to stop cleanly; nothing of the window reached the new side.
    expect(ops(h, OLD_IPV4, "stop db")).toBe(1);
    expect(windowOps(h, n, "restore")).toBe(0);
    expect(windowOps(h, n, "empty db")).toBe(0);
    expect((await move(h))?.step).toBe("deployed");
    expect(h.hosts.host(OLD_IPV4).app).toBe(true);

    h.hosts.killed.clear();
    expect(await run(h)).toMatchObject({ step: "switched", done: true });
  });

  it("047: moves a database with two logins, loading it owned by app_owner with its grants", async () => {
    const h = await moveHarness({ logins: true, release: true });
    const n = h.newServer.ipv4;
    expect(await run(h)).toMatchObject({ step: "switched", done: true });
    expect(h.hosts.host(n).db).toBe("orders before the move (migrated)");
    // Each load, before the window and in it, is the logins' one: never emptied and restored apart.
    expect(ops(h, n, "load")).toBe(2);
    expect(ops(h, n, "empty db")).toBe(0);
    expect(ops(h, n, "restore")).toBe(0);
    const window = h.handler.requests.find((r) => r.title.startsWith("Maintenance window"));
    expect(window?.details).toContain(
      "recreate the database empty, owned by app_owner, and restore the dump into it (pg_restore --single-transaction), keeping its owners and grants and granting again what the dump lacks",
    );
  });

  it("T831 and FR-3027: with a release command the app starts only on copied data, the command run on it again in the window", async () => {
    const h = await moveHarness({ release: true });
    const n = h.newServer.ipv4;
    const result = await run(h);
    expect(result).toMatchObject({ step: "switched", done: true });
    const lines = trail(h.events);
    // While the old app serves, the deploy of the image there runs the release command on the
    // database's copy and starts the app (no release run of OpsCrew's own); once it answered, it
    // stops and waits for the window.
    const first = lines.indexOf(`${n} restore`);
    expect(lines.slice(first, lines.indexOf("approve remote-exec"))).toEqual([
      `${n} restore`,
      `${n} mark copied`,
      `dispatch main sha256:${"e".repeat(12)}`,
      `${n} stop caddy`,
      `${n} stop app`,
      `${n} mark waiting`,
    ]);
    // The window: the release command on the final data, the app started again in place, no
    // workflow run.
    const from = lines.indexOf(`${OLD_IPV4} stop app`);
    expect(lines.slice(from, lines.indexOf(`${n} remove marker`) + 1)).toEqual([
      `${OLD_IPV4} stop app`,
      `${OLD_IPV4} dump`,
      `${OLD_IPV4} stop db`,
      `${n} stop app`,
      `${n} empty db`,
      `${n} restore`,
      `${n} release`,
      `${n} start app`,
      `${n} remove marker`,
    ]);
    // The old data, migrated forward by the version on the new server, once on the final data.
    expect(h.hosts.host(n)).toMatchObject({ db: "orders before the move (migrated)", app: true });
    const window = h.handler.requests.find((r) => r.title.startsWith("Maintenance window"));
    expect(window?.details).toContain("recreate the database empty and restore the dump");
    expect(window?.details).toContain(
      "run the release command (app.releaseCommand) on the final data, which migrates it to the version deployed there",
    );
    expect(window?.details).toContain(
      "start the app again, its workers and cron, then check its health route",
    );
    expect(window?.details).not.toContain("deploy workflow");
    expect(window?.details).not.toContain("--clean");
    const actions = h.audit.entries.map((e) => e.action);
    const opened = actions.indexOf("maintenance window");
    expect(actions.indexOf("restore database")).toBeLessThan(
      actions.indexOf("let the deploys start the app on its data"),
    );
    expect(actions.indexOf("deploy workflow")).toBeLessThan(opened);
    // The marker goes only once the app answers there on the final data, before the window ends.
    expect(actions.indexOf("remove the move's marker")).toBeGreaterThan(
      actions.lastIndexOf("run release command"),
    );
    expect(actions.lastIndexOf("run release command")).toBeGreaterThan(opened);
    expect(actions.indexOf("remove the move's marker")).toBeLessThan(
      actions.indexOf("retarget migrated"),
    );
    expect(h.audit.entries).toContainEqual(
      expect.objectContaining({
        action: "dispatch workflow",
        detail: `opscrew-deploy.yml on main with sha256:${"e".repeat(64)}`,
      }),
    );
    expectGated(h.events);
  });

  it("FR-3027: a release command that needs the data runs only on the copy, never on the new server's empty database", async () => {
    const h = await moveHarness({ release: true });
    h.hosts.releaseNeedsData = true;
    const n = h.newServer.ipv4;
    const result = await run(h);
    expect(result).toMatchObject({ step: "switched", done: true });
    // The deploy before the copy left only the image and the services; the one on the database's
    // copy, made while the old app serves, ran it all, and the window ran the command again.
    expect(ops(h, n, "release")).toBe(1);
    expect(h.audit.entries).toContainEqual(
      expect.objectContaining({
        action: "retarget deployed",
        detail: "the app's image and services ready on the new Droplet on DigitalOcean",
      }),
    );
    expect(h.reporter.text()).toContain(
      "The app's image and services are ready on the new Droplet on DigitalOcean; the app starts there once its data is copied",
    );
    expect(h.hosts.host(n)).toMatchObject({
      app: true,
      marker: undefined,
      db: "orders before the move (migrated)",
      outcome: "finished",
    });
    expect(trail(h.events).filter((line) => line.startsWith("dispatch"))).toEqual([
      "dispatch main",
      `dispatch main sha256:${"e".repeat(12)}`,
    ]);
    expectGated(h.events);
  });

  it("FR-3103: a failed deploy on the data copied while the app serves stops before the window, the new server waiting for its data again", async () => {
    const h = await moveHarness({ release: true });
    const n = h.newServer.ipv4;
    // The release command fails on the copy, in the deploy before the window.
    h.hosts.fail = (ip, op) => {
      if (ip === n && op === "mark copied") h.github.conclusion = "failure";
      return undefined;
    };
    const error = await caught(run(h));
    expect(error.code).toBe("COMMAND_FAILED");
    expect(error.message).toBe(
      "Copying the app's data to the new Droplet on DigitalOcean while your app serves failed: The deploy workflow did not succeed (failure): https://github.com/acme/shop/actions/runs/99. It ran on the new Droplet on DigitalOcean only; your users' data on the old server on Hetzner Cloud is untouched. The app on the old server on Hetzner Cloud kept serving: nothing there was stopped.",
    );
    expect(error.hint).toContain(
      "the release command's output stays on the new Droplet on DigitalOcean",
    );
    expect(error.hint).toContain("it copies the data again while your app serves");
    expect(error.hint).toContain("opscrew retarget --abort");
    const lines = trail(h.events);
    // The new side stops again and holds the app for its data, its edge stopped.
    expect(lines.slice(lines.lastIndexOf(`dispatch main sha256:${"e".repeat(12)}`))).toEqual([
      `dispatch main sha256:${"e".repeat(12)}`,
      `${n} stop app`,
      `${n} mark waiting`,
      `${n} stop caddy`,
    ]);
    // No downtime: the window was never asked for, and the old app never stopped.
    expect(windowStarted(h)).toBe(false);
    expect(ops(h, OLD_IPV4, "stop app")).toBe(0);
    const state = await move(h);
    expect(state?.step).toBe("deployed");
    expect(state?.oldAppStoppedAt).toBeUndefined();
    expect(h.hosts.host(OLD_IPV4)).toMatchObject({ app: true, db: "orders before the move" });
    expect(h.hosts.host(n)).toMatchObject({ app: false, caddy: false, marker: "waiting" });
    for (const ip of [OLD_IPV4, n]) {
      expect(h.hosts.docker(ip).volumes.has("opscrew-move-dump-shop")).toBe(false);
    }
    expect(h.engine.dnsServer()?.ipv4).toBe(OLD_IPV4);
    expect(h.audit.entries).toContainEqual(
      expect.objectContaining({ action: "copy while the app serves", decision: "refused" }),
    );
    // The sides in words, never their addresses, from the copy while the app serves on.
    const printed = h.reporter.text();
    const copying = printed.slice(printed.indexOf("OpsCrew copies the app's data"));
    expect(copying).toContain("while your app serves (about 8 minutes)");
    for (const text of [error.message, error.hint, copying, JSON.stringify(h.audit.entries)]) {
      expect(text).not.toContain(n);
      expect(text).not.toContain(OLD_IPV4);
    }

    // A re-run copies the data again while the app serves, then runs the window.
    h.hosts.fail = undefined;
    h.github.conclusion = "success";
    const result = await run(h);
    expect(result).toMatchObject({ step: "switched", done: true });
    expect(ops(h, OLD_IPV4, "dump")).toBe(3);
    expect(h.hosts.host(n).db).toBe("orders before the move (migrated)");
    expectGated(h.events);
  });

  it.each([
    { what: "unreadable", result: fail("pg_restore: error: input file is too short") },
    {
      what: "different from the old side's dump",
      result: { exitCode: 0, stdout: `${"0".repeat(64)}  /dump/app.dump\n`, stderr: "" },
    },
  ])("T831: a copied dump that is $what drops nothing and rolls back", async ({ result }) => {
    const h = await moveHarness({ release: true });
    const n = h.newServer.ipv4;
    let checks = 0;
    h.hosts.fail = (ip, op) => {
      // The old side's own check passes; the new side's check of the window's copy fails, once.
      if (ip !== n || op !== "verify dump" || !windowStarted(h) || checks++ > 0) return undefined;
      return result;
    };
    const error = await caught(run(h));
    expect(error.message).toContain("The maintenance window failed");
    expect(error.message).toContain("The app on the old server on Hetzner Cloud runs again");
    expect(windowOps(h, n, "empty db")).toBe(0);
    expect(windowOps(h, n, "restore")).toBe(0);
    // Nothing was dropped: the database holds the copy made while the app served.
    expect(h.hosts.host(n)).toMatchObject({
      db: "orders before the move (migrated)",
      marker: "waiting",
    });
    expect(h.github.runs).toHaveLength(2);
    const state = await move(h);
    expect(state?.step).toBe("deployed");
    expect(state?.oldAppStoppedAt).toBeUndefined();
    expect(h.hosts.host(OLD_IPV4).app).toBe(true);
  });

  it("FR-810: stops before any server command when the recorded servers share an address", async () => {
    const h = await moveHarness({ interactive: false });
    // A script without --allow-downtime stops right before the window.
    const stopped = await drive(h);
    expect(stopped.step).toBe("deployed");
    const file = serverAddressesFile(h.paths);
    const record = JSON.parse(await readFile(file, "utf8"));
    record.retarget.next = { ipv4: OLD_IPV4, ipv6: h.newServer.ipv6 };
    await writeFile(file, `${JSON.stringify(record)}\n`);
    h.events.length = 0;
    h.cli.allowDowntime = true;
    const error = await caught(run(h, { allowDowntime: true }));
    expect(error.code).toBe("PHASE_PRECONDITION");
    expect(error.message).toBe(
      "OpsCrew cannot tell which server is which on this computer: the server being replaced and the new server have the same address in .opscrew/server.json or in the infrastructure state, so it cannot continue the move. Nothing was changed.",
    );
    expect(error.hint).toContain(".opscrew/server.json");
    expect(h.events.filter((e) => e.type === "remote" || e.type === "scp")).toEqual([]);
    expect(h.hosts.host(OLD_IPV4)).toMatchObject({ app: true, db: "orders before the move" });
  });

  it.each([
    { same: "IPv4", next: { ipv4: OLD_IPV4 } },
    { same: "IPv6", next: { ipv4: "198.51.100.99", ipv6: OLD_IPV6.toUpperCase() } },
  ])(
    "FR-810: the maintenance window refuses two servers with the same $same address before any command",
    async ({ next }) => {
      const h = await moveHarness();
      const session = {
        deps: h.deps,
        services: h.services,
        plan: h.plan,
        command: "opscrew retarget",
        servers: { from: { ipv4: OLD_IPV4, ipv6: OLD_IPV6 }, next },
      } as unknown as MoveSession;
      const error = await caught(maintenanceWindow(session, { allowDowntime: true }));
      expect(error.code).toBe("PHASE_PRECONDITION");
      expect(error.message).toContain("OpsCrew cannot tell which server is which on this computer");
      expect(error.message).toContain("Nothing was changed.");
      expect(h.events).toEqual([]);
    },
  );

  it("says the app is offline when the old app cannot be started again, and retries first", async () => {
    const h = await moveHarness();
    h.hosts.fail = (ip, op) => {
      if (ip !== OLD_IPV4 || !windowStarted(h)) return undefined;
      if (op === "dump") return fail("dump failed");
      if (op === "start app") return fail("docker is not running");
      return undefined;
    };
    const error = await caught(run(h));
    expect(error.message).toContain("could not start the app on the old server");
    expect(error.message).toContain("Your app is offline");
    expect(error.hint).toContain("docker compose up -d");
    expect(`${error.message} ${error.hint}`).not.toContain(OLD_IPV4);
    expect((await move(h))?.oldAppStoppedAt).toBeDefined();

    h.hosts.fail = undefined;
    h.events.length = 0;
    await run(h);
    expect(trail(h.events).slice(0, 2)).toEqual([`${OLD_IPV4} start db`, `${OLD_IPV4} start app`]);
  });

  it("stops before the window when the DNS switch plan would create a record", async () => {
    const h = await moveHarness();
    h.engine.tamper = (effect) => {
      if (effect.dnsTo === undefined) return;
      effect.changes.push({
        address: "module.dns.cloudflare_dns_record.www",
        type: "cloudflare_dns_record",
        name: "www",
        provider: "registry.opentofu.org/cloudflare/cloudflare",
        action: "create",
      });
    };
    const error = await caught(run(h));
    expect(error.code).toBe("PHASE_PRECONDITION");
    expect(error.message).toContain(
      "The DNS switch plan would do more than update the DNS records in place",
    );
    expect(error.message).toContain("create module.dns.cloudflare_dns_record.www");
    expect(applies(h)).toHaveLength(2);
    expect(ops(h, OLD_IPV4, "dump")).toBe(0);
    expect(h.hosts.host(OLD_IPV4).app).toBe(true);
  });

  it("after a DNS switch that failed half-way, continuing copies again and completes it", async () => {
    const h = await moveHarness();
    const n = h.newServer.ipv4;
    h.engine.failApply = (effect) => {
      if (effect.dnsTo === undefined) return undefined;
      h.engine.state.dns = effect.dnsTo;
      return "Error: Cloudflare API timeout";
    };
    const error = await caught(run(h));
    expect(error.message).toContain("may already point at the new Droplet on DigitalOcean");
    expect(error.message).not.toContain(n);
    h.engine.failApply = undefined;
    expect(await run(h)).toMatchObject({ step: "switched", done: true });
    // Each run: one dump while the app serves, one in the window.
    expect(ops(h, OLD_IPV4, "dump")).toBe(4);
    expect(h.engine.dnsServer()?.ipv4).toBe(n);
    expect(h.hosts.host(n)).toMatchObject({ caddy: true, db: "orders before the move" });
  });

  it("a failed DNS switch starts the old app again and goes back before the window", async () => {
    const h = await moveHarness();
    h.engine.failApply = (effect) =>
      effect.dnsTo !== undefined ? "Error: Cloudflare API returned 500" : undefined;
    const error = await caught(run(h));
    expect(error.message).toContain("The switch failed");
    expect(error.message).toContain("The app on the old server on Hetzner Cloud runs again");
    expect(error.hint).toContain("repeats the maintenance window");
    const state = await move(h);
    expect(state?.step).toBe("deployed");
    expect(state?.oldAppStoppedAt).toBeUndefined();
    expect(h.hosts.host(OLD_IPV4).app).toBe(true);
    expect(h.engine.dnsServer()?.ipv4).toBe(OLD_IPV4);
    expect(h.hosts.host(h.newServer.ipv4).caddy).toBe(false);

    h.engine.failApply = undefined;
    expect(await run(h)).toMatchObject({ step: "switched", done: true });
    // Each run: one dump while the app serves, one in the window.
    expect(ops(h, OLD_IPV4, "dump")).toBe(4);
    expectGated(h.events);
  });

  it("a failed DNS apply after the window leaves the new app, its workers and cron stopped and held, and the old app running", async () => {
    const h = await moveHarness();
    const plan = await readArtifact("plan", h.paths.files.plan);
    await writeArtifact("plan", h.paths.files.plan, {
      ...plan,
      processes: {
        workers: [
          {
            name: "worker",
            command: "node worker.js",
            source: "procfile",
            count: 1,
            single: false,
            stopGraceSeconds: 30,
            memoryMb: 256,
            enabled: true,
          },
        ],
        cron: [
          { name: "cleanup", schedule: "*/15 * * * *", command: "node cleanup.js", enabled: true },
        ],
      },
    });
    const n = h.newServer.ipv4;
    h.engine.failApply = (effect) =>
      effect.dnsTo !== undefined ? "Error: Cloudflare API returned 500" : undefined;
    const error = await caught(run(h));
    expect(error.message).toContain("The switch failed");
    expect(error.message).toContain("The app on the old server on Hetzner Cloud runs again");
    const lines = trail(h.events);
    const back = lines.slice(lines.lastIndexOf(`${n} remove marker`) + 1);
    // The window started the app there; before the old app starts again, it stops (its workers
    // and cron too) and the marker holds it for its data.
    const processes = "cd /srv/apps/shop && docker compose";
    expect(back.filter((line) => !line.startsWith("apply"))).toEqual([
      "approve iac-apply",
      `${n} stop app`,
      `${n} ${processes} stop worker cron`,
      `${n} mark waiting`,
      `${OLD_IPV4} start db`,
      `${OLD_IPV4} start app`,
      `${OLD_IPV4} start worker cron`,
    ]);
    expect(h.hosts.host(n)).toMatchObject({ app: false, marker: "waiting" });
    expect(h.hosts.host(OLD_IPV4).app).toBe(true);
    expect((await move(h))?.step).toBe("deployed");

    // The next run copies again while the old app serves, then switches.
    h.engine.failApply = undefined;
    expect(await run(h)).toMatchObject({ step: "switched", done: true });
    expect(h.hosts.host(n)).toMatchObject({ app: true, marker: undefined });
  });

  it("starts the old app even when its services don't start, and says it failed", async () => {
    const h = await moveHarness();
    h.hosts.fail = (ip, op) => {
      if (ip !== OLD_IPV4 || !windowStarted(h)) return undefined;
      if (op === "dump") return fail("dump failed");
      if (op === "start db") return fail("db did not start");
      return undefined;
    };
    const error = await caught(run(h));
    expect(error.message).toContain("could not start the app on the old server");
    expect(error.message).toContain("db did not start");
    // The app runs again all the same: it may serve without its service.
    expect(h.hosts.host(OLD_IPV4).app).toBe(true);
    expect(trail(h.events).slice(-2)).toEqual([`${OLD_IPV4} start db`, `${OLD_IPV4} start app`]);
    expect((await move(h))?.oldAppStoppedAt).toBeDefined();
  });

  it("an interrupted window's next run, and an abort before the window, remove MySQL's leftover dumps", async () => {
    /** A move of the app with a MySQL service beside Postgres, stopped after `step`. */
    const moving = async (crash: (h: MoveHarness) => void) => {
      const h = await moveHarness();
      const plan = await readArtifact("plan", h.paths.files.plan);
      const mysql = {
        kind: "mysql",
        version: "8.4",
        memoryMb: 512,
        reason: "mysql2",
        licence: "GPL-2.0",
      };
      await writeArtifact(
        "plan",
        h.paths.files.plan,
        DeployPlanSchema.parse({ ...plan, services: [...plan.services, mysql] }),
      );
      h.hosts.services = ["db", "mysql"];
      h.hosts.seed(OLD_IPV4, {
        ibdata1: { type: "file", mode: 0o600, uid: 999, gid: 999, data: Buffer.from("rows") },
      });
      crash(h);
      await expect(run(h)).rejects.toThrow("interrupted");
      return h;
    };
    const volume = "opscrew-move-dump-shop-mysql";
    const n = NEW_SERVERS.digitalocean.ipv4;

    // A run killed in the window, after a run killed while copying left MySQL's dumps behind.
    const window = await moving((h) => crashOn(h, "maintenance window"));
    for (const ip of [OLD_IPV4, n]) window.hosts.docker(ip).addVolume(volume);
    expect(await run(window)).toMatchObject({ step: "switched", done: true });
    for (const ip of [OLD_IPV4, n]) {
      expect(window.hosts.docker(ip).volumes.has(volume)).toBe(false);
    }

    // An abort at the window's step: the old side, which stays, keeps no dump.
    const aborted = await moving((h) => crashAfter(h, "deployed"));
    aborted.hosts.docker(OLD_IPV4).addVolume(volume);
    const result = await abortRetarget(aborted.deps, {
      services: aborted.services,
      confirm: aborted.confirm,
    });
    expect(result).toMatchObject({ step: "aborted", done: true });
    expect(aborted.hosts.docker(OLD_IPV4).volumes.has(volume)).toBe(false);
  });

  it("a failed switch whose old app cannot start goes back before the window anyway", async () => {
    const h = await moveHarness();
    h.engine.failApply = (effect) => (effect.dnsTo !== undefined ? "Error: API 500" : undefined);
    h.hosts.fail = (ip, op) =>
      ip === OLD_IPV4 && op === "start app" ? fail("docker is not running") : undefined;
    const error = await caught(run(h));
    expect(error.message).toContain("Your app is offline");
    const state = await move(h);
    expect(state?.step).toBe("deployed");
    expect(state?.oldAppStoppedAt).toBeDefined();

    h.engine.failApply = undefined;
    h.hosts.fail = undefined;
    h.events.length = 0;
    expect(await run(h)).toMatchObject({ step: "switched", done: true });
    const lines = trail(h.events);
    expect(lines.slice(0, 2)).toEqual([`${OLD_IPV4} start db`, `${OLD_IPV4} start app`]);
    expect(lines).toContain(`${OLD_IPV4} dump`);
  });

  it("a refused DNS switch also rolls back so users keep being served", async () => {
    const h = await moveHarness();
    h.handler.answer = (r) => !(r.kind === "iac-apply" && r.title.includes("2 to update"));
    const error = await caught(run(h));
    expect(error.code).toBe("APPROVAL_REFUSED");
    expect(error.message).toContain("The switch was not approved");
    // Any hint before "When you are ready" (the command that approves it) ends as a sentence.
    expect(error.hint ?? "").toMatch(/(^|[.!?] )When you are ready/);
    expect((await move(h))?.step).toBe("deployed");
    expect(h.hosts.host(OLD_IPV4).app).toBe(true);
  });

  it("keeps recreate on the new cloud server for an app with a SQLite database", async () => {
    const h = await moveHarness();
    const before = await readArtifact("plan", h.paths.files.plan);
    await writeArtifact("plan", h.paths.files.plan, {
      ...before,
      storage: { ...before.storage, sqlite: { dir: "data" } },
      deploy: { strategy: "recreate", drainSeconds: 30 },
    });
    await run(h, { confirmStart: async () => true });
    const plan = await readArtifact("plan", h.paths.files.plan);
    expect(plan.deploy.strategy).toBe("recreate");
  });

  it("keeps the PHP extensions design found for a Laravel app Railpack builds", async () => {
    const h = await moveHarness();
    await writeArtifact("architecture", h.paths.files.architecture, {
      schemaVersion: 1,
      generatedAt: "2026-11-20T09:00:00.000Z",
      generator: { tool: "opscrew", version: "0.0.0-test" },
      facts: makeFacts({
        name: APP,
        languages: ["php"],
        packageManager: "none",
        frameworks: [{ name: "laravel", path: "." }],
      }),
      summary: "A shop.",
      risks: [],
      aiEnriched: false,
    });
    const before = await readArtifact("plan", h.paths.files.plan);
    const build = {
      builder: "railpack" as const,
      chosen: "auto" as const,
      reason: "Railpack builds PHP.",
      runtime: { language: "php" as const, version: "8.5" },
      probe: "php" as const,
      phpExtensions: ["pcntl", "sockets"],
    };
    await writeArtifact("plan", h.paths.files.plan, { ...before, app: { ...before.app, build } });
    await run(h, { confirmStart: async () => true });
    const plan = await readArtifact("plan", h.paths.files.plan);
    expect(plan.app.build).toMatchObject({
      builder: "railpack",
      phpExtensions: ["pcntl", "sockets"],
    });
  });

  it("shows the builder and the deploy strategy for the new server before the start, and records them with the user's snapshot settings", async () => {
    const h = await moveHarness();
    const before = await readArtifact("plan", h.paths.files.plan);
    const earlier = {
      builder: "buildpacks" as const,
      chosen: "auto" as const,
      reason: "Before the move.",
      runtime: { language: "node" as const, version: "24" },
      probe: "bash" as const,
    };
    await writeArtifact("plan", h.paths.files.plan, {
      ...before,
      app: { ...before.app, build: earlier },
      deploy: { strategy: "recreate", drainSeconds: 45, snapshots: true, keepSnapshots: 5 },
    });
    let summary: RetargetSummary | undefined;
    const refused = await caught(
      run(h, {
        confirmStart: async (s) => {
          summary = s;
          return false;
        },
      }),
    );
    expect(refused.code).toBe("APPROVAL_REFUSED");
    expect(summary?.changes).toEqual([
      expect.stringMatching(
        /^Image builder: generated-dockerfile \(was buildpacks\)\. OpsCrew has/,
      ),
      `Deploys: rolling (was recreate). ${ROLLING_NOTE}`,
    ]);
    for (const change of summary?.changes ?? []) expect(h.reporter.text()).toContain(change);
    expect(applies(h)).toHaveLength(0);
    expect((await readArtifact("plan", h.paths.files.plan)).app.build).toEqual(earlier);

    await run(h, { confirmStart: async () => true });
    const plan = await readArtifact("plan", h.paths.files.plan);
    expect(plan.app.build).toMatchObject({ builder: "generated-dockerfile", chosen: "auto" });
    expect(plan.deploy).toEqual({
      strategy: "rolling",
      drainSeconds: 45,
      snapshots: true,
      keepSnapshots: 5,
    });
  });

  it("stops before anything is created when the new server's builder needs a missing Dockerfile", async () => {
    const h = await moveHarness();
    await rm(join(h.root, "Dockerfile"));
    const error = await caught(run(h));
    expect(error.code).toBe("PHASE_PRECONDITION");
    expect(error.message).toBe(
      "The new side's builder needs a Dockerfile this repository lacks: run `opscrew design` and `opscrew adapt` first. Nothing was changed.",
    );
    expect(applies(h)).toHaveLength(0);
    expect((await readArtifact("plan", h.paths.files.plan)).retarget).toBeUndefined();
  });

  it("stops before anything is created when the plan's builder cannot build the app", async () => {
    const h = await moveHarness();
    const before = await readArtifact("plan", h.paths.files.plan);
    const build = {
      builder: "buildpacks" as const,
      chosen: "user" as const,
      reason: "You chose it.",
      runtime: { language: "node" as const, version: "24" },
      probe: "bash" as const,
    };
    await writeArtifact("plan", h.paths.files.plan, { ...before, app: { ...before.app, build } });
    // Buildpacks has no pnpm support.
    const architecture = await readArtifact("architecture", h.paths.files.architecture);
    await writeArtifact("architecture", h.paths.files.architecture, {
      ...architecture,
      facts: { ...architecture.facts, packageManager: "pnpm" },
    });
    const error = await caught(run(h));
    expect(error.code).toBe("INVALID_INPUT");
    expect(error.message).toContain(
      "sets app.build.builder to buildpacks, but the pinned Buildpacks builder has no pnpm support",
    );
    expect(error.message).toContain("Nothing was changed.");
    expect(applies(h)).toHaveLength(0);
    expect((await readArtifact("plan", h.paths.files.plan)).retarget).toBeUndefined();
  });

  it("without data to copy there is no maintenance window", async () => {
    const h = await moveHarness({ postgres: false });
    let summary: RetargetSummary | undefined;
    const result = await run(h, {
      confirmStart: async (s) => {
        summary = s;
        return true;
      },
    });
    expect(result).toMatchObject({ step: "switched", done: true });
    expect(summary?.data).toEqual([]);
    expect(summary?.expectedDowntimeMinutes).toBeUndefined();
    expect(summary?.steps.join(" ")).toContain("No maintenance window");
    const lines = trail(h.events);
    expect(lines).not.toContain("approve remote-exec");
    expect(lines.some((line) => line.includes("dump") || line.includes("db size"))).toBe(false);
    // The old app served users until the switch, then stops.
    const switchAt = lines.indexOf("apply updates=2");
    const stopAt = lines.indexOf(`${OLD_IPV4} stop app`);
    expect(stopAt).toBeGreaterThan(switchAt);
    expect((await move(h))?.oldAppStoppedAt).toBeDefined();
    expect(h.github.secrets.has("OPSCREW_SERVICE_DB_ENV")).toBe(false);
    // FR-3027: nothing to copy keeps today's flow: no marker, one deploy, the app checked there.
    const n = h.newServer.ipv4;
    expect(lines.some((line) => line.endsWith("waiting"))).toBe(false);
    expect(h.github.runs).toEqual([{ workflowFile: "opscrew-deploy.yml", ref: "main" }]);
    expect(ops(h, n, "health")).toBeGreaterThan(0);
    expect(ops(h, n, "services up?")).toBe(0);
    expect(summary?.steps.join(" ")).not.toContain("only the app's image and services");
  });

  it("DNS at another provider: shows the records and continues once the user confirms", async () => {
    const h = await moveHarness({ dns: "other" });
    const n = h.newServer.ipv4;
    h.handler.answer = (r) => {
      if (r.kind === "remote-exec" && r.title.startsWith("Switch")) h.manual.ip = n;
      return true;
    };
    const result = await run(h);
    expect(result).toMatchObject({ step: "switched", done: true });
    const confirm = h.handler.requests.find((r) => r.title.startsWith("Switch"));
    expect(confirm?.details).toContain(`A     ${DOMAIN} → ${n}`);
    expect(confirm?.details).toContain(`AAAA  ${DOMAIN} → ${h.newServer.ipv6}`);
    expect(trail(h.events).filter((line) => line.startsWith("apply"))).toEqual([
      "apply moves=3",
      "apply creates=4",
    ]);
    const plan = await readArtifact("plan", h.paths.files.plan);
    // The URL on the new server's IP is not committed; the address is in the local state.
    expect(plan.deployment.url).toBeUndefined();
    expect((await readServerAddresses(h.paths)).deployment?.ipv4).toBe(n);
    expect(h.events.some((e) => e.type === "fetch" && e.url.startsWith(`https://${DOMAIN}`))).toBe(
      true,
    );
  });

  it("DNS at another provider in a script: stops with the records until --dns-switched", async () => {
    const h = await moveHarness({ dns: "other", interactive: false });
    const n = h.newServer.ipv4;
    const stop = await drive(h, { allowDowntime: true });
    expect(stop).toMatchObject({ step: "migrated", done: false });
    expect(stop.pendingPlanHash).toBeUndefined();
    expect(stop.next.join("\n")).toContain(`A     ${DOMAIN} → ${n}`);
    expect(stop.next.join("\n")).toContain("opscrew retarget --dns-switched");
    expect(stop.next.join("\n")).toContain("users see an error");

    h.manual.ip = n;
    const result = await run(h, { dnsSwitched: true });
    expect(result).toMatchObject({ step: "switched", done: true });
    expect(h.audit.entries.some((e) => e.action === "dns-switched")).toBe(true);
    expectGated(h.events);
  });

  it("DNS at another provider: says the downtime lasts until the user's DNS change is live", async () => {
    const h = await moveHarness({ dns: "other" });
    const n = h.newServer.ipv4;
    h.handler.answer = (r) => {
      if (r.kind === "remote-exec" && r.title.startsWith("Switch")) h.manual.ip = n;
      return true;
    };
    let summary: RetargetSummary | undefined;
    await run(h, {
      confirmStart: async (s) => {
        summary = s;
        return true;
      },
    });
    const window = summary?.steps.find((step) => step.startsWith("Maintenance window"));
    expect(window).toContain(
      "the app stays offline from then until your DNS change has reached your users",
    );
    const printed = h.reporter.text();
    expect(printed).toContain(
      "Expected downtime: about 2 minutes for the last copy, after about 8 minutes of copying while your app serves, plus the time your DNS change takes to reach your users.",
    );
    expect(printed).toContain("Lower the TTL of those records beforehand");
    expect(printed).toContain("pass `--allow-downtime --dns-switched` together only when");
    const approval = h.handler.requests.find((r) => r.title.startsWith("Maintenance window"));
    expect(approval?.title).toContain("for the copy, plus your DNS change");
    expect(approval?.details).toContain("Lower the TTL");
    const confirm = h.handler.requests.find((r) => r.title.startsWith("Switch"));
    expect(confirm?.details).toContain("so your users are offline until your DNS change");
  });

  it("DNS at another provider in a script: the window stop says the app stays stopped", async () => {
    const h = await moveHarness({ dns: "other", interactive: false });
    const stop = await drive(h);
    expect(stop).toMatchObject({ step: "deployed", done: false });
    const text = stop.next.join("\n");
    expect(text).toContain("stays stopped until your DNS change has reached your users");
    expect(text).toContain("Lower the TTL");
    expect(text).toContain("`--allow-downtime --dns-switched`");
    expect(h.hosts.host(OLD_IPV4).app).toBe(true);
  });

  it("with Cloudflare DNS the downtime is only the copy", async () => {
    const h = await moveHarness();
    let summary: RetargetSummary | undefined;
    await run(h, {
      confirmStart: async (s) => {
        summary = s;
        return true;
      },
    });
    expect(summary?.steps.join(" ")).not.toContain("offline from then");
    expect(h.reporter.text()).not.toContain("TTL");
    const approval = h.handler.requests.find((r) => r.title.startsWith("Maintenance window"));
    expect(approval?.title).toContain("(about 2 minutes of downtime)");
    expect(approval?.title).toContain("(50.0 MB, copied while your app served)");
  });

  it("a script resumed after the copy says users are offline while the switch plan waits", async () => {
    const h = await moveHarness({ interactive: false });
    crashAfter(h, "migrated");
    await expect(drive(h, { allowDowntime: true })).rejects.toThrow("interrupted");
    expect((await move(h))?.step).toBe("migrated");
    h.cli.approve = undefined;
    h.cli.allowDowntime = undefined;
    const stop = await run(h);
    expect(stop).toMatchObject({ step: "migrated", done: false });
    const hash = stop.pendingPlanHash as string;
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
    const text = stop.next.join("\n");
    expect(text).toContain("The app on the old server on Hetzner Cloud is stopped");
    expect(text).toContain("your users are offline until this switch is applied");
    expect(text).toContain(`opscrew retarget --approve ${hash}`);
    expect(h.hosts.host(OLD_IPV4).app).toBe(false);

    h.cli.approve = hash;
    expect(await run(h, { approvePlanHash: hash })).toMatchObject({ step: "switched", done: true });
    // One dump while the app served, one in the window.
    expect(ops(h, OLD_IPV4, "dump")).toBe(2);
    expectGated(h.events);
  });

  it("reads both servers' addresses from the infrastructure state when the local record is gone", async () => {
    const h = await moveHarness({ dns: "none", postgres: false, interactive: false });
    const fresh = { ipv4: h.newServer.ipv4, ipv6: h.newServer.ipv6 };
    await drive(h);
    await rm(serverAddressesFile(h.paths));
    const result = await run(h, { dnsSwitched: true });
    expect(result).toMatchObject({ step: "switched", done: true });
    expect(await readServerAddresses(h.paths)).toEqual({
      schemaVersion: 1,
      deployment: fresh,
      retarget: { from: { ipv4: OLD_IPV4, ipv6: OLD_IPV6 }, next: fresh },
    });
    // The right servers were used: the old app is stopped, the new one serves.
    expect(h.hosts.host(OLD_IPV4).app).toBe(false);
    expect(h.hosts.host(fresh.ipv4)).toMatchObject({ app: true, caddy: true });
  });

  it("a switch made by hand, local record gone: the old and new servers are never swapped", async () => {
    // Without managed DNS no `switched` layout is ever applied: module.server is still the new
    // server, and the outputs' live server is still the old one.
    const h = await moveHarness({ dns: "none", postgres: false });
    const n = h.newServer.ipv4;
    crashAfter(h, "switched");
    await expect(run(h)).rejects.toThrow("interrupted");
    expect(await move(h)).toMatchObject({ step: "switched" });
    expect((await move(h))?.oldAppStoppedAt).toBeUndefined();
    expect(h.hosts.host(OLD_IPV4).app).toBe(true);
    await rm(serverAddressesFile(h.paths));

    const mark = h.events.length;
    expect(await run(h)).toMatchObject({ step: "switched", done: true });
    expect(trail(h.events.slice(mark))).toEqual([`${n} start caddy`, `${OLD_IPV4} stop app`]);
    expect(h.hosts.host(OLD_IPV4).app).toBe(false);
    expect(h.hosts.host(n)).toMatchObject({ app: true, caddy: true });
    // The record is rebuilt: both servers, and the new one receives the traffic.
    const fresh = { ipv4: n, ipv6: h.newServer.ipv6 };
    expect(await readServerAddresses(h.paths)).toEqual({
      schemaVersion: 1,
      deployment: fresh,
      retarget: { from: { ipv4: OLD_IPV4, ipv6: OLD_IPV6 }, next: fresh },
    });
  });

  it("a DNS switch applied but not recorded, local record gone: the servers are not swapped", async () => {
    const h = await moveHarness({ postgres: false });
    const n = h.newServer.ipv4;
    // The process dies right after the third apply (the DNS switch), before it is recorded.
    const append = h.audit.append.bind(h.audit);
    let applied = 0;
    h.audit.append = async (entry) => {
      await append(entry);
      if (entry.kind === "iac" && entry.action === "apply" && ++applied === 3) {
        throw new Error("interrupted");
      }
    };
    await caught(run(h));
    expect(h.engine.dnsServer()?.ipv4).toBe(n);
    expect((await move(h))?.step).toBe("deployed");
    // The state's outputs now follow the new server as the live one.
    expect(h.engine.state.outputs.server_ipv4).toBe(n);
    await rm(serverAddressesFile(h.paths));

    const mark = h.events.length;
    expect(await run(h)).toMatchObject({ step: "switched", done: true });
    expect(trail(h.events.slice(mark))).toEqual([`${n} start caddy`, `${OLD_IPV4} stop app`]);
    expect(h.hosts.host(OLD_IPV4).app).toBe(false);
    expect(h.hosts.host(n)).toMatchObject({ app: true, caddy: true });
    const fresh = { ipv4: n, ipv6: h.newServer.ipv6 };
    expect(await readServerAddresses(h.paths)).toEqual({
      schemaVersion: 1,
      deployment: fresh,
      retarget: { from: { ipv4: OLD_IPV4, ipv6: OLD_IPV6 }, next: fresh },
    });
  });

  it("stops without acting when it cannot tell which server is which", async () => {
    const h = await moveHarness({ dns: "none", postgres: false, interactive: false });
    await drive(h);
    expect((await move(h))?.step).toBe("deployed");
    await rm(serverAddressesFile(h.paths));
    // A state without the `servers` output: only the live server is named.
    h.engine.state.outputs = { server_ipv4: OLD_IPV4, server_ipv6: OLD_IPV6 };
    const mark = h.events.length;
    const error = await caught(run(h, { dnsSwitched: true }));
    expect(error.code).toBe("PHASE_PRECONDITION");
    expect(error.message).toContain("OpsCrew cannot tell which server is which on this computer");
    expect(error.message).toContain("Nothing was changed.");
    expect(error.hint).toContain("on the computer that started the move");
    expect(trail(h.events.slice(mark))).toEqual([]);
    expect((await move(h))?.step).toBe("deployed");
    expect(h.hosts.host(OLD_IPV4).app).toBe(true);
  });

  it("a damaged local record stops the move before anything happens", async () => {
    const h = await moveHarness({ dns: "none", postgres: false, interactive: false });
    await drive(h);
    await writeFile(serverAddressesFile(h.paths), '{"schemaVersion":1,"retarget":');
    const mark = h.events.length;
    const error = await caught(run(h, { dnsSwitched: true }));
    expect(error.code).toBe("ARTIFACT_INVALID");
    expect(error.message).toContain(".opscrew/server.json");
    expect(error.hint).toContain("Delete .opscrew/server.json");
    expect(trail(h.events.slice(mark))).toEqual([]);
    expect((await move(h))?.step).toBe("deployed");
    expect(await readFile(serverAddressesFile(h.paths), "utf8")).toBe(
      '{"schemaVersion":1,"retarget":',
    );
  });

  it("without a domain the app moves to the new address", async () => {
    const h = await moveHarness({ dns: "none", postgres: false, interactive: false });
    const n = h.newServer.ipv4;
    const stop = await drive(h);
    expect(stop.next.join("\n")).toContain(`The app's new address is http://${n}`);
    expect(h.hosts.host(OLD_IPV4).app).toBe(true);
    const result = await run(h, { dnsSwitched: true });
    expect(result).toMatchObject({ step: "switched", done: true });
    const plan = await readArtifact("plan", h.paths.files.plan);
    expect(plan.deployment.url).toBeUndefined();
    expect((await readServerAddresses(h.paths)).deployment?.ipv4).toBe(n);
    expect(await readFile(h.paths.files.plan, "utf8")).not.toContain(n);
    expect(h.events.some((e) => e.type === "fetch" && e.url === `http://${n}/api/health`)).toBe(
      true,
    );
  });

  it("a refused switch confirmation rolls back to the old app", async () => {
    const h = await moveHarness({ dns: "other" });
    h.handler.answer = (r) => !(r.kind === "remote-exec" && r.title.startsWith("Switch"));
    const error = await caught(run(h));
    expect(error.code).toBe("APPROVAL_REFUSED");
    expect((await move(h))?.step).toBe("deployed");
    expect(h.hosts.host(OLD_IPV4).app).toBe(true);
  });

  it("US3: a script stops at every plan with its hash and continues with --approve", async () => {
    const h = await moveHarness({ interactive: false });
    const first = await run(h);
    expect(first).toMatchObject({ step: "started", done: false });
    const rename = first.pendingPlanHash as string;
    expect(rename).toMatch(/^[0-9a-f]{64}$/);
    expect(first.next.join(" ")).toContain(`opscrew retarget --approve ${rename}`);
    expect(applies(h)).toHaveLength(0);

    // A wrong hash applies nothing: the step is planned again.
    h.cli.approve = "0".repeat(64);
    const wrong = await run(h, { approvePlanHash: "0".repeat(64) });
    expect(wrong.step).toBe("started");
    expect(applies(h)).toHaveLength(0);
    expect(h.reporter.text()).toContain("did not use --approve");
    const renameAgain = wrong.pendingPlanHash as string;

    h.cli.approve = renameAgain;
    const second = await run(h, { approvePlanHash: renameAgain });
    expect(second).toMatchObject({ step: "renamed", done: false });
    expect(applies(h)).toHaveLength(1);

    h.cli.approve = second.pendingPlanHash;
    const third = await run(h, { approvePlanHash: second.pendingPlanHash as string });
    expect(third).toMatchObject({ step: "deployed", done: false });
    const dnsSwitch = third.pendingPlanHash as string;
    expect(third.next.join(" ")).toContain(
      `opscrew retarget --allow-downtime --approve ${dnsSwitch}`,
    );
    expect(h.hosts.host(OLD_IPV4).app).toBe(true);

    // The data is copied while the app serves; the window needs --allow-downtime, and the
    // approved switch plan waits.
    h.cli.approve = dnsSwitch;
    const fourth = await run(h, { approvePlanHash: dnsSwitch });
    expect(fourth).toMatchObject({ step: "deployed", done: false, pendingPlanHash: dnsSwitch });
    expect(fourth.next.join(" ")).toContain("--allow-downtime");
    expect(h.hosts.host(OLD_IPV4).app).toBe(true);
    expect(ops(h, OLD_IPV4, "stop app")).toBe(0);
    expect(ops(h, OLD_IPV4, "dump")).toBe(1);
    expect(h.github.runs).toHaveLength(2);

    // The run at the window doesn't copy again first: only the window's dump.
    h.cli.allowDowntime = true;
    const last = await run(h, { approvePlanHash: dnsSwitch, allowDowntime: true });
    expect(last).toMatchObject({ step: "switched", done: true });
    expect(applies(h)).toHaveLength(3);
    expect(ops(h, OLD_IPV4, "dump")).toBe(2);
    expect(h.github.runs).toHaveLength(2);
    expectGated(h.events);
  });

  it("stops when the deploy workflow fails; the old server keeps serving", async () => {
    const h = await moveHarness();
    h.github.conclusion = "failure";
    const error = await caught(run(h));
    expect(error.message).toContain("The deploy workflow did not succeed (failure)");
    expect(error.message).toContain("https://github.com/acme/shop/actions/runs/99");
    expect(error.message).toContain(
      "The app on the old server on Hetzner Cloud still serves your users",
    );
    expect(error.hint).toContain("opscrew retarget --abort");
    expect((await move(h))?.step).toBe("created");
    expect(h.hosts.host(OLD_IPV4).app).toBe(true);

    h.github.conclusion = "success";
    expect(await run(h)).toMatchObject({ step: "switched", done: true });
    // The secrets were stored once; the workflow ran again, then in the window.
    expect(h.events.filter((e) => e.type === "secret")).toHaveLength(7);
    expect(h.github.runs).toHaveLength(3);
  });

  it("stops before any plan when a provider token is missing or rejected", async () => {
    const h = await moveHarness();
    h.services.providers = {
      ...h.services.providers,
      digitalocean: { configured: false, verify: async () => ({ ok: false, message: "no" }) },
    };
    const error = await caught(run(h));
    expect(error.code).toBe("CREDENTIALS_MISSING");
    expect(error.message).toContain("DigitalOcean");
    expect(h.events.filter((e) => e.type === "plan")).toEqual([]);
    expect(await move(h)).toBeUndefined();
  });

  it("stops before any plan when the GitHub token is missing", async () => {
    const h = await moveHarness();
    h.services.github = null;
    const error = await caught(run(h));
    expect(error.code).toBe("CREDENTIALS_MISSING");
    expect(error.message).toContain("GitHub");
    expect(error.hint).toBeTruthy();
    expect(h.events.filter((e) => e.type === "plan")).toEqual([]);
    expect(await move(h)).toBeUndefined();
  });

  it("stops before any plan when the Cloudflare token is missing", async () => {
    const h = await moveHarness();
    h.services.cloudflare = null;
    const error = await caught(run(h));
    expect(error.code).toBe("CREDENTIALS_MISSING");
    expect(error.message).toContain("No Cloudflare token found: set CLOUDFLARE_API_TOKEN");
    expect(error.hint).toBeTruthy();
    expect(h.events.filter((e) => e.type === "plan")).toEqual([]);
    expect(await move(h)).toBeUndefined();
  });

  it("stops before any plan without the state passphrase, naming the move's command", async () => {
    const h = await moveHarness();
    await rm(h.deps.paths.files.statePassphrase);
    const error = await caught(run(h));
    expect(error.code).toBe("PHASE_PRECONDITION");
    expect(error.message).toContain("does not have its passphrase");
    expect(error.hint).toMatch(/then run `opscrew retarget[^`]*` again\.$/);
    expect(existsSync(h.deps.paths.files.statePassphrase)).toBe(false);
    expect(h.engine.plans).toHaveLength(0);
  });

  it("stops before anything when the deploy key is not on this computer", async () => {
    const h = await moveHarness();
    await rm(h.paths.files.deployKey);
    const error = await caught(run(h));
    expect(error.code).toBe("PHASE_PRECONDITION");
    expect(error.message).toContain("deploy key is not on this computer");
    expect(await move(h)).toBeUndefined();
  });

  it("refuses a move to the provider the deployment already uses", async () => {
    const h = await moveHarness();
    const error = await caught(run(h, { to: "hetzner" }));
    expect(error.code).toBe("PHASE_PRECONDITION");
    expect(error.message).toContain("already runs on Hetzner Cloud");
    expect(h.events.filter((e) => e.type === "plan")).toEqual([]);
  });

  it.each([
    ["cloudflare-workers", "Cloudflare hosting"],
    ["github-pages", "GitHub Pages"],
  ] as const)(
    "refuses a move onto %s, which the answers name, before any plan",
    async (provider, name) => {
      const h = await moveHarness();
      const { region: _region, ...answers } = await readArtifact(
        "requirements",
        h.paths.files.requirements,
      );
      await writeArtifact("requirements", h.paths.files.requirements, { ...answers, provider });
      const error = await caught(run(h));
      expect(error).toMatchObject({
        code: "PHASE_PRECONDITION",
        message:
          "opscrew/requirements.yaml asks for a site host, and an app with a server does not move to one. Nothing was changed.",
        hint: expect.stringContaining("`opscrew destroy`"),
      });
      expect(name).toBeTruthy();
      expect(h.events.filter((e) => e.type === "plan")).toEqual([]);
      expect(await move(h)).toBeUndefined();
    },
  );

  it.each([
    ["cloudflare-workers", "Cloudflare hosting"],
    ["github-pages", "GitHub Pages"],
  ] as const)(
    "refuses a move off %s, whose destroy the hint names, before any plan",
    async (provider, name) => {
      const h = await moveHarness();
      await writeArtifact(
        "plan",
        h.paths.files.plan,
        sitePlan({ provider, name: "shop", deployed: true }),
      );
      const error = await caught(run(h, { to: "digitalocean" }));
      expect(error).toMatchObject({
        code: "PHASE_PRECONDITION",
        message:
          "Moving shop between a site host and a server changes the app's whole design, so OpsCrew does not do it as a move. Nothing was changed.",
        hint: expect.stringContaining("Run `opscrew destroy`"),
      });
      expect(name).toBeTruthy();
      expect(h.events.filter((e) => e.type === "plan")).toEqual([]);
      expect(await move(h)).toBeUndefined();
    },
  );

  it("US3: copies every service's data in the window, each checked by its digest on both sides", async () => {
    const h = await moveHarness();
    const n = h.newServer.ipv4;
    const plan = await readArtifact("plan", h.paths.files.plan);
    await writeArtifact(
      "plan",
      h.paths.files.plan,
      DeployPlanSchema.parse({
        ...plan,
        services: [
          ...plan.services,
          { kind: "mysql", version: "8.4", memoryMb: 512, reason: "mysql2", licence: "GPL-2.0" },
          {
            kind: "rabbitmq",
            version: "4.3",
            memoryMb: 384,
            reason: "amqplib",
            licence: "MPL-2.0",
          },
        ],
      }),
    );
    const file = (text: string) => ({
      type: "file" as const,
      mode: 0o600,
      uid: 999,
      gid: 999,
      data: Buffer.from(text),
    });
    h.hosts.services = ["db", "mysql", "rabbitmq"];
    h.hosts.seed(OLD_IPV4, { ibdata1: file("orders table"), "queue.idx": file("jobs") });
    const result = await run(h);
    expect(result).toMatchObject({ step: "switched", done: true });
    for (const service of ["mysql", "rabbitmq"]) {
      const folder = `/srv/data/shop/${service}`;
      const old = [...(h.hosts.docker(OLD_IPV4).folders.get(folder)?.files ?? [])];
      const copied = [...(h.hosts.docker(n).folders.get(folder)?.files ?? [])];
      expect(copied).toEqual(old);
      expect(copied.length).toBeGreaterThan(1);
    }
    expect(trail(h.events)).toEqual(
      expect.arrayContaining([
        `${OLD_IPV4} stop db mysql rabbitmq`,
        // The new side's Postgres keeps running; the others stop for the copy.
        `${n} stop mysql rabbitmq`,
        `${n} start mysql rabbitmq`,
      ]),
    );
    const window = h.handler.requests.find((r) => r.title.startsWith("Maintenance window"));
    expect(window?.details).toContain("mysql's data at /var/lib/postgresql/data");
    expect(window?.details).toContain("rabbitmq's data at /var/lib/postgresql/data");
    expect(window?.details).not.toContain(OLD_IPV4);
    expect(window?.details).not.toContain(n);
  });

  it("US3: --empty starts a service empty, and the summary says what that loses", async () => {
    const h = await moveHarness();
    const n = h.newServer.ipv4;
    const plan = await readArtifact("plan", h.paths.files.plan);
    await writeArtifact(
      "plan",
      h.paths.files.plan,
      DeployPlanSchema.parse({
        ...plan,
        services: [
          ...plan.services,
          {
            kind: "valkey",
            version: "8",
            memoryMb: 128,
            options: { mode: "queue" },
            reason: "BullMQ",
            licence: "BSD-3-Clause",
          },
        ],
      }),
    );
    h.hosts.services = ["db", "queue"];
    h.hosts.seed(OLD_IPV4, {
      "dump.rdb": { type: "file", mode: 0o600, uid: 999, gid: 999, data: Buffer.from("jobs") },
    });
    let summary: RetargetSummary | undefined;
    const result = await run(h, {
      empty: ["queue"],
      confirmStart: async (s) => {
        summary = s;
        return true;
      },
    });
    expect(result).toMatchObject({ step: "switched", done: true });
    expect(summary?.data).toContainEqual(expect.objectContaining({ owner: "queue", copy: false }));
    expect(h.reporter.text()).toContain(
      "starts empty. Starting it empty loses the jobs waiting in its queue",
    );
    expect((await move(h))?.empty).toEqual(["queue"]);
    // The queue's folder on the new server stays as its deploy made it.
    expect([
      ...(h.hosts.docker(n).folders.get("/srv/data/shop/queue")?.files.keys() ?? []),
    ]).toEqual([""]);

    const asked: string[] = [];
    const g = await moveHarness();
    await caught(
      run(g, {
        chooseEmpty: async (question) => {
          asked.push(`${question.owner}: ${question.loses}`);
          return true;
        },
        confirmStart: async () => false,
      }),
    );
    expect(asked).toEqual(["db: Starting it empty loses every table and row in it."]);
    const refused = await caught(run(await moveHarness(), { empty: ["nothing"] }));
    expect(refused.code).toBe("INVALID_INPUT");
    expect(refused.message).toContain("--empty nothing");
  });

  it("stops before any change when the key of the app's bucket is not known here", async () => {
    const h = await moveHarness();
    const plan = withBucket(await readArtifact("plan", h.paths.files.plan), "r2");
    await writeArtifact("plan", h.paths.files.plan, plan);
    delete h.deps.env[STORAGE_KEY_VARS.accessKeyId];
    delete h.deps.env[STORAGE_KEY_VARS.secretAccessKey];
    const before = h.events.length;
    const error = await caught(run(h));
    expect(error.code).toBe("CREDENTIALS_MISSING");
    expect(error.message).toContain("Nothing was changed.");
    expect(h.events.slice(before)).toEqual([]);
    expect(await move(h)).toBeUndefined();
  });

  it("moves an app whose files are in a bucket at a provider, which stays where it is", async () => {
    const h = await moveHarness();
    const plan = withBucket(await readArtifact("plan", h.paths.files.plan), "r2");
    await writeArtifact("plan", h.paths.files.plan, plan);
    const key = fakeSecret("aws-secret-access-key", "move");
    h.deps.env[STORAGE_KEY_VARS.accessKeyId] = fakeSecret("aws-access-key-id", "move");
    h.deps.env[STORAGE_KEY_VARS.secretAccessKey] = key;
    const result = await run(h);
    expect(result.step).toBe("switched");
    // The bucket and its root stay; the app on the new server keeps its key.
    expect((await readArtifact("plan", h.paths.files.plan)).storage).toEqual(plan.storage);
    expect(h.github.secrets.get("OPSCREW_APP_ENV")).toContain(`AWS_SECRET_ACCESS_KEY=${key}`);
    expect(existsSync(join(h.paths.files.tfstateDir, "storage.tfstate"))).toBe(false);
  });

  it("refuses a deployment that is not live", async () => {
    const h = await moveHarness();
    await rm(join(h.paths.files.tfstateDir, "prod.tfstate"));
    const error = await caught(run(h));
    expect(error.message).toContain("no live deployment");
  });

  it("changes nothing when the summary is not confirmed", async () => {
    const h = await moveHarness();
    const error = await caught(run(h, { confirmStart: async () => false }));
    expect(error.code).toBe("APPROVAL_REFUSED");
    expect(error.message).toBe("The move was not started. Nothing was changed.");
    expect(await move(h)).toBeUndefined();
    expect((await readArtifact("plan", h.paths.files.plan)).target.provider).toBe("hetzner");
  });

  it("uses the option the user picked", async () => {
    const h = await moveHarness();
    const result = await run(h, { option: "digitalocean-single-s-2vcpu-4gb-fra1" });
    expect(result.step).toBe("switched");
    const plan = await readArtifact("plan", h.paths.files.plan);
    expect(plan.target).toMatchObject({ serverType: "s-2vcpu-4gb" });
    const error = await caught(run(await moveHarness(), { choose: async () => "no-such-option" }));
    expect(error.code).toBe("INVALID_INPUT");
  });

  it("stops before approval when the new server's plan fails a security policy", async () => {
    const h = await moveHarness();
    h.engine.planJsonFor = (effect) =>
      effect.creates.length > 0
        ? planJsonFor({ provider: "digitalocean", openDatabasePort: true })
        : effect.planJson;
    const error = await caught(run(h));
    expect(error.message).toContain("security");
    expect(trail(h.events).filter((line) => line.startsWith("apply"))).toEqual(["apply moves=3"]);
    expect((await move(h))?.step).toBe("renamed");
  });

  // The old Kamatera server keeps its first boot's firewall while the move runs: when it cannot
  // be reached over SSH for an in-place host plan update, the move stops at the first plan.
  it("stops before any approval when the plan changes the networks of an unreachable old server's own firewall", async () => {
    // The fakes move from Hetzner; the old server in the plan is Kamatera's, which keeps no
    // provider backups (the old side's plan asks for none, so only the firewall's check fails).
    const h = await moveHarness();
    const live = await readArtifact("plan", h.paths.files.plan);
    await writeArtifact(
      "plan",
      h.paths.files.plan,
      DeployPlanSchema.parse({ ...live, target: { ...live.target, backups: false } }),
    );
    h.engine.planJsonFor = () =>
      staleServerFirewallPlanJson("module.server_previous.kamatera_server.this");
    const error = await caught(run(h));
    expect(error).toMatchObject({
      code: "PHASE_PRECONDITION",
      message:
        "The plan fails 1 security policy: The server's own firewall has the plan's networks. Nothing was changed.",
    });
    expect(error.hint).toContain("/etc/opscrew/firewall-networks.json");
    expect(error.hint).toContain("will not fall back to the first-boot script");
    expect(h.events.filter((e) => e.type === "approval")).toEqual([]);
    expect(applies(h)).toEqual([]);
  });

  it("a size the new provider cannot create says to abort and start again, never `opscrew design`", async () => {
    const h = await moveHarness();
    h.engine.failApply = (effect) =>
      effect.creates.length > 0
        ? 'Error: Error creating droplet: POST https://api.digitalocean.com/v2/droplets: 422 (request "r1") Size is not available in this region.'
        : undefined;
    const error = await caught(run(h));
    expect(error.code).toBe("ENGINE_FAILED");
    expect(error.hint).toMatch(/^DigitalOcean cannot create a \S+ Droplet in \S+ right now /);
    expect(error.hint).toContain(
      "Run `opscrew retarget --abort` (your app keeps running on the old server on Hetzner Cloud), then start the move again and pick another option: `opscrew retarget --to digitalocean --option <id>`. Nothing that was already created is removed until you abort.",
    );
    expect(error.hint).not.toContain("opscrew design");
    expect((await move(h))?.step).toBe("renamed");
  });

  it("stops when the rename would change more than the state (drift)", async () => {
    const h = await moveHarness();
    h.engine.state.servers = {};
    const error = await caught(run(h));
    expect(error.code).toBe("PHASE_PRECONDITION");
    expect(error.message).toContain("would do more than rename resources");
    expect(error.hint).toContain("opscrew retarget --abort");
    expect(applies(h)).toHaveLength(0);
  });

  it("never prints tokens, the database password or dump contents", async () => {
    const h = await moveHarness();
    const row = fakeSecret("generic-password", "row");
    h.hosts.fail = (ip, op) =>
      op === "restore" && ip === h.newServer.ipv4
        ? fail(
            `pg_restore: error: could not execute query\nDETAIL: Key (email)=(alice@example.com, ${row}) already exists.\nCommand was: COPY public.users (email, secret) FROM stdin;`,
          )
        : undefined;
    await caught(run(h));
    const printed = everythingPrinted(h);
    expect(printed).toContain("could not execute query");
    for (const secret of [row, "alice@example.com", STRIPE, ...Object.values(TOKENS)]) {
      expect(printed).not.toContain(secret);
    }
    const generated = await readFile(join(h.paths.projectHomeDir, "generated_values.json"), "utf8");
    const password = (JSON.parse(generated) as { dbPassword: string }).dbPassword;
    expect(password.length).toBeGreaterThan(8);
    expect(printed).not.toContain(password);
  });
});

describe.skipIf(!findExecutable("git"))("runRetarget on the nginx edge", () => {
  it("sizes the new server for nginx, and stops, checks and starts nginx instead of Caddy", async () => {
    const h = await moveHarness();
    const plan = await readArtifact("plan", h.paths.files.plan);
    await writeArtifact(
      "plan",
      h.paths.files.plan,
      DeployPlanSchema.parse({ ...plan, target: { ...plan.target, edge: "nginx" } }),
    );
    let offered: string[] = [];
    const result = await run(h, {
      choose: async (options) => {
        offered = options.map((option) => option.summary);
        return options.find((option) => option.recommended)?.id ?? (options[0]?.id as string);
      },
    });
    expect(result).toMatchObject({ step: "switched", done: true });
    // The sizing counts nginx's edge (nginx, certbot and kamal-proxy), as the plan's proxy.
    expect(offered.length).toBeGreaterThan(0);
    for (const summary of offered) expect(summary).toContain("behind nginx.");
    const n = h.newServer.ipv4;
    const steps = trail(h.events);
    expect(steps).toContain(`${n} stop nginx`);
    expect(steps).toContain(`${n} start nginx`);
    expect(steps.some((step) => step.includes("caddy"))).toBe(false);
    expect(h.reporter.text()).toContain("Starting nginx on the new");
    expect((await readArtifact("plan", h.paths.files.plan)).target).toMatchObject({
      edge: "nginx",
    });
  });
});

describe.skipIf(!findExecutable("git"))("runRetarget on the OpenLiteSpeed edge", () => {
  it("sizes the new server for OpenLiteSpeed, and stops, checks and starts it instead of Caddy", async () => {
    const h = await moveHarness();
    const plan = await readArtifact("plan", h.paths.files.plan);
    await writeArtifact(
      "plan",
      h.paths.files.plan,
      DeployPlanSchema.parse({ ...plan, target: { ...plan.target, edge: "openlitespeed" } }),
    );
    let offered: string[] = [];
    const result = await run(h, {
      choose: async (options) => {
        offered = options.map((option) => option.summary);
        return options.find((option) => option.recommended)?.id ?? (options[0]?.id as string);
      },
    });
    expect(result).toMatchObject({ step: "switched", done: true });
    expect(offered.length).toBeGreaterThan(0);
    for (const summary of offered) expect(summary).toContain("behind OpenLiteSpeed.");
    const n = h.newServer.ipv4;
    const steps = trail(h.events);
    expect(steps).toContain(`${n} stop openlitespeed`);
    expect(steps).toContain(`${n} start openlitespeed`);
    expect(steps.some((step) => step.includes("caddy"))).toBe(false);
    expect(h.reporter.text()).toContain("Starting OpenLiteSpeed on the new");
    expect((await readArtifact("plan", h.paths.files.plan)).target).toMatchObject({
      edge: "openlitespeed",
    });
  });
});

describe.skipIf(!findExecutable("git"))("runRetarget: the app's origin TLS", () => {
  /** A certificate and key made now, standing in for one Cloudflare issued. */
  const pair = (name: string) => {
    const key = generateP256().privateKey;
    return { key, certificate: selfSignedClientCertificate({ key, commonName: name, days: 1 }) };
  };

  it("the certificates follow the move: the same origin certificate reaches the new server in the same deploy secret", async () => {
    const h = await moveHarness();
    const origin = pair(DOMAIN);
    const client = pair("opscrew-shop");
    // What the last provision left: the record of the app's certificates and their keys.
    await writeFile(
      h.paths.files.cloudflareRecord,
      JSON.stringify({
        zoneId: FAKE_ZONE_ID,
        hostnames: {},
        createdEntrypoints: [],
        tls: {
          origin: {
            id: "o1",
            hostnames: [DOMAIN],
            expiresAt: "2041-10-21T09:00:00.000Z",
            sha256: fingerprintSha256(origin.certificate),
            superseded: [],
          },
          client: {
            id: "c1",
            expiresAt: "2041-10-21T09:00:00.000Z",
            sha256: fingerprintSha256(client.certificate),
            enabled: [DOMAIN],
            retiring: [],
          },
        },
      }),
    );
    const generated = join(h.paths.projectHomeDir, "generated_values.json");
    const earlier = JSON.parse(await readFile(generated, "utf8").catch(() => "{}"));
    await writeFile(
      generated,
      JSON.stringify({
        ...earlier,
        originTls: {
          ORIGIN_TLS_KEY: origin.key,
          ORIGIN_TLS_CERT: origin.certificate,
          ORIGIN_PULL_KEY: client.key,
          ORIGIN_PULL_CERT: client.certificate,
        },
      }),
    );

    const result = await run(h);
    expect(result).toMatchObject({ step: "switched", done: true });
    expect(h.github.secrets.get("OPSCREW_ORIGIN_TLS")).toBe(`${origin.certificate}${origin.key}`);
    // The proxy choice carries over.
    expect((await readArtifact("plan", h.paths.files.plan)).target).toMatchObject({
      provider: "digitalocean",
      edge: "caddy",
    });
    // The generated values keep the keys; nothing printed holds one.
    const kept = JSON.parse(await readFile(generated, "utf8"));
    expect(kept.originTls.ORIGIN_TLS_KEY).toBe(origin.key);
    expect(everythingPrinted(h)).not.toContain(origin.key);
    expect(everythingPrinted(h)).not.toContain(client.key);
  });
});
