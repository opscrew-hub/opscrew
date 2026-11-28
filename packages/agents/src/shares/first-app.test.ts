import { rm } from "node:fs/promises";
import { join } from "node:path";
import { type DeployPlan, DeployPlanSchema, writeArtifact } from "@opscrew/plan-schema";
import { describe, expect, it } from "vitest";
import { appMemoryMb } from "../shared/memory";
import { closedPlan } from "../shared/server-address";
import { recordOwnServer, type SharesReference } from "../shared/server-record";
import {
  ED25519,
  ED25519_FINGERPRINT,
  hostTestPlan,
  ownPlan,
  previewTestPlan,
  SERVER_IPV4,
  sharedPreviewTestPlan,
  sharedServerProject,
  testPlan,
  withLaptop,
} from "../testing";
import { firstApp, hostDescription } from "./first-app";
import { firstAppPaths } from "./reference";

/** A shared-server project whose first app's plan is `plan`. */
async function withPlan(plan: DeployPlan) {
  return sharedServerProject({ plan });
}

/** Expects `firstApp` to refuse before any change with `message`. */
async function refuses(
  project: Awaited<ReturnType<typeof sharedServerProject>>,
  message: RegExp,
  ref: SharesReference = project.ref,
) {
  const error = await firstApp(project.deps, ref).then(
    () => undefined,
    (thrown: unknown) => thrown as { code: string; message: string; hint?: string },
  );
  expect(error).toMatchObject({ code: "PHASE_PRECONDITION", message });
  expect(error?.message).toMatch(/Nothing was changed\.$/);
  expect(JSON.stringify(error)).not.toContain(project.firstKey);
  return error;
}

describe("firstApp", () => {
  it("reads the first app's plan, address, deploy login and pinned host key from its folder", async () => {
    const project = await sharedServerProject();
    const first = await firstApp(project.deps, project.ref);
    expect(first.paths).toEqual(project.first);
    expect(first.plan.app.name).toBe("shop");
    expect(first.address).toEqual({ ipv4: SERVER_IPV4 });
    expect(first.login).toEqual({ host: SERVER_IPV4, port: 22 });
    expect(first.keyFile).toBe(project.first.files.deployKey);
    expect(first.hostKey).toEqual({
      type: "ssh-ed25519",
      key: ED25519,
      fingerprint: ED25519_FINGERPRINT,
    });
    expect(JSON.stringify(first)).not.toContain(project.firstKey);
  });

  it("refuses a folder with no plan", async () => {
    const project = await sharedServerProject();
    await rm(project.first.files.plan);
    const error = await refuses(project, /^The app in .+ has no OpsCrew plan on this computer\./);
    expect(error?.hint).toContain("run `opscrew interview` again and name the folder");
  });

  it("refuses a first app that is not provisioned", async () => {
    const project = await withPlan(testPlan({ domain: "shop.example.com" }));
    const error = await refuses(project, /^"shop" is not provisioned on this computer/);
    expect(error?.hint).toContain("`opscrew provision`");
  });

  it("refuses an app that is not on a server OpsCrew created", async () => {
    const project = await withPlan(ownPlan({ deployed: true }));
    await refuses(project, /^"shop" does not run on a server OpsCrew created/);
  });

  it("refuses a preview environment", async () => {
    const project = await sharedServerProject();
    const ref = { ...project.ref, environment: "preview" };
    await writeArtifact(
      "plan",
      firstAppPaths(project.deps.paths, ref).files.plan,
      previewTestPlan(),
    );
    await refuses(project, /^"shop-preview" is a preview environment/, ref);
  });

  it("refuses a server previews of its repository run on", async () => {
    const project = await sharedServerProject();
    const ref = { ...project.ref, environment: "dev" };
    const dev = firstAppPaths(project.deps.paths, ref);
    await writeArtifact("plan", dev.files.plan, hostTestPlan());
    await writeArtifact(
      "plan",
      firstAppPaths(project.deps.paths, { ...ref, environment: "preview" }).files.plan,
      sharedPreviewTestPlan(),
    );
    await refuses(
      project,
      /^The previews of the preview environment run on "shop-dev"'s server/,
      ref,
    );
  });

  it("refuses a first app in the middle of a move to another server", async () => {
    const base = testPlan({ deployed: true, domain: "shop.example.com" });
    const plan = DeployPlanSchema.parse({
      ...base,
      retarget: {
        from: { target: base.target },
        step: "created",
        startedAt: "2026-11-05T12:00:00.000Z",
      },
    });
    const project = await withPlan(plan);
    const error = await refuses(project, /^"shop" is in the middle of a move to another server/);
    expect(error?.hint).toMatch(/opscrew retarget --finish/);
  });

  it("refuses a server whose public SSH is closed", async () => {
    const plan = closedPlan(withLaptop(testPlan({ deployed: true, domain: "shop.example.com" })));
    const project = await withPlan(plan);
    await refuses(project, /^"shop"'s server takes no public SSH/);
  });

  it("refuses a server on a private network or a VPN", async () => {
    const project = await withPlan(
      withLaptop(testPlan({ deployed: true, domain: "shop.example.com" })),
    );
    await refuses(project, /^"shop"'s server is on a private network/);
  });

  it("refuses an app that is itself a second app, naming its first app", async () => {
    const base = ownPlan({ deployed: true });
    const plan = DeployPlanSchema.parse({
      ...base,
      app: { ...base.app, name: "inventory" },
      target: { ...base.target, shares: { app: "blog", provider: "hetzner" } },
    });
    const project = await withPlan(plan);
    const blog = join(project.deps.paths.root, "elsewhere", "blog");
    await recordOwnServer(project.first, {
      host: SERVER_IPV4,
      user: "deploy",
      agent: false,
      keyPath: project.first.files.deployKey,
      shares: { root: blog },
    });
    const error = await refuses(
      project,
      /^"inventory" itself runs on the server of "blog", which OpsCrew created for that app\./,
    );
    expect(error?.hint).toContain(blog);
  });

  it("refuses when this computer lacks the server's pinned host key", async () => {
    const project = await sharedServerProject();
    await rm(project.first.files.knownHosts);
    await refuses(
      project,
      /^This computer does not have the pinned SSH host key of "shop"'s server\./,
    );
  });

  it("refuses when this computer lacks the first app's deploy key", async () => {
    const project = await sharedServerProject();
    await rm(project.first.files.deployKey);
    await refuses(project, /^This computer does not have the deploy key of "shop"\./);
  });
});

describe("hostDescription", () => {
  it("describes a proxied first app: every hostname, the web filter and its memory", () => {
    const plan = testPlan({ deployed: true, domain: "shop.example.com", www: true });
    expect(hostDescription(plan)).toEqual({
      app: "shop",
      hostnames: ["shop.example.com", "www.shop.example.com"],
      access: "web-filter",
      memoryMb: appMemoryMb(plan),
    });
  });

  it("describes a first app served with DNS only as public", () => {
    const base = testPlan({ deployed: true, domain: "shop.example.com" });
    const plan = DeployPlanSchema.parse({ ...base, dns: { ...base.dns, proxied: false } });
    expect(hostDescription(plan).access).toBe("public");
  });

  it("counts the subdomains of the first app's dashboards among its hostnames", () => {
    expect(hostDescription(ownPlan({ portainer: "subdomain" })).hostnames).toEqual([
      "portainer.example.com",
      "shop.example.com",
    ]);
    const base = ownPlan({ portainer: "subdomain" });
    const beszel = DeployPlanSchema.parse({
      ...base,
      portainer: undefined,
      observability: {
        beszel: {
          enabled: true,
          version: "0.12.10",
          mode: "hub",
          access: "subdomain",
          hostname: "beszel.example.com",
          allowedEmails: ["owner@example.com"],
        },
      },
    });
    expect(hostDescription(beszel).hostnames).toEqual(["beszel.example.com", "shop.example.com"]);
    const withGitea = DeployPlanSchema.parse({
      ...base,
      portainer: undefined,
      gitea: {
        enabled: true,
        version: "28.4.0",
        hostname: "git.example.com",
        adminEmail: "ops@example.com",
      },
    });
    expect(hostDescription(withGitea).hostnames).toEqual(["git.example.com", "shop.example.com"]);
  });
});
