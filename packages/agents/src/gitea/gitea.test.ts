import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import type {
  ApprovalDecision,
  ApprovalRequest,
  CommandResult,
  RemoteExec,
} from "@opscrew/contracts";
import { Redactor, resolveProjectPaths } from "@opscrew/core";
import { readArtifact, writeArtifact } from "@opscrew/plan-schema";
import { afterEach, describe, expect, it } from "vitest";
import type { PhaseDeps } from "../context";
import {
  describeGiteaStatus,
  giteaDisable,
  giteaEnable,
  giteaSettings,
  giteaStatusOf,
  readGiteaSecrets,
} from "./index";

const PLAN_FIXTURE = path.resolve(
  import.meta.dirname,
  "../../../plan-schema/src/__fixtures__/plan.yaml",
);

const tempDirs: string[] = [];

afterEach(async () => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir !== undefined) await rm(dir, { recursive: true, force: true });
  }
});

async function makeWorkspace(approve = true): Promise<{
  deps: PhaseDeps;
  approvals: ApprovalRequest[];
  remote: RemoteExec;
  calls: { command: string; input?: string }[];
  auditDir: string;
}> {
  const dir = await mkdtemp(path.join(tmpdir(), "opscrew-gitea-agent-"));
  tempDirs.push(dir);
  const home = path.join(dir, "home");
  const root = path.join(dir, "repo");
  const paths = resolveProjectPaths(root, { homedir: home, env: {} });
  const base = await readArtifact("plan", PLAN_FIXTURE);
  await writeArtifact("plan", paths.files.plan, base);

  const approvals: ApprovalRequest[] = [];
  const auditEntries: unknown[] = [];
  const calls: { command: string; input?: string }[] = [];
  const redactor = new Redactor();
  const audit = {
    async append(entry: unknown): Promise<void> {
      auditEntries.push(entry);
    },
  };
  const remote: RemoteExec = {
    host: "198.51.100.10",
    async run(command, options): Promise<CommandResult> {
      calls.push({ command, ...(options?.input === undefined ? {} : { input: options.input }) });
      if (command.includes("echo state=change") && command.includes("echo state=in-place")) {
        return { exitCode: 0, stdout: "state=change\n", stderr: "" };
      }
      if (command.includes("cat ") && command.includes(".app-token")) {
        return { exitCode: 0, stdout: "syntheticbottoken0123456789abcdef\n", stderr: "" };
      }
      return { exitCode: 0, stdout: "ok\n", stderr: "" };
    },
  };

  const deps = {
    paths,
    env: {},
    redactor,
    audit,
    reporter: {
      info: () => {},
      warn: () => {},
      error: () => {},
      success: () => {},
      step: () => {},
    },
    approvals: {
      async request(req: ApprovalRequest): Promise<ApprovalDecision> {
        approvals.push(req);
        return {
          approved: approve,
          approver: "tester",
          decidedAt: "2026-11-28T09:00:00.000Z",
        };
      },
    },
  } as unknown as PhaseDeps;

  return { deps, approvals, remote, calls, auditDir: paths.auditDir };
}

describe("giteaEnable / giteaDisable / giteaStatusOf", () => {
  it("supports --plan-only without mutating the server, plan.yaml, or secrets", async () => {
    const { deps, approvals, remote, calls } = await makeWorkspace(true);
    const plan = await readArtifact("plan", deps.paths.files.plan);

    const res = await giteaEnable(deps, plan, {
      hostname: "git.example.com",
      adminEmail: "admin@example.com",
      planOnly: true,
      skipOtherAppsCheck: true,
      services: { remote },
    });

    expect(res.hostApplied).toBe(false);
    expect(res.hostPlanHash).toMatch(/^[0-9a-f]{64}$/);
    expect(res.policies.every((p) => p.passed)).toBe(true);
    expect(res.connection?.apiUrl).toBe("https://git.example.com/api/v1");
    expect(approvals).toHaveLength(0);
    expect(calls).toHaveLength(0);
    expect(await readGiteaSecrets(deps)).toBeUndefined();
  });

  it("blocks when registration is enabled (SecOps policy violation) before asking approval", async () => {
    const { deps, approvals, remote } = await makeWorkspace(true);
    const plan = await readArtifact("plan", deps.paths.files.plan);

    await expect(
      giteaEnable(deps, plan, {
        hostname: "git.example.com",
        adminEmail: "admin@example.com",
        disableRegistration: false,
        skipOtherAppsCheck: true,
        services: { remote },
      }),
    ).rejects.toThrow(/gitea-registration-disabled/);
    expect(approvals).toHaveLength(0);
  });

  it("enables Gitea with hash-bound approval, delivers secrets only via stdin, and keeps secrets out of plan and audit", async () => {
    const { deps, approvals, remote, calls } = await makeWorkspace(true);
    const plan = await readArtifact("plan", deps.paths.files.plan);

    const res = await giteaEnable(deps, plan, {
      hostname: "git.example.com",
      adminEmail: "admin@example.com",
      database: "postgres",
      webhookPath: "/api/webhooks/gitea",
      skipOtherAppsCheck: true,
      services: { remote },
    });

    expect(res.hostApplied).toBe(true);
    expect(res.status.enabled).toBe(true);
    expect(res.status.database).toBe("postgres");
    expect(res.connection?.webhook.targetUrl).toBe(`https://${plan.dns.domain}/api/webhooks/gitea`);
    expect(approvals).toHaveLength(1);
    expect(approvals[0]?.kind).toBe("host-apply");
    expect(approvals[0]?.planHash).toBe(res.hostPlanHash);

    const savedSecrets = await readGiteaSecrets(deps);
    if (savedSecrets === undefined || savedSecrets.postgresPassword === undefined) {
      throw new Error("expected saved Gitea secrets with postgresPassword");
    }
    expect(savedSecrets.postgresPassword).toMatch(/^[0-9a-f]{64}$/);
    expect(savedSecrets.botPassword).toBeDefined();
    expect(savedSecrets.appApiToken).toBe("syntheticbottoken0123456789abcdef");
    expect(deps.redactor.redact("syntheticbottoken0123456789abcdef")).not.toContain(
      "syntheticbottoken0123456789abcdef",
    );

    // Verify zero secrets leaked into opcrew/plan.yaml, status text, or remote commands
    const planText = await readFile(deps.paths.files.plan, "utf8");
    const statusText = describeGiteaStatus(
      await giteaStatusOf(deps, await readArtifact("plan", deps.paths.files.plan)),
    );
    expect(statusText).toContain("https://git.example.com/api/v1");
    expect(statusText).toContain("X-Gitea-Signature");

    for (const secretValue of [
      savedSecrets.adminPassword,
      savedSecrets.botPassword ?? "",
      savedSecrets.secretKey,
      savedSecrets.internalToken,
      savedSecrets.webhookSecret,
      savedSecrets.appApiToken ?? "",
      savedSecrets.postgresPassword,
    ]) {
      expect(planText).not.toContain(secretValue);
      expect(statusText).not.toContain(secretValue);
      for (const call of calls) {
        expect(call.command).not.toContain(secretValue);
      }
    }
  });

  it("fails closed when local gitea_secrets.json is damaged", async () => {
    const { deps, remote } = await makeWorkspace(true);
    const plan = await readArtifact("plan", deps.paths.files.plan);
    await writeFile(deps.paths.files.giteaSecrets, "{broken", "utf8").catch(async () => {
      const { mkdir } = await import("node:fs/promises");
      await mkdir(path.dirname(deps.paths.files.giteaSecrets), { recursive: true });
      await writeFile(deps.paths.files.giteaSecrets, "{broken", "utf8");
    });

    await expect(
      giteaEnable(deps, plan, {
        hostname: "git.example.com",
        adminEmail: "admin@example.com",
        skipOtherAppsCheck: true,
        services: { remote },
      }),
    ).rejects.toThrow(/damaged/);
  });

  it("disables Gitea keeping volumes by default, and requires allowDestroy + confirmName when keepData is false", async () => {
    const { deps, approvals, remote } = await makeWorkspace(true);
    const plan = await readArtifact("plan", deps.paths.files.plan);
    await giteaEnable(deps, plan, {
      hostname: "git.example.com",
      adminEmail: "admin@example.com",
      skipOtherAppsCheck: true,
      services: { remote },
    });
    const enabledPlan = await readArtifact("plan", deps.paths.files.plan);

    // Default keepData: true -> no allowDestroy, secrets kept
    const kept = await giteaDisable(deps, enabledPlan, {
      skipOtherAppsCheck: true,
      services: { remote },
    });
    expect(kept.hostApplied).toBe(true);
    expect(kept.status.enabled).toBe(false);
    expect(approvals.at(-1)?.allowDestroy).toBeUndefined();
    expect(await readGiteaSecrets(deps)).toBeDefined();

    // Explicit keepData: false -> allowDestroy + resource-name confirmPhrase required, secrets removed
    const destroyed = await giteaDisable(deps, enabledPlan, {
      keepData: false,
      skipOtherAppsCheck: true,
      services: { remote },
    });
    expect(destroyed.hostApplied).toBe(true);
    expect(approvals.at(-1)?.allowDestroy).toBe(true);
    expect(approvals.at(-1)?.confirmPhrase).toBe("git.example.com");
    expect(await readGiteaSecrets(deps)).toBeUndefined();
  });

  it("refuses silent database engine switch in place and preserves existing version on re-enable", async () => {
    const { deps, remote } = await makeWorkspace(true);
    const plan = await readArtifact("plan", deps.paths.files.plan);
    await giteaEnable(deps, plan, {
      hostname: "git.example.com",
      adminEmail: "admin@example.com",
      database: "sqlite",
      skipOtherAppsCheck: true,
      services: { remote },
    });
    const enabledPlan = await readArtifact("plan", deps.paths.files.plan);

    await expect(
      giteaEnable(deps, enabledPlan, {
        database: "postgres",
        skipOtherAppsCheck: true,
        services: { remote },
      }),
    ).rejects.toThrow(/switching to `postgres` in place/);

    const pinnedOld = {
      ...enabledPlan,
      gitea: enabledPlan.gitea ? { ...enabledPlan.gitea, version: "27.1.0" } : undefined,
    };
    expect(giteaSettings(pinnedOld, {}).version).toBe("27.1.0");
    await expect(
      giteaEnable(deps, pinnedOld, {
        planOnly: true,
        skipOtherAppsCheck: true,
        services: { remote },
      }),
    ).rejects.toThrow(/gitea-image-pinned/);
  });

  it("enforces ADR 0035 other-apps check on cloud servers unless skipped", async () => {
    const { deps, approvals, remote, calls } = await makeWorkspace(true);
    const plan = await readArtifact("plan", deps.paths.files.plan);
    await expect(
      giteaEnable(deps, plan, {
        hostname: "git.example.com",
        adminEmail: "admin@example.com",
        services: { remote },
      }),
    ).rejects.toThrow(/other apps/);
    expect(approvals).toHaveLength(0);
    expect(calls).toHaveLength(0);
  });

  it("refuses a second app sharing a first app's server before touching anything (ADR 0035)", async () => {
    const { deps, approvals, remote, calls } = await makeWorkspace(true);
    const base = await readArtifact("plan", deps.paths.files.plan);
    const sharedPlan = {
      ...base,
      target: {
        provider: "own" as const,
        mode: "vps-compose" as const,
        arch: "amd64" as const,
        access: "public" as const,
        edge: "caddy" as const,
        shares: { app: "first-app", provider: "hetzner" as const },
      },
    };
    await expect(
      giteaEnable(deps, sharedPlan, {
        hostname: "git.example.com",
        adminEmail: "admin@example.com",
        services: { remote },
      }),
    ).rejects.toThrow(/first-app/);
    await expect(
      giteaDisable(deps, sharedPlan, { keepData: false, services: { remote } }),
    ).rejects.toThrow(/first-app/);
    expect(approvals).toHaveLength(0);
    expect(calls).toHaveLength(0);
  });
});
