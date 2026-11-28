import type { CommandResult, RemoteExec } from "@opscrew/contracts";
import { describe, expect, it } from "vitest";
import { applyHostPlan } from "./apply";
import { giteaStepScripts, planGitea } from "./gitea";
import { hostPlanHash } from "./hash";

const SAMPLE_COMPOSE = [
  "name: opscrew-gitea",
  "services:",
  "  gitea:",
  "    image: gitea/gitea:28.4.0-rootless@sha256:15ab7fadb44981a2b781f40c712cad07066197f395100ea1c6326e14e5bb073a",
  "    env_file:",
  "      - gitea.env",
].join("\n");

const SAMPLE_PROXY = [
  {
    filename: "opscrew-gitea.caddy",
    content: "git.example.com {\n\treverse_proxy opscrew-gitea:3000\n}\n",
  },
];

function stubRemote(): {
  remote: RemoteExec;
  calls: { command: string; stdin?: string }[];
} {
  const calls: { command: string; stdin?: string }[] = [];
  const remote: RemoteExec = {
    host: "198.51.100.10",
    async run(command, options): Promise<CommandResult> {
      calls.push({ command, ...(options?.input === undefined ? {} : { stdin: options.input }) });
      if (command.includes("echo state=change") && command.includes("echo state=in-place")) {
        return { exitCode: 0, stdout: "state=change\n", stderr: "" };
      }
      return { exitCode: 0, stdout: "ok\n", stderr: "" };
    },
  };
  return { remote, calls };
}

describe("planGitea & applyHostPlan(gitea)", () => {
  it("builds a deterministic hash-bound plan without secrets and refuses wrong hash or missing secrets", async () => {
    const plan = planGitea({
      app: "shop",
      runAs: "login",
      enable: {
        composeYaml: SAMPLE_COMPOSE,
        proxy: "caddy",
        proxyFiles: SAMPLE_PROXY,
        bootstrapScript: "echo ok\n",
        usePostgres: false,
        hostname: "git.example.com",
        version: "28.4.0",
      },
    });
    const hash = hostPlanHash(plan);
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(plan)).not.toContain("GITEA__security__SECRET_KEY");

    const { remote } = stubRemote();
    await expect(
      applyHostPlan(remote, plan, {
        approvedHash: "0".repeat(64),
        command: "opscrew addon enable gitea",
        verifyLogin: async () => true,
      }),
    ).rejects.toThrow(/not the one that was approved/);

    await expect(
      applyHostPlan(remote, plan, {
        approvedHash: hash,
        command: "opscrew addon enable gitea",
        verifyLogin: async () => true,
      }),
    ).rejects.toThrow(/Gitea's secret environment file/);
  });

  it("delivers Gitea secrets strictly via base64 stdin and applies/verifies cleanly", async () => {
    const plan = planGitea({
      app: "shop",
      runAs: "login",
      enable: {
        composeYaml: SAMPLE_COMPOSE,
        proxy: "nginx",
        proxyFiles: [
          {
            filename: "opscrew-gitea.conf",
            content: "server { server_name git.example.com; }\n",
          },
        ],
        bootstrapScript: "echo boot\n",
        usePostgres: true,
        hostname: "git.example.com",
        version: "28.4.0",
      },
    });
    const hash = hostPlanHash(plan);
    const { remote, calls } = stubRemote();

    const giteaEnv = "GITEA__security__SECRET_KEY=syntheticsecretkeyvalue0123456789\n";
    const giteaPostgresEnv =
      "POSTGRES_DB=gitea\nPOSTGRES_USER=gitea\nPOSTGRES_PASSWORD=syntheticpgpass0123456789\n";
    const giteaBootstrapEnv = "GITEA_ADMIN_PASSWORD=syntheticadminpass0123456789\n";

    const result = await applyHostPlan(remote, plan, {
      approvedHash: hash,
      command: "opscrew addon enable gitea",
      verifyLogin: async () => true,
      secrets: { giteaEnv, giteaPostgresEnv, giteaBootstrapEnv },
    });

    expect(result.applied).toEqual(["gitea"]);
    const checkCall = calls.find(
      (c) => c.command.includes("echo state=change") && c.command.includes("echo state=in-place"),
    );
    expect(checkCall?.command).toContain(".owner");
    expect(checkCall?.command).toContain(".bootstrapped");
    expect(checkCall?.command).toContain(".app-token");

    const applyCall = calls.find((c) => c.stdin !== undefined);
    expect(applyCall).toBeDefined();
    expect(applyCall?.command).not.toContain("syntheticsecretkeyvalue0123456789");
    expect(applyCall?.command).not.toContain("syntheticpgpass0123456789");
    expect(applyCall?.command).not.toContain("syntheticadminpass0123456789");
    expect(applyCall?.command).toContain("chmod 600");
    expect(applyCall?.command).toContain(".owner.tmp");
    expect(applyCall?.command).toContain('rm -f "$DIR/.bootstrapped"');
    expect(applyCall?.command).toContain("nginx -t && nginx -s reload");
    const stdinLines = (applyCall?.stdin ?? "").trim().split("\n");
    expect(stdinLines).toHaveLength(3);
    expect(Buffer.from(stdinLines[0] ?? "", "base64").toString("utf8")).toBe(giteaEnv);
    expect(Buffer.from(stdinLines[1] ?? "", "base64").toString("utf8")).toBe(giteaPostgresEnv);
    expect(Buffer.from(stdinLines[2] ?? "", "base64").toString("utf8")).toBe(giteaBootstrapEnv);
  });

  it("enforces owner lock on disable, keeps volumes by default, and verifies volumes are gone when keepData is false", () => {
    const keepPlan = planGitea({
      app: "shop",
      runAs: "login",
      disable: { proxy: "caddy", keepData: true },
    });
    const keepStep = keepPlan.steps[0];
    if (!keepStep) throw new Error("expected step");
    const keepScripts = giteaStepScripts(keepStep);
    expect(keepScripts.check).toContain(".owner");
    expect(keepScripts.apply).toContain(".owner");
    expect(keepScripts.apply).toContain("down >/dev/null");
    expect(keepScripts.apply).not.toContain("down -v");
    expect(keepScripts.verify).not.toContain("docker volume inspect");

    const dropPlan = planGitea({
      app: "shop",
      runAs: "login",
      disable: { proxy: "caddy", keepData: false },
    });
    const dropStep = dropPlan.steps[0];
    if (!dropStep) throw new Error("expected step");
    const dropScripts = giteaStepScripts(dropStep);
    expect(dropScripts.apply).toContain("down -v");
    expect(dropScripts.apply).toContain("docker volume rm -f");
    expect(dropScripts.verify).toContain("docker volume inspect");
  });
});
