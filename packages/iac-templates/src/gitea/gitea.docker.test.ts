import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path, { join } from "node:path";
import { DeployPlanSchema, readArtifact } from "@opscrew/plan-schema";
import { afterAll, describe, expect, it } from "vitest";
import { EDGE_PROJECT } from "../edge";
import {
  GITEA_BOT_USER,
  GITEA_ENV_FILE,
  GITEA_PROJECT,
  giteaBootstrapScript,
  renderGiteaCompose,
} from "./index";

/*
 * Docker-gated integration test for self-hosted Gitea against the pinned rootless image:
 * verifies renderGiteaCompose -> docker compose up -d --wait -> giteaBootstrapScript (stdin-only
 * password delivery, non-admin bot user, scoped token generation, .bootstrapped marker) ->
 * /api/healthz -> /api/v1/user authenticated with the bot token -> docker compose down -v.
 * Runs only when OPSCREW_DOCKER_TESTS=1 on a host with a Linux Docker engine and sh.
 */

function skipReason(): string | undefined {
  if (process.env.OPSCREW_DOCKER_TESTS !== "1") return "set OPSCREW_DOCKER_TESTS=1 to run it";
  const info = spawnSync("docker", ["info", "--format", "{{.OSType}}"], { encoding: "utf8" });
  if (info.status !== 0 || info.stdout.trim() !== "linux") {
    return "no Docker engine for Linux containers is running";
  }
  const sh = spawnSync("sh", ["-c", "echo ok"], { encoding: "utf8" });
  return sh.stdout?.trim() === "ok" ? undefined : "POSIX sh is not available";
}

const reason = skipReason();
if (reason) console.warn(`[iac-templates] skipping the Gitea Docker check: ${reason}`);

const PLAN_FIXTURE = path.resolve(
  import.meta.dirname,
  "../../../plan-schema/src/__fixtures__/plan.yaml",
);

const runId = randomBytes(4).toString("hex");
const testProject = `opscrew-gitea-test-${runId}`;
const testEdgeNet = `opscrew-edge-test-${runId}`;
let workDir: string | undefined;

function run(cmd: string, args: string[], options: { cwd?: string; input?: string } = {}): string {
  const res = spawnSync(cmd, args, {
    cwd: options.cwd,
    input: options.input,
    encoding: "utf8",
  });
  if (res.status !== 0) {
    throw new Error(`${cmd} ${args.join(" ")} failed:\n${res.stdout}\n${res.stderr}`);
  }
  return res.stdout.trim();
}

describe.skipIf(reason !== undefined)("self-hosted Gitea Docker lifecycle", () => {
  afterAll(() => {
    if (workDir !== undefined) {
      spawnSync("docker", ["compose", "-p", testProject, "down", "-v"], { cwd: workDir });
      rmSync(workDir, { recursive: true, force: true });
    }
    spawnSync("docker", ["network", "rm", testEdgeNet]);
  });

  it("enables, bootstraps admin + non-admin bot token over stdin, answers /api/healthz, and disables cleanly", async () => {
    const base = await readArtifact("plan", PLAN_FIXTURE);
    const plan = DeployPlanSchema.parse({
      ...base,
      gitea: {
        enabled: true,
        version: "28.4.0",
        hostname: "git.example.com",
        database: "sqlite",
        adminEmail: "admin@example.com",
      },
    });
    const gitea = plan.gitea;
    if (!gitea) throw new Error("expected gitea");

    workDir = mkdtempSync(join(tmpdir(), "opscrew-gitea-docker-"));
    run("docker", ["network", "create", testEdgeNet]);

    // Isolate the Compose project name and external edge network for this test run.
    const composeYaml = renderGiteaCompose(plan, gitea)
      .replaceAll(`name: ${GITEA_PROJECT}`, `name: ${testProject}`)
      .replaceAll(EDGE_PROJECT, testEdgeNet);
    writeFileSync(join(workDir, "compose.yaml"), composeYaml, { mode: 0o644 });

    const secretKey = randomBytes(32).toString("hex");
    const internalToken = randomBytes(64).toString("base64url");
    const jwtSecret = randomBytes(32).toString("base64url");
    const lfsJwtSecret = randomBytes(32).toString("base64url");
    writeFileSync(
      join(workDir, GITEA_ENV_FILE),
      [
        `GITEA__security__SECRET_KEY=${secretKey}`,
        `GITEA__security__INTERNAL_TOKEN=${internalToken}`,
        `GITEA__oauth2__JWT_SECRET=${jwtSecret}`,
        `GITEA__lfs__JWT_SECRET=${lfsJwtSecret}`,
      ].join("\n"),
      { mode: 0o600 },
    );

    run("docker", ["compose", "-p", testProject, "up", "-d", "--wait"], { cwd: workDir });

    const bootstrap = giteaBootstrapScript(gitea).replaceAll(GITEA_PROJECT, testProject);
    writeFileSync(join(workDir, "bootstrap.sh"), bootstrap, { mode: 0o700 });
    const adminPassword = randomBytes(18).toString("base64url");
    const botPassword = randomBytes(18).toString("base64url");
    run("sh", ["bootstrap.sh"], {
      cwd: workDir,
      input: `GITEA_ADMIN_PASSWORD=${adminPassword}\nGITEA_BOT_PASSWORD=${botPassword}\n`,
    });

    const token = readFileSync(join(workDir, ".app-token"), "utf8").trim();
    expect(token.length).toBeGreaterThan(20);

    const health = run(
      "docker",
      [
        "compose",
        "-p",
        testProject,
        "exec",
        "-T",
        "gitea",
        "wget",
        "-q",
        "-O",
        "-",
        "http://127.0.0.1:3000/api/healthz",
      ],
      { cwd: workDir },
    );
    expect(health).toContain("pass");

    // Verify the generated token authenticates as the non-admin opscrew-bot user.
    const whoami = run(
      "docker",
      [
        "compose",
        "-p",
        testProject,
        "exec",
        "-T",
        "gitea",
        "wget",
        "-q",
        "-O",
        "-",
        "--header",
        `Authorization: token ${token}`,
        "http://127.0.0.1:3000/api/v1/user",
      ],
      { cwd: workDir },
    );
    const parsedUser = JSON.parse(whoami) as { login?: string; is_admin?: boolean };
    expect(parsedUser.login).toBe(GITEA_BOT_USER);
    expect(parsedUser.is_admin).toBe(false);

    run("docker", ["compose", "-p", testProject, "down", "-v"], { cwd: workDir });
    const remaining = run("docker", ["compose", "-p", testProject, "ps", "-aq"], { cwd: workDir });
    expect(remaining).toBe("");
  }, 180_000);
});
