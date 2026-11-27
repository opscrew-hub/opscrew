/**
 * Real Docker `floci` (`floci/floci`, MIT, port 4566) + OpenTofu integration test (Feature 034, T3411).
 *
 * Runs only when `OPSCREW_DOCKER_TESTS=1` is set AND both `docker` and `tofu` are available.
 * Renders real AWS OpenTofu HCL pointed at the local `floci` endpoint, runs `tofu init`,
 * `tofu validate`, `tofu plan`, `tofu apply`, and `tofu destroy`, and guarantees container cleanup
 * in `finally` so zero leftover containers or networks remain.
 */
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";
import { designAwsTarget } from "./design";
import { renderAwsHcl } from "./hcl";

const execFileAsync = promisify(execFile);
const RUN_DOCKER_TESTS = process.env.OPSCREW_DOCKER_TESTS === "1";

async function runCmd(
  bin: string,
  args: readonly string[],
  options?: { cwd?: string; env?: NodeJS.ProcessEnv; timeout?: number },
): Promise<{ stdout: string; stderr: string }> {
  return execFileAsync(bin, [...args], {
    cwd: options?.cwd,
    env: options?.env ?? process.env,
    timeout: options?.timeout ?? 180_000,
    maxBuffer: 10 * 1024 * 1024,
  });
}

async function waitForFloci(url: string, timeoutMs = 45_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url);
      if (res.status > 0) return;
    } catch {
      // Wait for container to listen.
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error(`floci did not become ready at ${url} within ${timeoutMs}ms`);
}

describe.skipIf(!RUN_DOCKER_TESTS)(
  "AWS HCL real OpenTofu integration against floci (T3411)",
  () => {
    it("runs tofu init, validate, plan, apply, and destroy cleanly against floci/floci", async () => {
      const containerName = `opscrew-floci-test-${Date.now()}`;
      const hostPort = 14566 + Math.floor(Math.random() * 500);
      const endpointUrl = `http://127.0.0.1:${hostPort}`;
      const tmpDir = await mkdtemp(path.join(os.tmpdir(), "opscrew-aws-floci-"));
      const tofuBin = process.env.OPSCREW_TOFU_BIN ?? "tofu";

      try {
        await runCmd("docker", [
          "run",
          "-d",
          "--rm",
          "--name",
          containerName,
          "-p",
          `127.0.0.1:${hostPort}:4566`,
          "floci/floci:latest",
        ]);
        await waitForFloci(endpointUrl);

        const { target } = designAwsTarget({
          facts: {
            appKind: "fullstack",
            languages: ["typescript"],
            services: [{ kind: "s3", evidence: ["S3_BUCKET"], variable: "S3_BUCKET" }],
          },
          requirements: {
            region: "us-east",
            expectedMonthlyUsers: "<1k",
            uptime: "standard",
            dataCriticality: "important",
            budgetMonthly: { amount: 25, currency: "USD" },
          },
          preset: "lean",
        });

        // Render core VPC, S3 + Block Public Access, Secrets shell, CloudWatch Log Group, and IAM OIDC files.
        const files = renderAwsHcl({
          appName: "floci-demo",
          environment: "prod",
          infraDir: ".",
          target,
          github: { owner: "acme", repo: "floci-demo", environmentName: "prod" },
          endpointUrl,
          createOidcProvider: true,
        });

        // Write rendered foundation HCL files supported by floci.
        const selected = new Set([
          "providers.tf",
          "variables.tf",
          "vpc.tf",
          "storage.tf",
          "secrets.tf",
          "observability.tf",
        ]);
        for (const file of files) {
          const baseName = path.posix.basename(file.path);
          if (!selected.has(baseName)) continue;
          const dest = path.join(tmpDir, baseName);
          await mkdir(path.dirname(dest), { recursive: true });
          await writeFile(dest, file.content, "utf8");
        }

        const pluginCacheDir =
          process.env.TF_PLUGIN_CACHE_DIR ??
          path.join(process.env.OPSCREW_TEST_TMP ?? os.tmpdir(), "tofu-plugin-cache");
        await mkdir(pluginCacheDir, { recursive: true });
        const env = {
          ...process.env,
          TF_PLUGIN_CACHE_DIR: pluginCacheDir,
          AWS_ACCESS_KEY_ID: "test",
          AWS_SECRET_ACCESS_KEY: "test",
          AWS_DEFAULT_REGION: "us-east-1",
          AWS_REGION: "us-east-1",
        };

        await runCmd(tofuBin, ["init", "-input=false", "-no-color"], { cwd: tmpDir, env });
        const validate = await runCmd(tofuBin, ["validate", "-no-color"], { cwd: tmpDir, env });
        expect(validate.stdout).toContain("Success!");

        await runCmd(tofuBin, ["plan", "-input=false", "-no-color", "-out=tfplan"], {
          cwd: tmpDir,
          env,
        });
        const apply = await runCmd(tofuBin, ["apply", "-input=false", "-no-color", "tfplan"], {
          cwd: tmpDir,
          env,
        });
        expect(apply.stdout).toContain("Apply complete!");

        const destroy = await runCmd(
          tofuBin,
          ["destroy", "-auto-approve", "-input=false", "-no-color"],
          { cwd: tmpDir, env },
        );
        expect(destroy.stdout).toContain("Destroy complete!");
      } finally {
        await runCmd("docker", ["rm", "-f", containerName]).catch(() => undefined);
        await rm(tmpDir, { recursive: true, force: true }).catch(() => undefined);
      }
    }, 300_000);
  },
);
