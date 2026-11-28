/**
 * Real OpenTofu schema validation against `hashicorp/google ~> 8.0` (Feature 039, T3908).
 * Skipped during offline unit tests unless `OPSCREW_IT=1` is set.
 */
import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import type { ProjectFacts, Requirements } from "@opscrew/plan-schema";
import { afterEach, describe, expect, it } from "vitest";
import { applyGcpOverrides, designGcpTarget, renderGcpHcl } from "./index";

const execFileAsync = promisify(execFile);
const IT_ENABLED = process.env.OPSCREW_IT === "1";
const TOFU_BIN = process.env.OPSCREW_TOFU_BIN || "tofu";

const tempDirs: string[] = [];

afterEach(async () => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir !== undefined) await rm(dir, { recursive: true, force: true });
  }
});

function sampleFacts(dbKind: "postgres" | "mysql" = "postgres"): ProjectFacts {
  return {
    schemaVersion: 1,
    name: "acme-gcp",
    language: "typescript",
    packageManager: "pnpm",
    appKind: "fullstack",
    platformExport: "none",
    port: 3000,
    healthEndpoint: "/health",
    services: [
      { kind: dbKind, confidence: "high", evidence: [dbKind] },
      { kind: "redis", confidence: "high", evidence: ["ioredis"] },
      { kind: "s3", confidence: "high", evidence: ["@aws-sdk/client-s3"] },
    ],
    envVars: [],
    hasDockerfile: true,
    hasDockerignore: true,
    warnings: [],
  } as unknown as ProjectFacts;
}

function sampleRequirements(): Requirements {
  return {
    schemaVersion: 1,
    expectedMonthlyUsers: "10k-100k",
    budgetMonthly: { amount: 250, currency: "USD" },
    provider: "gcp",
    region: "us-east",
    uptime: "standard",
    dataCriticality: "important",
    domain: "app.example.com",
    dnsProvider: "cloudflare",
  } as unknown as Requirements;
}

async function runTofuValidate(files: readonly { path: string; content: string }[]) {
  const baseTmp = process.env.OPSCREW_TEST_TMP || os.tmpdir();
  const dir = await mkdtemp(path.join(baseTmp, "opscrew-google-validate-"));
  tempDirs.push(dir);
  for (const file of files) {
    await writeFile(path.join(dir, file.path), file.content, "utf8");
  }
  await execFileAsync(TOFU_BIN, ["init", "-backend=false", "-no-color"], {
    cwd: dir,
    timeout: 480_000,
    env: process.env,
  });
  try {
    const { stdout } = await execFileAsync(TOFU_BIN, ["validate", "-json", "-no-color"], {
      cwd: dir,
      timeout: 120_000,
      env: process.env,
    });
    return JSON.parse(stdout) as { valid: boolean; diagnostics: unknown[] };
  } catch (err) {
    const out = (err as { stdout?: string }).stdout;
    if (typeof out === "string" && out.trim().startsWith("{")) {
      return JSON.parse(out) as { valid: boolean; diagnostics: unknown[] };
    }
    throw err;
  }
}

describe.skipIf(!IT_ENABLED)("GCP HCL OpenTofu validation against hashicorp/google (T3908)", () => {
  it("validates full Cloud Run v2 + Artifact Registry + Secrets + Cloud SQL Postgres + Memorystore Valkey + PSC + GCS + Global ALB HCL", async () => {
    const { target } = designGcpTarget({
      facts: sampleFacts("postgres"),
      requirements: sampleRequirements(),
      preset: "production-ha",
    });
    const files = renderGcpHcl({
      appName: "acme-gcp",
      environment: "prod",
      target,
      domain: "app.example.com",
      dnsProvider: "cloudflare",
      secretNames: ["APP_SECRET", "DATABASE_URL"],
      github: { owner: "acme", repo: "web", environmentName: "prod" },
    });
    const result = await runTofuValidate(files);
    expect(result.valid, JSON.stringify(result.diagnostics, null, 2)).toBe(true);
  }, 600_000);

  it("validates Compute Engine + Compose + Caddy + IAP + instance-scoped IAM + existingVpcId + MySQL + branch-mode WIF HCL", async () => {
    const base = designGcpTarget({
      facts: sampleFacts("mysql"),
      requirements: sampleRequirements(),
      preset: "lean",
      pins: {
        projectId: "acme-dev-1234",
        existingVpcId: "projects/acme-dev-1234/global/networks/shared-vpc",
      },
    }).target;
    const gce = applyGcpOverrides(base, ["compute=compute-engine"]).target;
    const result = await runTofuValidate(
      renderGcpHcl({
        appName: "acme-gcp",
        environment: "dev",
        target: gce,
        domain: "dev.example.com",
        github: { owner: "acme", repo: "web", branch: "main" },
      }),
    );
    expect(result.valid, JSON.stringify(result.diagnostics, null, 2)).toBe(true);
  }, 600_000);
});
