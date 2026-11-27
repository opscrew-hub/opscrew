/**
 * Real OpenTofu schema validation against `hashicorp/azurerm ~> 5.0` (Feature 038, T3808).
 *
 * Skipped during offline unit test runs unless `OPSCREW_IT=1` is set (downloads the azurerm
 * provider once into `TF_PLUGIN_CACHE_DIR`). Validates Container Apps + PostgreSQL + Azure Managed
 * Redis + Key Vault + Storage, App Service + existingVnetId, and VM + Compose HCL outputs.
 */
import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import type { ProjectFacts, Requirements } from "@opscrew/plan-schema";
import { afterEach, describe, expect, it } from "vitest";
import { applyAzureOverrides, designAzureTarget, renderAzureHcl } from "./index";

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

function sampleFacts(): ProjectFacts {
  return {
    schemaVersion: 1,
    name: "acme-az",
    language: "typescript",
    packageManager: "pnpm",
    appKind: "fullstack",
    platformExport: "none",
    port: 3000,
    healthEndpoint: "/health",
    services: [
      { kind: "postgres", confidence: "high", evidence: ["pg"] },
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
    provider: "azure",
    region: "eu-central",
    uptime: "standard",
    dataCriticality: "important",
    domain: "app.example.com",
    dnsProvider: "cloudflare",
  } as unknown as Requirements;
}

async function runTofuValidate(files: readonly { path: string; content: string }[]) {
  const dir = await mkdtemp(path.join(os.tmpdir(), "opscrew-azurerm-validate-"));
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

describe.skipIf(!IT_ENABLED)(
  "Azure HCL OpenTofu validation against hashicorp/azurerm (T3808)",
  () => {
    it("validates full Container Apps + Flexible Postgres + Managed Redis + Blob + Key Vault HCL", async () => {
      const { target } = designAzureTarget({
        facts: sampleFacts(),
        requirements: sampleRequirements(),
        preset: "production-ha",
      });
      const files = renderAzureHcl({
        appName: "acme-az",
        environment: "prod",
        target,
        domain: "app.example.com",
        dnsProvider: "cloudflare",
        github: { owner: "acme", repo: "web", environmentName: "prod" },
      });
      const result = await runTofuValidate(files);
      expect(result.valid, JSON.stringify(result.diagnostics, null, 2)).toBe(true);
    }, 600_000);

    it("validates App Service + existingVnetId and VM + Compose HCL", async () => {
      const base = designAzureTarget({
        facts: sampleFacts(),
        requirements: sampleRequirements(),
        preset: "lean",
        pins: {
          existingVnetId:
            "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-core",
        },
      }).target;

      const appService = applyAzureOverrides(base, ["compute=app-service"]).target;
      const appServiceResult = await runTofuValidate(
        renderAzureHcl({
          appName: "acme-az",
          environment: "staging",
          target: appService,
          github: { owner: "acme", repo: "web", environmentName: "staging" },
        }),
      );
      expect(appServiceResult.valid, JSON.stringify(appServiceResult.diagnostics, null, 2)).toBe(
        true,
      );

      const vmCompose = applyAzureOverrides(base, ["compute=vm-compose"]).target;
      const vmResult = await runTofuValidate(
        renderAzureHcl({
          appName: "acme-az",
          environment: "dev",
          target: vmCompose,
          github: { owner: "acme", repo: "web", environmentName: "dev" },
        }),
      );
      expect(vmResult.valid, JSON.stringify(vmResult.diagnostics, null, 2)).toBe(true);
    }, 600_000);
  },
);
