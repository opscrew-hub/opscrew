import { mkdir, mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { type CommandRunner, MANAGED_CLOUD_CONTRACT_VERSION } from "@opscrew/contracts";
import { afterEach, describe, expect, it } from "vitest";
import {
  installProviderPlugin,
  listInstalledPlugins,
  loadManagedProviderPlugin,
  OFFICIAL_PROVIDER_PLUGINS,
  officialPluginSpec,
  PLUGIN_RECORD_FILE,
  pluginInstallDir,
  pluginsRootDir,
  removeProviderPlugin,
  validateManagedProviderDefinition,
} from "./index";

const tempDirs: string[] = [];

async function makeTempHome(): Promise<string> {
  const dir = await mkdtemp(path.join(os.tmpdir(), "opscrew-plugins-test-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(async () => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir !== undefined) await rm(dir, { recursive: true, force: true });
  }
});

/** Creates a fake npm executable inside `binDir` so `findExecutable("npm", env)` succeeds. */
async function makeFakeNpmBin(homeDir: string): Promise<Record<string, string>> {
  const binDir = path.join(homeDir, "fake-bin");
  await mkdir(binDir, { recursive: true });
  const ext = process.platform === "win32" ? ".cmd" : "";
  await writeFile(path.join(binDir, `npm${ext}`), "echo fake-npm\n", { mode: 0o755 });
  return {
    PATH: binDir,
    PATHEXT: ".CMD;.EXE;.BAT",
  };
}

/** Fake CommandRunner that populates a staged npm install tree for `@opscrew/provider-aws`. */
function makeFakeNpmRunner(overrides?: {
  version?: string;
  contractVersion?: number;
  installExitCode?: number;
  auditExitCode?: number;
  auditStdout?: string;
}): { runner: CommandRunner; calls: string[][] } {
  const calls: string[][] = [];
  const spec = OFFICIAL_PROVIDER_PLUGINS.aws;
  const runner: CommandRunner = {
    async run(_cmd, args) {
      calls.push([...args]);
      if (args[0] === "install") {
        if (overrides?.installExitCode && overrides.installExitCode !== 0) {
          return {
            exitCode: overrides.installExitCode,
            stdout: "",
            stderr: "npm ERR! 404 Not Found",
          };
        }
        const prefixIdx = args.indexOf("--prefix");
        const stageDir = args[prefixIdx + 1] ?? "";
        const pkgDir = path.join(stageDir, "node_modules", ...spec.packageName.split("/"));
        await mkdir(pkgDir, { recursive: true });
        await writeFile(
          path.join(stageDir, "package.json"),
          JSON.stringify({ name: "stage", private: true }),
        );
        await writeFile(
          path.join(pkgDir, "package.json"),
          JSON.stringify({
            name: spec.packageName,
            version: overrides?.version ?? spec.version,
            main: "./index.js",
            opscrewPlugin: {
              contractVersion: overrides?.contractVersion ?? MANAGED_CLOUD_CONTRACT_VERSION,
            },
          }),
        );
        await writeFile(path.join(pkgDir, "index.js"), "export default {};\n");
        return { exitCode: 0, stdout: "added 1 package", stderr: "" };
      }
      if (args[0] === "audit" && args[1] === "signatures") {
        return {
          exitCode: overrides?.auditExitCode ?? 0,
          stdout: overrides?.auditStdout ?? '{"verified":1}',
          stderr: "",
        };
      }
      return { exitCode: 1, stdout: "", stderr: "unexpected command" };
    },
  };
  return { runner, calls };
}

describe("034 official provider plugin manager (T3402)", () => {
  it("refuses unknown or third-party plugin names before touching npm", async () => {
    expect(() => officialPluginSpec("evil-plugin")).toThrow(/Unknown provider plugin/);
    expect(() => officialPluginSpec("aws").packageName).not.toThrow();
    expect(officialPluginSpec("AWS").packageName).toBe("@opscrew/provider-aws");
  });

  it("installs pinned official plugin with --ignore-scripts, verifies provenance, lists, loads, and removes cleanly", async () => {
    const homeDir = await makeTempHome();
    const env = await makeFakeNpmBin(homeDir);
    const { runner, calls } = makeFakeNpmRunner();

    const record = await installProviderPlugin("aws", {
      homeDir,
      runner,
      env,
      now: () => new Date("2026-11-27T12:00:00.000Z"),
    });

    expect(record).toMatchObject({
      id: "aws",
      packageName: "@opscrew/provider-aws",
      version: OFFICIAL_PROVIDER_PLUGINS.aws.version,
      contractVersion: MANAGED_CLOUD_CONTRACT_VERSION,
      verifiedProvenance: true,
      installedAt: "2026-11-27T12:00:00.000Z",
    });

    // Verify exact pinned install flags with --ignore-scripts.
    expect(calls[0]).toContain("--ignore-scripts");
    expect(calls[0]).toContain("--save-exact");
    expect(calls[0]).toContain(`@opscrew/provider-aws@${OFFICIAL_PROVIDER_PLUGINS.aws.version}`);
    // Verify signature audit ran against the staging directory.
    expect(calls[1]?.slice(0, 2)).toEqual(["audit", "signatures"]);

    const listed = await listInstalledPlugins(homeDir);
    expect(listed).toEqual([record]);

    // Load installed plugin via injected importer.
    let importedSpecifier = "";
    const def = await loadManagedProviderPlugin("aws", {
      homeDir,
      allowWorkspaceFallback: false,
      importModule: async (specifier) => {
        importedSpecifier = specifier;
        return {
          default: {
            contractVersion: MANAGED_CLOUD_CONTRACT_VERSION,
            id: "aws",
            displayName: "Amazon Web Services (AWS)",
            packageName: "@opscrew/provider-aws",
            credentials: {
              envVars: ["AWS_REGION"],
              secretPatterns: [],
              consoleUrl: "https://aws.amazon.com",
              instructions: "ok",
            },
            regions: [],
            presets: ["lean", "balanced", "production-ha"],
            createConnector: () => ({}),
          },
        };
      },
    });
    expect(importedSpecifier.startsWith("file://")).toBe(true);
    expect(def.id).toBe("aws");

    expect(await removeProviderPlugin("aws", homeDir)).toBe(true);
    expect(await listInstalledPlugins(homeDir)).toEqual([]);
    expect(await removeProviderPlugin("aws", homeDir)).toBe(false);
  });

  it("refuses tampered version, incompatible contractVersion, or failed provenance and cleans up staging dir", async () => {
    const homeDir = await makeTempHome();
    const env = await makeFakeNpmBin(homeDir);

    // 1. Version mismatch.
    const badVer = makeFakeNpmRunner({ version: "9.9.9" });
    await expect(
      installProviderPlugin("aws", { homeDir, runner: badVer.runner, env }),
    ).rejects.toThrow(/Installed plugin mismatch/);

    // 2. Contract version mismatch.
    const badContract = makeFakeNpmRunner({ contractVersion: 99 });
    await expect(
      installProviderPlugin("aws", { homeDir, runner: badContract.runner, env }),
    ).rejects.toThrow(/declares contractVersion 99/);

    // 3. Failed signature/provenance verification.
    const badSig = makeFakeNpmRunner({ auditExitCode: 1 });
    await expect(
      installProviderPlugin("aws", { homeDir, runner: badSig.runner, env }),
    ).rejects.toThrow(/provenance verification failed/);

    // Staging directories must be cleaned up and nothing installed.
    const remaining = await readdir(pluginsRootDir(homeDir));
    expect(remaining).toEqual([]);
    expect(await listInstalledPlugins(homeDir)).toEqual([]);
  });

  it("checks contractVersion on disk BEFORE calling dynamic import()", async () => {
    const homeDir = await makeTempHome();
    const targetDir = pluginInstallDir(homeDir, "aws");
    const pkgDir = path.join(targetDir, "node_modules", "@opscrew", "provider-aws");
    await mkdir(pkgDir, { recursive: true });
    await writeFile(path.join(targetDir, PLUGIN_RECORD_FILE), JSON.stringify({ id: "aws" }));
    await writeFile(
      path.join(pkgDir, "package.json"),
      JSON.stringify({
        name: "@opscrew/provider-aws",
        version: OFFICIAL_PROVIDER_PLUGINS.aws.version,
        main: "./index.js",
        opscrewPlugin: { contractVersion: 2 },
      }),
    );

    let importCalled = false;
    await expect(
      loadManagedProviderPlugin("aws", {
        homeDir,
        allowWorkspaceFallback: false,
        importModule: async () => {
          importCalled = true;
          return {};
        },
      }),
    ).rejects.toThrow(/declares contractVersion 2/);
    expect(importCalled).toBe(false);
  });

  it("validates exported definition shape strictly", () => {
    expect(() => validateManagedProviderDefinition({}, "aws")).toThrow(/exported contractVersion/);
    expect(() =>
      validateManagedProviderDefinition(
        { contractVersion: MANAGED_CLOUD_CONTRACT_VERSION, id: "azure" },
        "aws",
      ),
    ).toThrow(/mismatched id/);
  });
});
