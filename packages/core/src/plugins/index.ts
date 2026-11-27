/**
 * Official installable provider plugin manager (ADR 0040, feature 034).
 *
 * Installs only pinned official `@opscrew/provider-<id>` packages into `<homeDir>/plugins/<id>`
 * with `--ignore-scripts`, verifies exact package name/version/contractVersion and npm registry
 * signatures & provenance BEFORE loading any code, and swaps atomically from a staging folder so
 * a failed verification never leaves a partial or untrusted install behind.
 */
import { existsSync } from "node:fs";
import { mkdir, readdir, rename, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  type CommandRunner,
  type InstalledPluginRecord,
  MANAGED_CLOUD_CONTRACT_VERSION,
  type ManagedCloudProviderDefinition,
  type ManagedCloudProviderId,
  type OfficialPluginSpec,
  type PluginSignatureVerifier,
  type Reporter,
} from "@opscrew/contracts";
import { OpsCrewError } from "../errors";
import { findExecutable } from "../exec";
import { readTextIfExists } from "../paths";
import { isRecord } from "../values";

/** Metadata file written inside each verified plugin directory. */
export const PLUGIN_RECORD_FILE = "opscrew-plugin.json";

/** Core's allowlist of official separately-installed cloud provider packages. */
export const OFFICIAL_PROVIDER_PLUGINS: Readonly<
  Record<ManagedCloudProviderId, OfficialPluginSpec>
> = {
  aws: {
    id: "aws",
    packageName: "@opscrew/provider-aws",
    version: "0.1.0",
    contractVersion: MANAGED_CLOUD_CONTRACT_VERSION,
    displayName: "Amazon Web Services (AWS)",
    companionClaudePlugin: "opscrew-aws@opscrew",
    provenance: {
      repository: "opscrew-hub/opscrew",
      workflowPath: ".github/workflows/release.yml",
      refPrefix: "refs/tags/",
    },
  },
  azure: {
    id: "azure",
    packageName: "@opscrew/provider-azure",
    version: "0.1.0",
    contractVersion: MANAGED_CLOUD_CONTRACT_VERSION,
    displayName: "Microsoft Azure",
    companionClaudePlugin: "opscrew-azure@opscrew",
    provenance: {
      repository: "opscrew-hub/opscrew",
      workflowPath: ".github/workflows/release.yml",
      refPrefix: "refs/tags/",
    },
  },
  gcp: {
    id: "gcp",
    packageName: "@opscrew/provider-gcp",
    version: "0.1.0",
    contractVersion: MANAGED_CLOUD_CONTRACT_VERSION,
    displayName: "Google Cloud (GCP)",
    companionClaudePlugin: "opscrew-gcp@opscrew",
    provenance: {
      repository: "opscrew-hub/opscrew",
      workflowPath: ".github/workflows/release.yml",
      refPrefix: "refs/tags/",
    },
  },
};

/** Options for installing, verifying, or loading a provider plugin. */
export interface ProviderPluginOptions {
  /** OpsCrew's user-level folder (`ProjectPaths.homeDir`); plugins live under `<homeDir>/plugins`. */
  readonly homeDir: string;
  /** Runs npm for install and signature verification. */
  readonly runner?: CommandRunner;
  /** Shows install progress. */
  readonly reporter?: Reporter;
  /** Environment variables used to find `npm`. */
  readonly env?: Readonly<Record<string, string | undefined>>;
  /** Clock for recorded timestamps. */
  readonly now?: () => Date;
  /** Override for registry signature + provenance verification (default: `npm audit signatures`). */
  readonly verifySignatures?: PluginSignatureVerifier;
  /** Dynamic importer override (default: `import()`). */
  readonly importModule?: (specifier: string) => Promise<unknown>;
  /** Allow resolving workspace package directly when running inside the OpsCrew monorepo. */
  readonly allowWorkspaceFallback?: boolean;
}

/** Returns the official plugin spec for `id`, or throws `INVALID_INPUT` for unknown/third-party names. */
export function officialPluginSpec(id: string): OfficialPluginSpec {
  const normalized = id.trim().toLowerCase();
  if (normalized === "aws" || normalized === "azure" || normalized === "gcp") {
    return OFFICIAL_PROVIDER_PLUGINS[normalized];
  }
  const available = Object.keys(OFFICIAL_PROVIDER_PLUGINS).join(", ");
  throw new OpsCrewError(
    "INVALID_INPUT",
    `Unknown provider plugin "${id}". OpsCrew installs only official @opscrew/provider-* plugins (${available}).`,
    { hint: `Run \`opscrew plugin add aws\` or \`opscrew plugin list\`.` },
  );
}

/** Root directory holding installed provider plugins under `homeDir`. */
export function pluginsRootDir(homeDir: string): string {
  return path.join(homeDir, "plugins");
}

/** Target directory for a specific installed provider plugin. */
export function pluginInstallDir(homeDir: string, id: ManagedCloudProviderId): string {
  return path.join(pluginsRootDir(homeDir), id);
}

/** Default verifier: runs `npm audit signatures` inside the staged plugin directory. */
export const defaultPluginSignatureVerifier: PluginSignatureVerifier = async ({
  installDir,
  spec,
  runNpm,
}) => {
  const audit = await runNpm(["audit", "signatures", "--prefix", installDir, "--json"]);
  if (audit.exitCode !== 0) {
    const reason = (audit.stderr || audit.stdout).trim().split("\n")[0] ?? "signature audit failed";
    return {
      verified: false,
      detail: `npm registry signature and provenance verification failed for ${spec.packageName}@${spec.version}: ${reason}`,
    };
  }
  const combined = `${audit.stdout}\n${audit.stderr}`;
  if (combined.includes("invalid") || combined.includes("missing")) {
    return {
      verified: false,
      detail: `npm audit signatures reported missing or invalid signatures/attestations for ${spec.packageName}@${spec.version}.`,
    };
  }
  return {
    verified: true,
    detail: `Verified npm registry signatures and provenance for ${spec.packageName}@${spec.version}.`,
  };
};

/** Reads and validates the installed package's `package.json` BEFORE any dynamic `import()`. */
async function readVerifiedPackageManifest(
  dir: string,
  spec: OfficialPluginSpec,
): Promise<{ name: string; version: string; contractVersion: number }> {
  const pkgPath = path.join(dir, "node_modules", ...spec.packageName.split("/"), "package.json");
  const raw = await readTextIfExists(pkgPath);
  if (raw === undefined) {
    throw new OpsCrewError(
      "COMMAND_FAILED",
      `Installed plugin directory ${dir} is missing ${spec.packageName}/package.json.`,
      { hint: `Reinstall with \`opscrew plugin add ${spec.id}\`.` },
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new OpsCrewError(
      "ARTIFACT_INVALID",
      `${spec.packageName}/package.json in ${dir} is not valid JSON.`,
    );
  }
  if (!isRecord(parsed)) {
    throw new OpsCrewError(
      "ARTIFACT_INVALID",
      `${spec.packageName}/package.json in ${dir} must be a JSON object.`,
    );
  }
  if (parsed.name !== spec.packageName || parsed.version !== spec.version) {
    throw new OpsCrewError(
      "PLAN_HASH_MISMATCH",
      `Installed plugin mismatch: expected ${spec.packageName}@${spec.version}, found ${String(parsed.name)}@${String(parsed.version)}.`,
      { hint: `Remove and reinstall with \`opscrew plugin add ${spec.id}\`.` },
    );
  }
  const meta = isRecord(parsed.opscrewPlugin) ? parsed.opscrewPlugin : undefined;
  const contractVersion =
    typeof meta?.contractVersion === "number" ? meta.contractVersion : undefined;
  if (contractVersion !== spec.contractVersion) {
    throw new OpsCrewError(
      "ARTIFACT_INVALID",
      `${spec.packageName}@${spec.version} declares contractVersion ${String(contractVersion)}, but this OpsCrew CLI requires contractVersion ${spec.contractVersion}.`,
      {
        hint: "Update OpsCrew (`npm i -g opscrew` / `npx opscrew@latest`) so the CLI and plugin contract match.",
      },
    );
  }
  return { name: spec.packageName, version: spec.version, contractVersion };
}

/**
 * Installs official provider plugin `id` into `<homeDir>/plugins/<id>` using an exact pinned
 * version, `--ignore-scripts`, manifest/contract pre-check, and npm signature/provenance
 * verification in a staging directory before swapping it into place atomically.
 */
export async function installProviderPlugin(
  id: string,
  options: ProviderPluginOptions,
): Promise<InstalledPluginRecord> {
  const spec = officialPluginSpec(id);
  const runner = options.runner;
  if (runner === undefined) {
    throw new OpsCrewError("INTERNAL", "installProviderPlugin requires a CommandRunner.");
  }
  const env = options.env ?? process.env;
  const npm = findExecutable("npm", env);
  if (npm === undefined) {
    throw new OpsCrewError(
      "COMMAND_FAILED",
      `npm is not installed here, so OpsCrew cannot install ${spec.packageName}.`,
      { hint: "Install Node.js / npm, then run `opscrew plugin add` again." },
    );
  }

  const root = pluginsRootDir(options.homeDir);
  const targetDir = pluginInstallDir(options.homeDir, spec.id);
  const stageDir = path.join(root, `.stage-${spec.id}-${Date.now()}`);
  await mkdir(stageDir, { recursive: true });

  const runNpm = (args: readonly string[]) =>
    runner.run(npm, [...args], { env, timeoutMs: 10 * 60_000 });

  try {
    options.reporter?.step(`Installing ${spec.packageName}@${spec.version} (no install scripts)`);
    const pkgSpec = `${spec.packageName}@${spec.version}`;
    const installResult = await runNpm([
      "install",
      "--prefix",
      stageDir,
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      "--save-exact",
      pkgSpec,
    ]);
    if (installResult.exitCode !== 0) {
      const cause = installResult.stderr
        .split("\n")
        .map((line) => line.trim())
        .find((line) => /^npm (?:error|ERR!) /.test(line) && !line.includes("A complete log"));
      throw new OpsCrewError(
        "COMMAND_FAILED",
        `npm could not install ${pkgSpec}${cause === undefined ? "" : ` (${cause})`}.`,
        { hint: "Check your network connection and npm registry access, then try again." },
      );
    }

    await readVerifiedPackageManifest(stageDir, spec);

    options.reporter?.step(
      `Verifying npm signatures and provenance for ${spec.packageName}@${spec.version}`,
    );
    const verifier = options.verifySignatures ?? defaultPluginSignatureVerifier;
    const verification = await verifier({ installDir: stageDir, spec, runNpm });
    if (!verification.verified) {
      throw new OpsCrewError("PLAN_HASH_MISMATCH", verification.detail, {
        hint: `Refused to install ${spec.packageName}@${spec.version} because provenance/signature verification failed.`,
      });
    }

    const record: InstalledPluginRecord = {
      id: spec.id,
      packageName: spec.packageName,
      version: spec.version,
      contractVersion: spec.contractVersion,
      installedAt: (options.now?.() ?? new Date()).toISOString(),
      verifiedProvenance: true,
      installDir: targetDir,
    };
    await writeFile(
      path.join(stageDir, PLUGIN_RECORD_FILE),
      `${JSON.stringify(record, null, 2)}\n`,
    );
    await rm(targetDir, { recursive: true, force: true });
    await rename(stageDir, targetDir);
    options.reporter?.success(`Installed ${spec.displayName} plugin (${pkgSpec}).`);
    return record;
  } catch (error) {
    await rm(stageDir, { recursive: true, force: true }).catch(() => undefined);
    throw error;
  }
}

/** Removes an installed provider plugin directory cleanly. Returns `true` if removed. */
export async function removeProviderPlugin(id: string, homeDir: string): Promise<boolean> {
  const spec = officialPluginSpec(id);
  const targetDir = pluginInstallDir(homeDir, spec.id);
  const recordText = await readTextIfExists(path.join(targetDir, PLUGIN_RECORD_FILE));
  if (recordText === undefined) {
    await rm(targetDir, { recursive: true, force: true });
    return false;
  }
  await rm(targetDir, { recursive: true, force: true });
  return true;
}

/** Lists all verified official provider plugins installed under `<homeDir>/plugins`. */
export async function listInstalledPlugins(homeDir: string): Promise<InstalledPluginRecord[]> {
  const root = pluginsRootDir(homeDir);
  let entries: string[];
  try {
    entries = await readdir(root);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw error;
  }
  const records: InstalledPluginRecord[] = [];
  for (const entry of entries.sort()) {
    if (entry.startsWith(".stage-")) continue;
    const raw = await readTextIfExists(path.join(root, entry, PLUGIN_RECORD_FILE));
    if (raw === undefined) continue;
    try {
      const parsed: unknown = JSON.parse(raw);
      if (
        isRecord(parsed) &&
        typeof parsed.id === "string" &&
        typeof parsed.packageName === "string" &&
        typeof parsed.version === "string" &&
        typeof parsed.contractVersion === "number" &&
        typeof parsed.installedAt === "string" &&
        typeof parsed.verifiedProvenance === "boolean" &&
        typeof parsed.installDir === "string"
      ) {
        records.push(parsed as unknown as InstalledPluginRecord);
      }
    } catch {
      // Ignore damaged metadata records; loadManagedProviderPlugin rejects unusable installs.
    }
  }
  return records;
}

/** Validates the plain-data shape exported by a loaded managed-cloud provider module. */
export function validateManagedProviderDefinition(
  candidate: unknown,
  expectedId: ManagedCloudProviderId,
): ManagedCloudProviderDefinition {
  const mod = isRecord(candidate) && isRecord(candidate.default) ? candidate.default : candidate;
  if (!isRecord(mod)) {
    throw new OpsCrewError(
      "ARTIFACT_INVALID",
      `Provider plugin "${expectedId}" did not export a definition object.`,
    );
  }
  if (mod.contractVersion !== MANAGED_CLOUD_CONTRACT_VERSION) {
    throw new OpsCrewError(
      "ARTIFACT_INVALID",
      `Provider plugin "${expectedId}" exported contractVersion ${String(mod.contractVersion)}, expected ${MANAGED_CLOUD_CONTRACT_VERSION}.`,
    );
  }
  if (mod.id !== expectedId) {
    throw new OpsCrewError(
      "ARTIFACT_INVALID",
      `Provider plugin "${expectedId}" exported mismatched id "${String(mod.id)}".`,
    );
  }
  if (
    typeof mod.displayName !== "string" ||
    typeof mod.packageName !== "string" ||
    !isRecord(mod.credentials) ||
    !Array.isArray(mod.regions) ||
    !Array.isArray(mod.presets) ||
    typeof mod.createConnector !== "function"
  ) {
    throw new OpsCrewError(
      "ARTIFACT_INVALID",
      `Provider plugin "${expectedId}" is missing required definition fields (displayName, packageName, credentials, regions, presets, createConnector).`,
    );
  }
  return mod as unknown as ManagedCloudProviderDefinition;
}

/**
 * Loads an installed managed-cloud provider plugin after verifying its on-disk manifest and
 * `contractVersion` BEFORE calling `import()`. When `allowWorkspaceFallback` is true (default),
 * falls back to resolving the monorepo workspace package if not installed in `<homeDir>/plugins`.
 */
export async function loadManagedProviderPlugin(
  id: string,
  options: ProviderPluginOptions,
): Promise<ManagedCloudProviderDefinition> {
  const spec = officialPluginSpec(id);
  const importModule = options.importModule ?? ((specifier: string) => import(specifier));
  const targetDir = pluginInstallDir(options.homeDir, spec.id);
  const recordText = await readTextIfExists(path.join(targetDir, PLUGIN_RECORD_FILE));

  if (recordText !== undefined) {
    await readVerifiedPackageManifest(targetDir, spec);
    const entry = createRequire(path.join(targetDir, "package.json")).resolve(spec.packageName);
    const loaded = await importModule(pathToFileURL(entry).href);
    return validateManagedProviderDefinition(loaded, spec.id);
  }

  if (options.allowWorkspaceFallback !== false) {
    try {
      const loaded = await importModule(spec.packageName);
      return validateManagedProviderDefinition(loaded, spec.id);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ERR_MODULE_NOT_FOUND") throw error;
    }
    const workspaceEntry = path.resolve(
      path.dirname(fileURLToPath(import.meta.url)),
      "../../../providers",
      spec.id,
      "src/index.ts",
    );
    if (existsSync(workspaceEntry)) {
      const loaded = await importModule(pathToFileURL(workspaceEntry).href);
      return validateManagedProviderDefinition(loaded, spec.id);
    }
  }

  throw new OpsCrewError(
    "PHASE_PRECONDITION",
    `The ${spec.displayName} plugin (${spec.packageName}@${spec.version}) is not installed yet.`,
    { hint: `Install it with \`opscrew plugin add ${spec.id}\`, then run this command again.` },
  );
}
