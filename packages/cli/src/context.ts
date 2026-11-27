import type { Reporter } from "@opscrew/contracts";
import { Redactor, registerEnvSecrets } from "@opscrew/core";
import { version as packageVersion } from "../package.json";
import type { ReportCollector } from "./report";
import { TerminalReporter } from "./reporter";

/** Set by the bundle's build (tsup.config.ts, `scripts/build-version.mjs`); absent from source. */
declare const __OPSCREW_VERSION__: string | undefined;

/**
 * The version this CLI reports and generated files record: the bundle's, which is the release's
 * own only when built on its tag (`<version>-dev.<short commit>` otherwise), or `<version>-dev`
 * when it runs from source.
 */
export const CLI_VERSION =
  typeof __OPSCREW_VERSION__ === "string" ? __OPSCREW_VERSION__ : `${packageVersion}-dev`;

/** Everything a command needs from the outside world. Tests build their own. */
export interface CliContext {
  /** Absolute project directory; the global `--cwd <dir>` option replaces it before an action. */
  cwd: string;
  env: Record<string, string | undefined>;
  /** OpsCrew's version ({@link CLI_VERSION}). */
  version: string;
  /** True when a human can answer prompts (stdin and stdout are TTYs and `CI` is not set). */
  isInteractive: boolean;
  /** Writes redacted text to standard output (no newline added). */
  stdout(text: string): void;
  /** Writes redacted text to standard error (no newline added). */
  stderr(text: string): void;
  /**
   * Writes `text` to standard output without redaction (no newline added): only for a secret the
   * user asked to be shown once, such as a device's database password from `opscrew vpn grant`.
   */
  showOnce(text: string): void;
  reporter: Reporter;
  redactor: Redactor;
  /** Feature 041: collects structured run facts and sealed secrets when `--report` or `--secrets-key*` is set. */
  report?: ReportCollector;
}

/** Builds the context for the real process: `process.cwd()`, `process.env` and real streams. */
export function createDefaultContext(): CliContext {
  const env = process.env;
  const redactor = new Redactor();
  registerEnvSecrets(redactor, env);
  const stdout = (text: string) => {
    process.stdout.write(redactor.redact(text));
  };
  const stderr = (text: string) => {
    process.stderr.write(redactor.redact(text));
  };
  return {
    cwd: process.cwd(),
    env,
    version: CLI_VERSION,
    isInteractive:
      process.stdin.isTTY === true && process.stdout.isTTY === true && !isTruthy(env.CI),
    stdout,
    stderr,
    showOnce: (text) => {
      process.stdout.write(text);
    },
    reporter: new TerminalReporter({
      stdout,
      stderr,
      redactor,
      color: colorEnabled(env, process.stdout.isTTY === true),
    }),
    redactor,
  };
}

/** Colours are on for a TTY unless `NO_COLOR` is set (non-empty); `FORCE_COLOR` turns them on. */
export function colorEnabled(env: Record<string, string | undefined>, isTty: boolean): boolean {
  if (env.NO_COLOR !== undefined && env.NO_COLOR !== "") return false;
  if (isTruthy(env.FORCE_COLOR)) return true;
  return isTty;
}

function isTruthy(value: string | undefined): boolean {
  return value !== undefined && value !== "" && value !== "0" && value.toLowerCase() !== "false";
}
