import type {
  AgentRuntime,
  AuditLog,
  Clock,
  CommandRunner,
  FetchLike,
  Reporter,
  SealedSecretSink,
  StreamRunner,
} from "@opscrew/contracts";
import type {
  ApprovalGate,
  CostLedger,
  ProjectPaths,
  ProjectStateStore,
  Redactor,
} from "@opscrew/core";
import type { RegistryDsLookup } from "./domain/registry-ds";
import type { RegistryNsLookup } from "./domain/registry-ns";

/**
 * Everything a phase needs, injected by the CLI or the MCP server. Phases never reach for globals
 * (process.env, fetch, child_process, Date) directly — they use these. Lead-owned.
 */
export interface PhaseDeps {
  paths: ProjectPaths;
  reporter: Reporter;
  /** Present when a model is configured and allowed for this run (`--no-ai` leaves it unset). */
  runtime?: AgentRuntime;
  approvals: ApprovalGate;
  audit: AuditLog;
  state: ProjectStateStore;
  costs: CostLedger;
  runner: CommandRunner;
  /**
   * Starts a binary with its stdin and stdout as one stream (`ssh … docker system dial-stdio` for a
   * move's Docker API). Absent, a move uses core's `NodeStreamRunner`.
   */
  streams?: StreamRunner;
  fetch: FetchLike;
  /** Asks a registry's own nameservers for a domain's DS record and its full TTL; unset, the DS wait keeps its 24-hour floor. */
  registryDs?: RegistryDsLookup;
  /**
   * Asks a registry's RDAP record which nameservers it names for a domain; unset, the Cloudflare
   * move's switch reads the delegation from the registrar's API or the public DNS.
   */
  registryNs?: RegistryNsLookup;
  env: Record<string, string | undefined>;
  clock: Clock;
  redactor: Redactor;
  /** True when a human can answer prompts (TTY, not CI). */
  interactive: boolean;
  /** OpsCrew version, written into generated files and reports. */
  version: string;
  /**
   * Present in GitHub Actions runs (Feature 041) when `--secrets-key-id`/`--secrets-key` are
   * passed: secret writes seal ciphertext into `report.json` instead of calling GitHub's API.
   */
  sealedSecrets?: SealedSecretSink;
}
