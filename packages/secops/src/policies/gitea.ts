import type { PolicyResult, Severity } from "@opscrew/contracts";
import type { DeployPlan } from "@opscrew/plan-schema";
import { giteaOf } from "@opscrew/plan-schema";
import { parse } from "yaml";

/** Files passed to {@link evaluateGiteaPolicies} before approving a Gitea host plan. */
export interface GiteaPolicyInput {
  /** Rendered `compose.yaml` for the `opscrew-gitea` Compose project. */
  composeYaml: string;
  /** Rendered edge proxy site file contents (`opscrew-gitea.caddy`, `.conf`, or `.vhconf`). */
  proxyFiles: readonly { filename: string; content: string }[];
}

const SECRET_KEYS = [
  "GITEA__security__SECRET_KEY",
  "GITEA__security__INTERNAL_TOKEN",
  "GITEA__oauth2__JWT_SECRET",
  "GITEA__lfs__JWT_SECRET",
  "GITEA__database__PASSWD",
  "POSTGRES_PASSWORD",
  "GITEA_ADMIN_PASSWORD",
  "GITEA_BOT_PASSWORD",
  "GITEA_API_TOKEN",
  "GITEA_TOKEN",
  "GITEA_WEBHOOK_SECRET",
];

const RESERVED_SSH_PORTS = new Set([22, 80, 443]);

/** Gitea built-in webhook host keywords that allow SSRF to internal/loopback services. */
const FORBIDDEN_WEBHOOK_HOSTS = new Set(["*", "all", "private", "loopback"]);

function policy(
  policyId: string,
  title: string,
  severity: Severity,
  passed: boolean,
  message: string,
): PolicyResult {
  return { policyId, title, severity, passed, message, resource: "gitea" };
}

interface ParsedCompose {
  services?: Record<
    string,
    {
      image?: unknown;
      ports?: unknown;
      environment?: unknown;
      security_opt?: unknown;
      cap_drop?: unknown;
    }
  >;
}

function envMap(raw: unknown): Record<string, string> {
  if (raw === null || raw === undefined) return {};
  if (Array.isArray(raw)) {
    const out: Record<string, string> = {};
    for (const item of raw) {
      if (typeof item !== "string") continue;
      const idx = item.indexOf("=");
      if (idx > 0) out[item.slice(0, idx)] = item.slice(idx + 1);
    }
    return out;
  }
  if (typeof raw === "object") {
    const out: Record<string, string> = {};
    for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
      if (v !== undefined && v !== null) out[k] = String(v);
    }
    return out;
  }
  return {};
}

function publishesPortOnPublicInterface(ports: unknown, containerPort: number): boolean {
  if (!Array.isArray(ports)) return false;
  for (const entry of ports) {
    const text = String(entry).trim();
    if (!text.endsWith(`:${containerPort}`) && text !== String(containerPort)) continue;
    // Loopback-only bindings (127.0.0.1:..., [::1]:...) are not public.
    if (text.startsWith("127.0.0.1:") || text.startsWith("[::1]:")) continue;
    return true;
  }
  return false;
}

/**
 * Deterministic SecOps policy checks for self-hosted Gitea (`plan.gitea`, feature 043 follow-up):
 * runs before asking the user to approve the Gitea host plan; callers stop on any failed
 * `critical` or `high` result.
 */
export function evaluateGiteaPolicies(
  deployPlan: DeployPlan,
  input: GiteaPolicyInput,
): PolicyResult[] {
  const gitea = giteaOf(deployPlan);
  if (gitea === undefined) return [];

  let doc: ParsedCompose = {};
  try {
    doc = (parse(input.composeYaml) ?? {}) as ParsedCompose;
  } catch {
    return [
      policy(
        "gitea-compose-valid",
        "Gitea Compose file is valid YAML",
        "critical",
        false,
        "The rendered Gitea compose.yaml could not be parsed as YAML.",
      ),
    ];
  }

  const giteaSvc = doc.services?.gitea;
  const giteaEnv = envMap(giteaSvc?.environment);
  const allEnvKeys = new Set<string>();
  for (const svc of Object.values(doc.services ?? {})) {
    for (const key of Object.keys(envMap(svc?.environment))) {
      allEnvKeys.add(key);
    }
  }

  const results: PolicyResult[] = [];

  // 1. INSTALL_LOCK=true (prevents interactive /install hijack)
  const installLocked = giteaEnv.GITEA__security__INSTALL_LOCK === "true";
  results.push(
    policy(
      "gitea-install-lock",
      "Gitea web installer is locked (INSTALL_LOCK=true)",
      "critical",
      installLocked,
      installLocked
        ? "GITEA__security__INSTALL_LOCK is true, so the web installer is disabled."
        : "GITEA__security__INSTALL_LOCK must be true to prevent unauthenticated web installer hijack.",
    ),
  );

  // 2. DISABLE_REGISTRATION=true (hardened default)
  const registrationDisabled =
    gitea.disableRegistration === true && giteaEnv.GITEA__service__DISABLE_REGISTRATION === "true";
  results.push(
    policy(
      "gitea-registration-disabled",
      "Public self-registration is disabled",
      "high",
      registrationDisabled,
      registrationDisabled
        ? "Open user sign-ups are disabled (GITEA__service__DISABLE_REGISTRATION=true)."
        : "Open user sign-ups are enabled; set gitea.disableRegistration to true so only administrators create accounts.",
    ),
  );

  // 3. Pinned rootless image digest
  const image = typeof giteaSvc?.image === "string" ? giteaSvc.image : "";
  const pinnedRootless = image.includes("-rootless") && /@sha256:[0-9a-f]{64}$/.test(image);
  results.push(
    policy(
      "gitea-image-pinned",
      "Gitea uses a digest-pinned rootless image",
      "high",
      pinnedRootless,
      pinnedRootless
        ? `Gitea runs the digest-pinned rootless image (${image.split("@")[0]}).`
        : `Gitea image "${image}" must be a digest-pinned -rootless image (gitea/gitea:<ver>-rootless@sha256:...).`,
    ),
  );

  // 4. HTTP port 3000 never published publicly
  const publicHttp = publishesPortOnPublicInterface(giteaSvc?.ports, 3000);
  results.push(
    policy(
      "gitea-no-public-http-port",
      "Gitea HTTP port 3000 is not exposed directly",
      "critical",
      !publicHttp,
      !publicHttp
        ? "Gitea port 3000 is reachable only behind the reverse proxy on the internal edge network."
        : "Gitea publishes port 3000 directly; remove the host port mapping so traffic passes only through the HTTPS reverse proxy.",
    ),
  );

  // 5. No plaintext secrets in compose.yaml or proxy files
  const leakedKeys = SECRET_KEYS.filter(
    (key) => allEnvKeys.has(key) || input.proxyFiles.some((file) => file.content.includes(key)),
  );
  results.push(
    policy(
      "gitea-no-plaintext-secrets",
      "No Gitea secrets appear in Compose or proxy files",
      "critical",
      leakedKeys.length === 0,
      leakedKeys.length === 0
        ? "All Gitea secrets are kept in 0600 env files delivered over stdin, never in compose.yaml or proxy configs."
        : `Plaintext secret keys found in rendered files (${leakedKeys.join(", ")}); move them into 0600 env files.`,
    ),
  );

  // 6. Webhook allowed host list does not allow '*', 'all', 'private', or 'loopback' (SSRF guard)
  const allowList = (giteaEnv.GITEA__webhook__ALLOWED_HOST_LIST ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const forbiddenHosts = allowList.filter((entry) =>
    FORBIDDEN_WEBHOOK_HOSTS.has(entry.toLowerCase()),
  );
  const skipTls = giteaEnv.GITEA__webhook__SKIP_TLS_VERIFY === "true";
  const webhookSafe = allowList.length > 0 && forbiddenHosts.length === 0 && !skipTls;
  results.push(
    policy(
      "gitea-webhook-host-restricted",
      "Gitea outgoing webhooks enforce TLS and restrict target hosts",
      "high",
      webhookSafe,
      webhookSafe
        ? `Gitea webhooks verify TLS and allow only: ${allowList.join(", ")}.`
        : "Gitea webhooks must set a non-empty GITEA__webhook__ALLOWED_HOST_LIST without '*', 'all', 'private', or 'loopback' and keep SKIP_TLS_VERIFY=false.",
    ),
  );

  // 7. SSH port safety
  const sshEnabled = gitea.ssh.enabled;
  const sshSafe = !sshEnabled
    ? giteaEnv.GITEA__server__DISABLE_SSH === "true" &&
      !publishesPortOnPublicInterface(giteaSvc?.ports, 2222)
    : !RESERVED_SSH_PORTS.has(gitea.ssh.port) &&
      giteaEnv.GITEA__server__START_SSH_SERVER === "true" &&
      giteaEnv.GITEA__server__SSH_PORT === String(gitea.ssh.port);
  results.push(
    policy(
      "gitea-ssh-port-safe",
      "Gitea SSH listener matches plan and avoids reserved ports",
      "high",
      sshSafe,
      sshSafe
        ? sshEnabled
          ? `Gitea built-in SSH is explicitly configured on port ${gitea.ssh.port}.`
          : "Gitea SSH is disabled (Git over HTTPS only; no extra host ports exposed)."
        : "Gitea SSH configuration does not match the plan or collides with reserved ports (22, 80, 443).",
    ),
  );

  // 8. Reverse proxy site enforces HSTS & routes to opscrew-gitea:3000
  const proxyCombined = input.proxyFiles.map((f) => f.content).join("\n");
  const proxyHardened =
    input.proxyFiles.length > 0 &&
    proxyCombined.includes(gitea.hostname) &&
    proxyCombined.includes("opscrew-gitea:3000") &&
    proxyCombined.includes("Strict-Transport-Security");
  results.push(
    policy(
      "gitea-proxy-hardened",
      "Reverse proxy serves Gitea over HTTPS with HSTS",
      "high",
      proxyHardened,
      proxyHardened
        ? `Reverse proxy routes ${gitea.hostname} to opscrew-gitea:3000 with Strict-Transport-Security.`
        : `Reverse proxy configuration must route ${gitea.hostname} to opscrew-gitea:3000 with HSTS enabled.`,
    ),
  );

  return results;
}
