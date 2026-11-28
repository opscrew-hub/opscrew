import type { CloudflareClient } from "@opscrew/connector-cloudflare";
import { readNetworkFilter } from "@opscrew/connector-ssh-host";
import type {
  CheckResult,
  PolicyResult,
  RemoteExec,
  Scanner,
  ScanReport,
} from "@opscrew/contracts";
import {
  exists,
  OpsCrewError,
  plural,
  replaceNames,
  toPosixRelative,
  writeFileAtomic,
} from "@opscrew/core";
import { edgeProxy, IMAGES, TOOLS } from "@opscrew/iac-templates";
import {
  APP_SERVER,
  type DeployPlan,
  isServerlessProvider,
  readArtifact,
  type ServerlessProvider,
} from "@opscrew/plan-schema";
import {
  certificateHostChecks,
  type DeepPins,
  type DeepToolResult,
  defaultTcpConnect,
  evaluatePlanPolicies,
  existingOwnFirewallServers,
  type HostCheck,
  type LocalDocker,
  localDocker,
  localDockerProblem,
  originHostChecks,
  probePorts,
  probeSshPasswordAuth,
  runHostChecks,
  runLynis,
  runScan,
  runSshAudit,
  runTestssl,
  skippedTool,
  type TcpConnect,
} from "@opscrew/secops";
import type { PhaseDeps } from "../context";
import { commandFlags } from "../environments/choice";
import { type HomeServerRead, readHomeServer } from "../home/server";
import { hostnameOf } from "../hosting/provision-plans";
import { type HostingSecurity, hostingSecurityChecks } from "../hosting/secure";
import { LOCAL_PROBES_SKIPPED, LOCAL_SECURE_NOTES, localSecurityChecks } from "../localhost/secure";
import type { LocalhostServices } from "../localhost/services";
import { planProvider, providerProfile } from "../providers";
import { originTlsHostnames } from "../provision/origin-tls";
import { sharesOf } from "../provision/own";
import { findSavedPlan } from "../provision/plan-apply";
import { readCloudflareRecord } from "../provision/shared-cloudflare";
import type { OwnServerServices, PortainerServices } from "../provision/types";
import { type RunnerGitHubApi, runnerChecks } from "../runners";
import { appServerShell, hidesServerAddress, serverAddress, withoutServerAddress } from "../shared";
import { runPhase } from "../shared/phase-status";
import { readExistingServerFirewalls } from "../shared/server-firewall";
import { hasExtraServers } from "../shared/servers";
import {
  proxyCertificateHosts,
  proxyRenewalAdvice,
  readRenewalFailure,
} from "../status/certificates";
import { appDeployed } from "../status/run";
import { verifyHosts } from "../verify/checks";
import { siteHost } from "../verify/serverless";
import {
  awayFromHome,
  fromInside,
  homeSecurityChecks,
  insideLabel,
  NOT_CHECKED_AWAY,
} from "./home";
import { monitoringSecurityChecks } from "./monitoring";
import {
  firstAppHardening,
  firstAppHardeningCheck,
  type OwnSecureTarget,
  ownSecureTarget,
} from "./own";
import {
  PORTAINER_PROBES_SKIPPED,
  portainerSecureNotes,
  portainerSecurityChecks,
} from "./portainer";
import { previewServiceChecks } from "./previews";
import { probeExpectedPorts, probeOwnServerPorts } from "./probes";
import {
  renderSecurityReport,
  renderSecuritySummary,
  type SecurityProblem,
  type SecurityReportInput,
  securityProblems,
  UNKNOWN_SERVER_ADDRESS,
} from "./report";
import { plannedWebSources } from "./server-firewall";
import {
  extraServerChecks,
  hostChecksFor,
  type NetworkFilterReader,
  networkListing,
  privateAddressChecks,
} from "./servers";
import { serverServiceChecks, servicePorts } from "./services";
import { behindCloudflare, settingsChecks } from "./settings";
import { siteProbesSkipped, siteSecureNotes, siteSecurityChecks } from "./site";

/** Options for {@link runSecure}; every side effect has a default built from `deps`. */
export interface RunSecureOptions {
  /** The engine's plan JSON (`PlanSummary.planJson`) to evaluate the plan policies against. */
  planJson?: unknown;
  /** Runs commands on the server (default: `appServerShell`, deploy with the project's key). */
  remote?: RemoteExec;
  /** TCP probe for the outside port checks (default `node:net`). */
  tcpConnect?: TcpConnect;
  /** Scanners for the repository scan (default: the `opscrew scan` set). */
  scanners?: readonly Scanner[];
  /** Keep the scan offline (no OSV lookups). Default false. */
  offline?: boolean;
  /** Probe timeout in milliseconds (default 3000). */
  probeTimeoutMs?: number;
  /** Whether this computer can reach IPv6 addresses (default: it has a global IPv6 address). */
  ipv6Route?: () => Promise<boolean>;
  /** The user's Portainer: its client (default: the pinned `portainerClient`; a fake in tests). */
  portainer?: Pick<PortainerServices, "client">;
  /** Also run the deeper checks, Lynis, ssh-audit and testssl.sh (`--deep`). Default false. */
  deep?: boolean;
  /** Docker on this computer, for ssh-audit and testssl.sh (default: `docker` through `deps.runner`). */
  docker?: LocalDocker;
  /** Cloudflare, for the zone's CAA records and minimum TLS (default: `CLOUDFLARE_API_TOKEN`'s). */
  cloudflare?: CloudflareClient;
  /** The localhost target: this computer's OS (a fake in tests). */
  localhost?: LocalhostServices;
  /** GitHub's runner API for a self-hosted runner (default: the client of the user's token). */
  runnerGitHub?: RunnerGitHubApi;
  /** The shell on an extra server, by its address (default: `serverRemote`). */
  serverRemote?: (host: string) => RemoteExec;
  /** Reads the private network's filter on a server (feature 018); none: not checked. */
  readNetworkFilter?: NetworkFilterReader;
  /**
   * A server at home: the admin login's shell and the host adapter its server-side checks read
   * through (default: SSH with the recorded login, and `inspectHost`).
   */
  own?: Pick<OwnServerServices, "remote" | "homeDir" | "host">;
}

/** Outcome of {@link runSecure}. */
export interface SecureResult {
  scan: ScanReport;
  /** Undefined when no plan JSON was given. */
  policies?: PolicyResult[];
  hostChecks: CheckResult[];
  probes: CheckResult[];
  /** The app's certificates, its zone's CAA and minimum TLS, the secrets copy and the runner. */
  settings: CheckResult[];
  /** The deeper checks, one per tool; undefined without `deep`. */
  deep?: DeepToolResult[];
  /** Every failure and warning, most severe first. */
  problems: SecurityProblem[];
  /** True when nothing failed (warnings allowed). */
  passed: boolean;
  /** Repo-relative path of `SECURITY_REPORT.md`. */
  reportPath: string;
  /** The report text that was written. */
  report: string;
  /** Short terminal summary (also sent to the reporter). */
  summary: string;
}

/**
 * The report input without the server's address: no `host`, and check targets that name one of
 * `names` (its addresses or host name) are left out (the checks still say what they found).
 */
function privateReportInput(
  input: SecurityReportInput,
  names: readonly (string | undefined)[],
): SecurityReportInput {
  const { host: _host, ...rest } = input;
  const named = new Set(names.filter((name) => name !== undefined));
  const strip = (checks: readonly CheckResult[]) =>
    checks.map(({ target, ...check }) =>
      target === undefined || named.has(target) ? check : { ...check, target },
    );
  return { ...rest, hostChecks: strip(input.hostChecks), probes: strip(input.probes) };
}

/**
 * The checks of the app's site from the server itself, once the app was deployed (FR-1423,
 * FR-1406): `openssl s_client` to 127.0.0.1:443 for each hostname whose origin certificate and
 * client certificate the app's Cloudflare record holds (refused without the client certificate,
 * served Cloudflare's origin certificate, an unknown hostname refused, by OpenLiteSpeed with a
 * 403), and the certificates of DNS-only hostnames renewed in time, with certbot's reason beside
 * nginx and OpenLiteSpeed.
 */
async function siteTlsChecks(
  deps: PhaseDeps,
  plan: DeployPlan,
  remote: RemoteExec,
): Promise<HostCheck[]> {
  if (!appDeployed(plan)) return [];
  const tls = (await readCloudflareRecord(deps.paths))?.tls;
  const origin = originTlsHostnames(plan).filter(
    (h) => tls?.origin?.hostnames.includes(h) && tls.client?.enabled.includes(h),
  );
  const hosts = proxyCertificateHosts(plan);
  const renewal =
    hosts.length > 0 ? proxyRenewalAdvice(plan, await readRenewalFailure(deps, plan, remote)) : "";
  return [
    ...originHostChecks(origin, edgeProxy(plan)),
    ...certificateHostChecks(hosts, { now: deps.clock.now(), renewal }),
  ];
}

/**
 * The server's hardening checks, run as `deploy` over SSH (pinned host key), and the outside
 * probes. On a server the user owns (`own`) they run on the recorded login's address and port with
 * what OpsCrew set up there (sshd's real ports, root's key-only login, a password choice), and the
 * probes expect SSH and, in public mode, the web ports, in tunnel mode no web port at all. On a
 * server OpsCrew created they run on `host` with the provider firewall's expectations. Once public
 * SSH is closed the host checks connect to the server's private address (`appServerShell`), and a
 * connection that fails there says this computer's tunnel looks down, in each check it stopped.
 * A second app on a server OpsCrew created (`own.firstApp`) runs only its own checks (its
 * services, its site) and probes only its services' ports: the server's hardening is the first
 * app's, said in one skipped check.
 */
async function checkServer(
  deps: PhaseDeps,
  plan: DeployPlan,
  host: string,
  own: OwnSecureTarget | undefined,
  options: RunSecureOptions,
  /** A server at home whose SSH didn't answer: the command's flags for the skips' next step. */
  away?: string,
): Promise<{
  hostChecks: CheckResult[];
  probes: CheckResult[];
  skipped?: string;
  remote?: RemoteExec;
}> {
  const { paths, reporter } = deps;
  const remote =
    away !== undefined
      ? undefined
      : (options.remote ??
        ((await exists(paths.files.deployKey))
          ? await appServerShell(deps, plan, { host, port: own?.sshPort ?? 22 })
          : undefined));
  let hostChecks: CheckResult[] = [];
  let skipped: string | undefined;
  if (away !== undefined) {
    // Away from home nothing logs in: each check is a skip with the reason, never a failure.
    hostChecks = hostChecksFor(plan, APP_SERVER, own?.hardening).map((check) =>
      awayFromHome(check, away),
    );
  } else if (remote === undefined) {
    skipped = `the deploy key is not on this machine (it is created by \`opscrew provision\`). Run the checks from the machine that ${own !== undefined ? "prepared your server" : "provisioned the server"}.`;
  } else {
    reporter.step(
      own !== undefined
        ? "Checking your server's hardening over SSH"
        : `Checking the server's hardening over SSH (${host})`,
    );
    // With the app's services' checks: no published port, their login set (FR-1328), Valkey's
    // password (FR-1450).
    const previews =
      plan.environment?.previews === undefined
        ? undefined
        : await previewServiceChecks(deps, plan, remote);
    // A second app: the server's hardening is the first app's, said in one skipped check.
    const firstApp = own?.firstApp;
    // The web ports' networks the plan applied, which a server's own firewall is held to.
    const web = await plannedWebSources(paths.root, plan);
    hostChecks = [
      ...(firstApp === undefined ? [] : [firstAppHardeningCheck(firstApp)]),
      ...(await runHostChecks(remote, [
        ...(firstApp === undefined
          ? hostChecksFor(plan, APP_SERVER, own?.hardening, web)
          : serverServiceChecks(plan)),
        ...(previews?.checks ?? []),
        ...(await siteTlsChecks(deps, plan, remote)),
      ])),
      ...(previews?.unread ?? []),
    ];
  }
  // A server at home is probed from inside its network: no result there proves the outside view.
  const inside = own?.home === undefined ? undefined : insideLabel(own.home);
  reporter.step(
    own === undefined
      ? `Probing ${host} from outside`
      : own.access === "tunnel"
        ? "Probing your server from this machine (the app is served through the Cloudflare Tunnel, so no web port should answer)"
        : inside !== undefined
          ? "Probing your server from this computer, inside your home network (not proof: `opscrew verify` checks from outside)"
          : "Probing your server from outside",
  );
  const connect = options.tcpConnect ?? defaultTcpConnect;
  const timeoutMs = options.probeTimeoutMs ?? 3000;
  const probeHost = own?.probeHost ?? host;
  // The three probe groups run together; their results keep this order. A second app probes only
  // its services' ports: the server's firewall and SSH are the first app's.
  const second = own?.firstApp !== undefined;
  const [expected, services, password] = await Promise.all([
    second
      ? []
      : own === undefined
        ? probeExpectedPorts(host, plan, { connect, timeoutMs })
        : probeOwnServerPorts(probeHost, plan, {
            connect,
            timeoutMs,
            sshPort: own.sshPort,
            ...(own.probeIpv6 !== undefined ? { ipv6: own.probeIpv6 } : {}),
            ...(options.ipv6Route !== undefined ? { ipv6Route: options.ipv6Route } : {}),
            ...(inside !== undefined ? { inside } : {}),
          }),
    probePorts(probeHost, {
      services: servicePorts(plan),
      connect,
      timeoutMs,
      // A second app's server is behind the first app's cloud firewall.
      providerName:
        own === undefined || second
          ? providerProfile(sharesOf(plan)?.provider ?? planProvider(plan)).displayName
          : "ufw",
    }),
    second
      ? undefined
      : away !== undefined
        ? awayFromHome(PASSWORD_PROBE, away)
        : probeSshPasswordAuth(host, {
            runner: deps.runner,
            knownHostsFile: paths.files.knownHosts,
            ...(own !== undefined
              ? { port: own.sshPort, passwordsKept: own.hardening.passwordsKept }
              : {}),
          }),
  ]);
  const probes = [
    ...expected,
    ...(inside === undefined ? services : services.map((check) => fromInside(check, inside))),
    ...(password === undefined ? [] : [password]),
  ];
  return {
    hostChecks,
    probes,
    ...(skipped !== undefined ? { skipped } : {}),
    ...(remote !== undefined ? { remote } : {}),
  };
}

/** The password probe's check, as `probeSshPasswordAuth` names it. */
const PASSWORD_PROBE = {
  id: "ssh-password-login-disabled",
  title: "SSH refuses password logins",
  severity: "high",
} as const;

/** The pins the deeper checks run from: Lynis's container is the pinned Alpine curl image. */
const DEEP_PINS: DeepPins = {
  lynisImage: IMAGES.curl.ref,
  lynis: TOOLS.lynis,
  sshAudit: IMAGES.sshAudit.ref,
  testssl: IMAGES.testssl.ref,
};

/** Why the deeper checks have no server to reach (the user's Portainer, a site), and what to do. */
interface NoServer {
  message: string;
  hint: string;
}

/** How the deeper checks reach the server. */
interface DeepServer {
  /** The SSH session as `deploy`; undefined when the server checks were skipped. */
  remote?: RemoteExec;
  /** Why the server checks were skipped. */
  skipped?: string;
  sshHost?: string;
  sshPort: number;
}

const PORTAINER_DEEP: NoServer = {
  message:
    "OpsCrew reaches your Portainer only through its API, never over SSH, so the server audit and the SSH audit do not run there. The TLS audit still runs.",
  hint: "Run Lynis and ssh-audit on the Portainer host yourself if you manage it.",
};

/** A site with no server of its own: nothing to audit but its TLS. */
function siteDeep(provider: ServerlessProvider): NoServer {
  return {
    message: `The site has no server of its own (${siteHost(provider)} serves it), so the server audit and the SSH audit do not apply. The TLS audit still runs.`,
    hint: "Nothing to do: there is no server or SSH to audit.",
  };
}

/** A hosting account: OpsCrew has no shell there, so nothing to audit but the hostname's TLS. */
const HOSTING_DEEP: NoServer = {
  message:
    "OpsCrew has no shell on the hosting account (the host runs its server), so the server audit and the SSH audit do not apply. The TLS audit still runs.",
  hint: "Nothing to do: the host runs the server and its SSH.",
};

/** The deeper checks on this computer: a local stack has no server, SSH or public TLS to audit. */
function localDeepSkipped(): DeepToolResult[] {
  return (["lynis", "ssh-audit", "testssl"] as const).map((tool) =>
    skippedTool(
      tool,
      DEEP_PINS,
      "A local stack has no server, SSH or public TLS to audit: it listens on 127.0.0.1 only, with OpsCrew's local CA.",
      "Nothing to do on this computer: the audits run for an environment on a server.",
    ),
  );
}

/**
 * The deeper checks (FR-1420–FR-1424), after today's checks: Lynis on the server over SSH,
 * ssh-audit and testssl.sh (per public hostname, labelled Cloudflare's edge when proxied) from this
 * computer's Docker. A tool that cannot run gives one `skip` with how to enable it, and the others
 * still run. In the user's Portainer and for a site with no server only testssl.sh runs.
 */
async function deepChecks(
  deps: PhaseDeps,
  plan: DeployPlan,
  server: DeepServer | NoServer,
  docker: LocalDocker,
): Promise<DeepToolResult[]> {
  const { reporter } = deps;
  const unreachable = (tool: "lynis" | "ssh-audit") =>
    "message" in server
      ? skippedTool(tool, DEEP_PINS, server.message, server.hint)
      : skippedTool(
          tool,
          DEEP_PINS,
          `The server could not be reached: ${server.skipped ?? UNKNOWN_SERVER_ADDRESS}`,
          "Run `opscrew secure --deep` on the computer that provisioned the server.",
        );

  let lynis: DeepToolResult;
  if ("message" in server || server.remote === undefined) {
    lynis = unreachable("lynis");
  } else {
    reporter.step("Auditing the server with Lynis, read-only (up to 4 minutes)");
    lynis = await runLynis(server.remote, DEEP_PINS, deps.fetch);
  }

  const noDocker = await localDockerProblem(docker);
  let sshAudit: DeepToolResult;
  if ("message" in server || server.sshHost === undefined) {
    sshAudit = unreachable("ssh-audit");
  } else if (noDocker !== undefined) {
    sshAudit = skippedTool("ssh-audit", DEEP_PINS, noDocker.message, noDocker.remediation);
  } else {
    reporter.step("Auditing the server's SSH with ssh-audit");
    sshAudit = await runSshAudit(docker, server.sshHost, server.sshPort, DEEP_PINS);
  }

  // A hosting account's hostname may be on any DNS.
  const hostnames = plan.target.provider === "hosting" ? [hostnameOf(plan)] : verifyHosts(plan);
  let testssl: DeepToolResult;
  if (plan.environment?.previews !== undefined) {
    testssl = skippedTool(
      "testssl",
      DEEP_PINS,
      "A preview environment has no hostname of its own: its previews come and go with pull requests.",
      "Nothing to do: `opscrew verify` checks each running preview's certificate.",
    );
  } else if (hostnames.length === 0) {
    testssl = skippedTool(
      "testssl",
      DEEP_PINS,
      "The app has no domain, so there is no TLS to audit: testssl.sh tests hostnames only.",
      "Give the app a domain, provision it, then run `opscrew secure --deep` again.",
    );
  } else if (noDocker !== undefined) {
    testssl = skippedTool("testssl", DEEP_PINS, noDocker.message, noDocker.remediation);
  } else {
    // One result for all hostnames, with the version testssl.sh reported where it could scan.
    const edge = behindCloudflare(plan);
    const runs: DeepToolResult[] = [];
    for (const hostname of hostnames) {
      reporter.step(
        `Auditing the TLS of ${hostname} with testssl.sh${edge ? " (at Cloudflare's edge)" : ""}`,
      );
      runs.push(await runTestssl(docker, hostname, DEEP_PINS, { edge }));
    }
    const scanned = (run: DeepToolResult) => run.results.some((r) => r.status !== "skip");
    testssl = {
      tool: "testssl",
      version: (runs.find(scanned) ?? (runs[0] as DeepToolResult)).version,
      results: runs.flatMap((run) => run.results),
    };
  }
  return [lynis, sshAudit, testssl];
}

/**
 * The secure phase: re-runs the repository scan, evaluates the plan policies (when an engine plan
 * is given), runs the hardening checks on the server over SSH as `deploy`, probes from outside that
 * only the expected ports answer and that SSH refuses passwords, with `deep` also runs the deeper
 * checks (see `deepChecks`), then writes
 * `opscrew/SECURITY_REPORT.md` and prints a summary. On a hosting account the account's own checks
 * (`hostingSecurityChecks`) take the server's place. Marks `secure` (`failed` when anything fails).
 */
export async function runSecure(
  deps: PhaseDeps,
  options: RunSecureOptions = {},
): Promise<SecureResult> {
  return runPhase(deps, "secure", () => secure(deps, options));
}

async function secure(deps: PhaseDeps, options: RunSecureOptions): Promise<SecureResult> {
  const { paths, reporter } = deps;
  const say = (text: string) => deps.redactor.redact(text);
  const plan = await readArtifact("plan", paths.files.plan);
  // Previews on another environment's server: that server's checks are its environment's.
  const sharedHost = plan.environment?.previews?.server?.environment;
  if (sharedHost !== undefined) {
    throw new OpsCrewError(
      "PHASE_PRECONDITION",
      `The previews of ${paths.environment} run on ${sharedHost}'s server, whose hardening \`opscrew secure\` checks for ${sharedHost}. Nothing was changed.`,
      {
        hint: `Run \`opscrew secure${await commandFlags(paths.root, sharedHost, paths.app)}\`; \`opscrew verify${await commandFlags(paths.root, paths.environment, paths.app)}\` checks the previews themselves.`,
      },
    );
  }
  // A server the user owns is reached by its recorded login instead (see `ownSecureTarget`); the
  // user's Portainer through its API (see `portainerSecurityChecks`), never its host; this
  // computer through its Docker (see `localSecurityChecks`); a site with no server over HTTPS
  // (see `siteSecurityChecks`); a hosting account through its panel and over HTTP (see
  // `hostingSecurityChecks`).
  const portainer = plan.target.provider === "portainer";
  const localhost = plan.target.provider === "localhost";
  const site = isServerlessProvider(plan.target.provider) ? plan.target.provider : undefined;
  const hosting = plan.target.provider === "hosting";
  const address =
    plan.target.provider === "own" || portainer || localhost || site !== undefined || hosting
      ? undefined
      : await serverAddress(deps, plan);
  const host = address?.ipv4;

  reporter.step("Scanning the repository");
  const scan = await runScan(paths.root, {
    offline: options.offline ?? false,
    fetch: deps.fetch,
    runner: deps.runner,
    version: deps.version,
    now: () => deps.clock.now(),
    ...(options.scanners !== undefined ? { scanners: options.scanners } : {}),
  });

  // Without an explicit plan JSON, re-check the plan that was last applied (saved by provision).
  const planJson =
    options.planJson ??
    (plan.deployment.lastPlanHash === undefined
      ? undefined
      : (await findSavedPlan(paths.files.plansDir, plan.deployment.lastPlanHash))?.planJson);
  const secureRemote = options.remote;
  const extraRemote = options.serverRemote;
  const serverFirewalls =
    planJson !== undefined && existingOwnFirewallServers(planJson).length > 0
      ? await readExistingServerFirewalls(
          deps,
          {
            plan,
            ...(secureRemote !== undefined || extraRemote !== undefined
              ? {
                  remote: (targetHost: string, server: string) => {
                    if (server === APP_SERVER && secureRemote !== undefined) return secureRemote;
                    if (extraRemote !== undefined) return extraRemote(targetHost);
                    return undefined;
                  },
                }
              : {}),
          },
          planJson,
          "secure",
        )
      : undefined;
  const policies =
    planJson === undefined
      ? undefined
      : evaluatePlanPolicies(
          planJson,
          plan,
          serverFirewalls === undefined
            ? undefined
            : {
                serverFirewallNetworks: serverFirewalls.networks,
                serverFirewallReadErrors: serverFirewalls.errors,
              },
        );

  let hostChecks: CheckResult[] = [];
  let probes: CheckResult[] = [];
  let hostChecksSkipped: string | undefined;
  let remote: RemoteExec | undefined;
  let account: HostingSecurity | undefined;
  let homeRead: HomeServerRead | undefined;
  const own = plan.target.provider === "own" ? await ownSecureTarget(deps, plan) : undefined;
  const sshHost = own?.sshHost ?? host;
  if (portainer) {
    const checked = await portainerSecurityChecks(deps, plan, options.portainer);
    hostChecks = checked.checks;
    hostChecksSkipped = checked.skipped;
  } else if (localhost) {
    hostChecks = await localSecurityChecks(deps, plan, options.localhost);
  } else if (site !== undefined) {
    hostChecks = await siteSecurityChecks(deps, plan);
  } else if (hosting) {
    account = await hostingSecurityChecks(deps, plan);
    hostChecks = account.checks;
  } else if (sshHost === undefined) {
    hostChecksSkipped =
      plan.target.provider === "own"
        ? "OpsCrew does not know how to reach your server on this computer. Run `opscrew secure` on the computer that ran `opscrew provision` (its `.opscrew/` folder holds the login and the confirmed host key)."
        : UNKNOWN_SERVER_ADDRESS;
  } else {
    // A server at home is read once through its admin login first: away from home (SSH answers
    // only on the home network) nothing else tries it, and every check over SSH is a skip.
    homeRead =
      own?.home === undefined
        ? undefined
        : await readHomeServer(deps, {
            services: options.own,
            phase: "secure",
            detail: "the SSH table, the web filter and the address updater",
            step: "Checking your server's home setup as its admin login (read-only)",
          });
    const flags = await commandFlags(paths.root, paths.environment, paths.app);
    const away = homeRead !== undefined && "away" in homeRead ? flags : undefined;
    const checked = await checkServer(deps, plan, sshHost, own, options, away);
    hostChecks = checked.hostChecks;
    probes = checked.probes;
    hostChecksSkipped = checked.skipped;
    remote = checked.remote;
    // What only its admin login reads: the SSH table, the web filter, the updater, the power.
    if (own?.home !== undefined && homeRead !== undefined) {
      hostChecks = [...hostChecks, ...homeSecurityChecks(plan, own.home, homeRead, flags)];
    }
  }
  const away = homeRead !== undefined && "away" in homeRead;
  // An app with a private network (feature 018): every extra server as the app's, each service on
  // a private address held to it, named by server; their addresses never reach the report. When
  // the app's server's checks were skipped (no deploy key here), only the outside probes run.
  let extraHosts: { server: string; host: string }[] = [];
  if (plan.network !== undefined && sshHost !== undefined) {
    const servers = {
      ...(options.serverRemote !== undefined ? { remote: options.serverRemote } : {}),
      ...(remote !== undefined ? { appRemote: remote } : {}),
      readNetworkFilter: options.readNetworkFilter ?? readNetworkFilter,
      hostChecks: hostChecksSkipped === undefined,
      connect: options.tcpConnect ?? defaultTcpConnect,
      timeoutMs: options.probeTimeoutMs ?? 3000,
    };
    const extra = await extraServerChecks(deps, plan, servers);
    const onApp = (check: CheckResult): CheckResult =>
      hasExtraServers(plan)
        ? {
            ...check,
            title: `Server ${APP_SERVER}: ${check.title}`,
            message: `On server ${APP_SERVER}: ${check.message}`,
          }
        : check;
    hostChecks = [
      ...hostChecks.map(onApp),
      ...extra.hostChecks,
      ...(servers.hostChecks ? await privateAddressChecks(deps, plan, servers) : []),
    ];
    probes = [...probes.map(onApp), ...extra.probes];
    extraHosts = extra.hosts;
  }
  // Self-hosted monitoring (feature 020): Grafana and the front only on private addresses, and
  // the network's filter for their ports, on the stack's server.
  if (sshHost !== undefined && hostChecksSkipped === undefined && !away) {
    hostChecks = [
      ...hostChecks,
      ...(await monitoringSecurityChecks(deps, plan, {
        ...(options.serverRemote !== undefined ? { remote: options.serverRemote } : {}),
        readNetworkFilter: options.readNetworkFilter ?? readNetworkFilter,
      })),
    ];
  }

  const settings = [
    ...(await settingsChecks(
      deps,
      plan,
      options.cloudflare !== undefined ? { cloudflare: options.cloudflare } : {},
    )),
    // A self-hosted runner: online, current, and never open to outside contributors (FR-1530).
    ...(await runnerChecks(deps, plan, options.runnerGitHub)),
    // The private network's grants and public SSH (feature 018).
    ...networkListing(plan),
  ];

  const deep = !options.deep
    ? undefined
    : localhost
      ? localDeepSkipped()
      : await deepChecks(
          deps,
          plan,
          portainer
            ? PORTAINER_DEEP
            : site !== undefined
              ? siteDeep(site)
              : hosting
                ? HOSTING_DEEP
                : own?.firstApp !== undefined
                  ? firstAppHardening(own.firstApp)
                  : away
                    ? { skipped: NOT_CHECKED_AWAY, sshPort: own?.sshPort ?? 22 }
                    : {
                        ...(remote !== undefined ? { remote } : {}),
                        ...(hostChecksSkipped !== undefined ? { skipped: hostChecksSkipped } : {}),
                        ...(sshHost !== undefined ? { sshHost } : {}),
                        sshPort: own?.sshPort ?? 22,
                      },
          options.docker ?? localDocker(deps.runner),
        );

  const shownHost = plan.target.provider === "own" ? own?.probeHost : host;
  const input: SecurityReportInput = {
    appName: plan.app.name,
    version: deps.version,
    generatedAt: deps.clock.now().toISOString(),
    scan,
    hostChecks,
    probes,
    ...(settings.length > 0 ? { settings } : {}),
    ...(shownHost !== undefined ? { host: shownHost } : {}),
    ...(policies !== undefined ? { policies } : {}),
    ...(hostChecksSkipped !== undefined ? { hostChecksSkipped } : {}),
    ...(deep !== undefined ? { deep } : {}),
    ...(portainer
      ? {
          portainer: { notes: portainerSecureNotes(plan), probesSkipped: PORTAINER_PROBES_SKIPPED },
        }
      : {}),
    ...(localhost
      ? { localhost: { notes: LOCAL_SECURE_NOTES, probesSkipped: LOCAL_PROBES_SKIPPED } }
      : {}),
    ...(site !== undefined
      ? {
          site: {
            host: siteHost(site),
            notes: siteSecureNotes(site),
            probesSkipped: siteProbesSkipped(site),
          },
        }
      : {}),
    // An app on a hosting account reads as a site on the account, which the host runs.
    ...(account !== undefined
      ? {
          site: { host: account.host, notes: account.notes, probesSkipped: account.probesSkipped },
        }
      : {}),
  };
  // A server the user owns: the report and the terminal say "your server", never its address or
  // host name.
  const hidden = own?.hidden ?? [];
  const hide = (text: string) => replaceNames(text, hidden, "your server");
  // The report is committed: behind Cloudflare's proxy it never names the server's address, and
  // for a server the user owns it never names its address or host name at all (FR-902).
  const withoutExtraHosts = (text: string) =>
    extraHosts.reduce(
      (out, { server, host }) => replaceNames(out, [host], `server ${server}`),
      text,
    );
  const report = say(
    withoutExtraHosts(
      plan.target.provider === "own"
        ? hide(renderSecurityReport(privateReportInput(input, hidden)))
        : hidesServerAddress(plan)
          ? withoutServerAddress(
              renderSecurityReport(privateReportInput(input, [address?.ipv4, address?.ipv6])),
              [address],
            )
          : renderSecurityReport(input),
    ),
  );
  await writeFileAtomic(paths.files.securityReport, report);
  const reportPath = toPosixRelative(paths.root, paths.files.securityReport);

  const problems = securityProblems(input);
  const passed = problems.every((problem) => problem.status !== "fail");
  const summary = say(
    plan.target.provider === "own"
      ? hide(renderSecuritySummary(privateReportInput(input, hidden), { reportPath }))
      : renderSecuritySummary(input, { reportPath }),
  );
  const [headline = "", ...details] = summary.trimEnd().split("\n");
  if (passed) reporter.success(headline);
  else reporter.error(headline);
  for (const line of details) reporter.info(line);
  if (portainer) reporter.info(portainerSecureNotes(plan).join(" "));
  if (localhost) reporter.info(LOCAL_SECURE_NOTES.join(" "));
  if (site !== undefined) reporter.info(siteSecureNotes(site).join(" "));
  if (account !== undefined) reporter.info(account.notes.join(" "));
  if (hostChecksSkipped !== undefined)
    reporter.warn(
      say(
        hide(`${portainer ? "Portainer checks" : "Server checks"} skipped: ${hostChecksSkipped}`),
      ),
    );

  const failures = problems.filter((problem) => problem.status === "fail").length;
  await deps.state.markPhase(
    "secure",
    passed ? "ok" : "failed",
    passed
      ? `no failures, ${plural(problems.length, "warning")}`
      : `${plural(failures, "problem")} to fix`,
  );
  return {
    scan,
    ...(policies !== undefined ? { policies } : {}),
    hostChecks,
    probes,
    settings,
    ...(deep !== undefined ? { deep } : {}),
    problems,
    passed,
    reportPath,
    report,
    summary,
  };
}
