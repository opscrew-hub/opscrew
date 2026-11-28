/**
 * @opscrew/connector-ssh-host: the typed host adapter for servers the user already owns
 * (feature 009). Read-only inspection, host plans of fixed steps, and an apply bound to the
 * plan's SHA-256 hash, with SSH and firewall changes under a dead-man switch on the server.
 * Several OpsCrew apps share a server (feature 013): each has its own record, folders, deploy key
 * and Cloudflare Tunnel connector, and the shared edge goes with the last one. An app's GitHub
 * Actions runner (feature 015) is deploy's systemd user service there and, through `planRunner`
 * as the deploy user, on the servers OpsCrew creates. A runner machine (a machine of the user's
 * that only runs the environments' runners) has a host plan of its own, `planRunnerHost`, hardened
 * only when asked (SSH hardening, and OpsCrew's own nftables table for port 22), and is taken back
 * with `planUndo`. No plan replaces or removes another repository's runner.
 * `planAddon` (feature 017) adds the scheduled check's key, which can run only `CHECK_KEY_COMMAND`
 * (the disk's usage and the scheduled snapshots' results, read-only), and runs the Beszel and
 * Grafana Alloy add-ons as the deploy user, one of each per server.
 * `planNetwork` (feature 018) joins a server to the app's private WireGuard network, also on the
 * servers OpsCrew creates, where the deploy user becomes root through Docker (the `docker`
 * privilege), and with it the network's filter, which lets only the app's servers and the granted
 * devices reach what Docker publishes on the private address; `readWireGuard` reads the
 * network's peers and `readNetworkFilter` its filter. `planPublicSsh` closes or opens public SSH
 * on such a server, and `planGrant` gives a device its own login to one of the app's databases.
 * Self-hosted monitoring (feature 020): `planAddon("monitoring")` runs the stack (Prometheus, Loki,
 * Grafana and its front) as root on any server, Grafana's password in a root-only file; `alloy`
 * runs on any server of the app with its destinations; and `planGrant`'s `monitor` access makes
 * the Postgres login `opscrew_monitor` (`MONITOR_LOGIN`) that Alloy reads Postgres's figures with.
 * `planNetworkRemoval` takes one network's interface off a server, such as the monitoring server
 * another environment owns once this one stops sending to it.
 * Preview environments (feature 022): `planAddon("previews")` installs a preview environment's
 * recipe in `/srv/apps/<app>`, its values (supplied at apply as `previewValues`), the previews'
 * Origin CA certificate in `/srv/edge/tls/<app>` (supplied at apply as `previewTls`), the key
 * (`previewKeyLine`, which can run only the recipe's `opscrew-preview`) and the deploy user's cron
 * line for idle previews, in a plan that deletes data; `inspectHost` lists each recipe's previews.
 * Hosting at home (feature 029): `detectHomeNetwork` reads the home's network from the server
 * (read-only), and `inspectHost` reads the board, the storage devices, the power supply's
 * under-voltage and the address updater's instances and files. `DesiredHost.dnsUpdater` adds the
 * `dns-updater` step: the address updater (a script and two systemd template units) keeps a home
 * app's A/AAAA records at the server's own address, with the token supplied at apply
 * (`ApplySecrets.dnsUpdaterToken`); a teardown removes the app's instance, and the shared files
 * with the last one.
 * The Cloudflare uptime check's server reports (feature 046): `planUptimeReport` installs the
 * `uptime-report` step from `inspectUptimeReport`'s facts, one instance per environment: a
 * script and two systemd template units that check the disk, the scheduled snapshot and restore
 * drill, the certificates and the credentials' ages with the scheduled check's rules, and send
 * signed reports to the Worker on a change and once a day, the key supplied at apply
 * (`ApplySecrets.uptimeReportKey`); a teardown removes the app's instances, and the shared files
 * with the last one.
 * A second app on a server OpsCrew created for another app (feature 030): `DesiredHost.shares`
 * describes the first app, and `planHost` then plans only the app's own steps as the deploy login
 * (its deploy key's lines, every other line of authorized_keys kept as it is, its folders, drills
 * and runner), its record, which names the first app, as root through Docker; `planTeardown` with
 * `shares` never counts it as the last app. `inspectHost` with `rootImage` reads the records there.
 * See `specs/009-own-server/contracts/host-adapter.md`,
 * `specs/013-component-model/contracts/components.md`,
 * `specs/015-environments-runners/contracts/runners.md`,
 * `specs/017-observability/contracts/observability.md`,
 * `specs/018-split-placement/contracts/split-placement.md` and
 * `specs/020-self-hosted-monitoring/contracts/monitoring.md`.
 */

export { keyFingerprint } from "./addons";
export { applyHostPlan, HostApplyError } from "./apply";
export {
  ADDON_PROJECTS,
  type AddonKind,
  ALLOY_DESTINATIONS_FILE,
  addonDir,
  appDirs,
  checkKeyComment,
  checkKeyLine,
  DRILL_DIR,
  DRILL_LIMIT_SECONDS,
  DRILL_RECIPE,
  DRILL_SCHEDULE_FILE,
  DRILL_SLOT_AFTER_HOURS,
  DRILL_VALUES,
  DRILLS_LOG,
  drillProject,
  EDGE_DIR,
  EDGE_PROJECT,
  HASHED_RUNTIME_FILES,
  MIN_DOCKER_MAJOR,
  PORTAINER_DIR,
  PORTAINER_PROJECT,
  previewCommand,
  previewKeyLine,
  RUNNERS_DIR,
  type RuntimeFileName,
  runnerDir,
  runtimeFilePath,
  SECRET_RUNTIME_FILES,
  SHARED_DIRS,
  snapshotScheduleTag,
  snapshotsDir,
  sshdDropIn,
  tunnelDir,
  tunnelProject,
  UFW_SSH_COMMENT,
  UFW_WEB_COMMENT,
} from "./constants";
export {
  DNS_UPDATER_CONFIG_DIR,
  DNS_UPDATER_ERRORS,
  DNS_UPDATER_RECORD_COMMENT,
  DNS_UPDATER_SCRIPT,
  DNS_UPDATER_SERVICE_UNIT,
  DNS_UPDATER_STATE_DIR,
  DNS_UPDATER_TIMER_UNIT,
  DNS_UPDATER_TOKEN_REACH,
  DNS_UPDATER_VERSION,
  type DnsUpdaterError,
  type DnsUpdaterState,
  DnsUpdaterStateSchema,
  dnsUpdaterConfig,
  dnsUpdaterFileHashes,
  dnsUpdaterTimer,
  renderDnsUpdaterScript,
} from "./dns-updater";
export {
  type AppRecord,
  type DnsUpdaterConfig,
  DnsUpdaterConfigSchema,
  type DnsUpdaterFact,
  type DnsUpdaterFiles,
  type HostFacts,
  HostFactsSchema,
  otherActiveApps,
  type RunnerFact,
  type RunnerFacts,
  readableRecords,
  runnerOf,
  type StorageDevice,
  tunnelOf,
  type UptimeReportFacts,
} from "./facts";
export {
  GITEA_HOST_PROJECT,
  GITEA_PROXY_PARAM_PREFIX,
  type GiteaDisablePlanInput,
  type GiteaEdgeProxy,
  type GiteaEnablePlanInput,
  giteaHostDir,
  giteaStepScripts,
  type PlanGiteaOptions,
  planGitea,
} from "./gitea";
export { type GrantParams, GrantParamsSchema, MONITOR_LOGIN } from "./grant";
export { hostPlanHash } from "./hash";
export {
  agreedIpv4,
  detectHomeNetwork,
  type HomeNetwork,
  HomeNetworkSchema,
} from "./home-network";
export {
  inspectHost,
  inspectRunners,
  inspectUptimeReport,
  probePrivilege,
  readGrant,
} from "./inspect";
export { localExec } from "./local";
export { type NetworkStepParams, NetworkStepParamsSchema } from "./network";
export { networkFileHashes, networkFilterFileHashes, networkUfwRules } from "./network-files";
export {
  type NetworkFilterParams,
  NetworkFilterParamsSchema,
  type NetworkFilterRule,
  readNetworkFilter,
} from "./network-filter";
export { canonicalSshSource, isPublicAddress } from "./parse";
export {
  type AddonConnector,
  type AddonEnable,
  type AddonPlanKind,
  planAddon,
  planGrant,
  planHost,
  planNetwork,
  planNetworkRemoval,
  planNextTunnelConnector,
  planNextTunnelConnectorRemoval,
  planPortainer,
  planPublicSsh,
  planRunner,
  planRunnerHost,
  planTeardown,
  planTunnelToken,
  planUndo,
  planUptimeReport,
} from "./plan";
export type { HostPrivilege } from "./privilege";
export { type PublicSshParams, PublicSshParamsSchema } from "./public-ssh";
export {
  type ApplyOptions,
  type ApplyResult,
  type ApplySecrets,
  type DesiredDnsUpdater,
  type DesiredHost,
  type DesiredRunner,
  type DesiredRunnerHost,
  type DesiredUptimeReport,
  type HostPlan,
  HostPlanSchema,
  type HostStep,
  type HostStepId,
  MAX_SSH_SOURCES,
  UPTIME_REPORT_NAME_MAX,
} from "./types";
export {
  renderUptimeReportScript,
  UPTIME_REPORT_CONFIG_DIR,
  UPTIME_REPORT_KEY_REACH,
  UPTIME_REPORT_SCRIPT,
  UPTIME_REPORT_SERVICE_UNIT,
  UPTIME_REPORT_STATE_DIR,
  UPTIME_REPORT_TIMER_UNIT,
  UPTIME_REPORT_USER_AGENT,
  UPTIME_REPORT_VERSION,
  uptimeReportConfigText,
  uptimeReportFileHashes,
  uptimeReportInstance,
  uptimeReportTimer,
} from "./uptime-report";
export { webFilterFileHashes, webFilterTable6Hash } from "./web-filter";
export { readWireGuard, type WireGuardPeer } from "./wireguard";
