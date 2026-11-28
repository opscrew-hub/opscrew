/**
 * The first app, whose server OpsCrew created and a second app shares, as this computer knows it:
 * read from its repository folder (its plan, its server's address, its deploy login and the
 * server's pinned host key), never copied into the second app's state. Only the server's public
 * host key is copied, by `secondAppLogin`.
 */
import { listText, type ProjectPaths, readTextIfExists, upperFirst } from "@opscrew/core";
import { siteHosts } from "@opscrew/iac-templates";
import { type DeployPlan, isCloudTarget, readOptionalArtifact } from "@opscrew/plan-schema";
import type { PhaseDeps } from "../context";
import { commandFlags } from "../environments/choice";
import { refusedBeforeChange, sharedPreviewsOn } from "../previews/host";
import { deployLogin } from "../provision/origin-tls";
import { appMemoryMb } from "../shared/memory";
import { hasDeployment, serverAddress } from "../shared/server-address";
import type { ServerAddress, SharesReference } from "../shared/server-record";
import { hostKeyFingerprint, keysFor, knownHostsName, type ScannedHostKey } from "../shared/wait";
import { firstAppPaths, readShares } from "./reference";

/** What {@link firstApp} reads with: the second app's paths (for this computer's OpsCrew home). */
export type FirstAppDeps = Pick<PhaseDeps, "paths" | "runner" | "env" | "redactor" | "clock">;

/** The first app as this computer knows it ({@link firstApp}). */
export interface FirstApp {
  /** Its paths, from its repository folder on this computer. */
  paths: ProjectPaths;
  /** Its plan, provisioned on a server OpsCrew created. */
  plan: DeployPlan;
  /** Its server's public addresses, from its local state: never written to committed files. */
  address: ServerAddress;
  /** Where its deploy login reaches the server, as `deploy`. */
  login: { host: string; port: number };
  /** Its deploy key's path on this computer: ssh reads it there, nothing ever copies it. */
  keyFile: string;
  /** The server's host key pinned on this computer for {@link FirstApp.login}. */
  hostKey: ScannedHostKey;
}

/**
 * The first app named by `ref` (spec FR-3002): its paths, plan, server address, deploy login and
 * the server's pinned host key, once its plan allows a second app beside it. Every refusal comes
 * before any change and ends "Nothing was changed.":
 * - no plan, or not provisioned on this computer, or this computer lacks its address, deploy key
 *   or pinned host key;
 * - itself a second app (named with its own first app);
 * - not on a server OpsCrew created;
 * - a preview environment, or previews of its repository running on its server;
 * - public SSH closed, or its server on a private network (other servers or a VPN's devices).
 * - in the middle of a move to another server (`plan.retarget`).
 * @throws OpsCrewError `PHASE_PRECONDITION`.
 */
export async function firstApp(deps: FirstAppDeps, ref: SharesReference): Promise<FirstApp> {
  const paths = firstAppPaths(deps.paths, ref);
  const where = placeWords(ref);
  const instead =
    "Name the folder of another app whose server OpsCrew created, or choose another server, with `opscrew interview`.";
  const plan = await readOptionalArtifact("plan", paths.files.plan);
  if (plan === undefined) {
    throw refusedBeforeChange(
      "PHASE_PRECONDITION",
      `${upperFirst(where)} has no OpsCrew plan on this computer.`,
      `Check the folder, or ${elsewhere(ref)}`,
    );
  }
  const name = `"${plan.app.name}"`;
  const itsFirst = plan.target.provider === "own" ? plan.target.shares?.app : undefined;
  const itsRef = await readShares(paths);
  if (itsFirst !== undefined || itsRef !== undefined) {
    const named = itsFirst === undefined ? "another app" : `"${itsFirst}"`;
    throw refusedBeforeChange(
      "PHASE_PRECONDITION",
      `${name} itself runs on the server of ${named}, which OpsCrew created for that app.`,
      `Name the repository folder of ${named}${itsRef === undefined ? "" : ` (${itsRef.root})`} instead, with \`opscrew interview\`.`,
    );
  }
  // During a move the plan's target is the new side, and the recorded address still the old
  // server: a second app could join the server the move is about to delete. The first app's
  // retarget refuses to start while a second app runs there, so its finish needs no look.
  if (plan.retarget !== undefined) {
    throw refusedBeforeChange(
      "PHASE_PRECONDITION",
      `${name} is in the middle of a move to another server (\`opscrew retarget\`), so its server can't take another app now.`,
      `Finish or abort the move in ${ref.root} first (\`opscrew retarget --finish\` or \`opscrew retarget --abort\`), then run this command again.`,
    );
  }
  if (!isCloudTarget(plan.target)) {
    throw refusedBeforeChange(
      "PHASE_PRECONDITION",
      `${name} does not run on a server OpsCrew created, so this app can't share it this way.`,
      plan.target.provider === "own"
        ? "For a server of yours, answer the interview's server question with your own server's login instead."
        : instead,
    );
  }
  const why = await sharingProblem(paths, plan, name);
  if (why !== undefined) throw refusedBeforeChange("PHASE_PRECONDITION", why, instead);
  if (!hasDeployment(plan)) {
    throw refusedBeforeChange(
      "PHASE_PRECONDITION",
      `${name} is not provisioned on this computer, so it has no server to share yet.`,
      `Run \`opscrew provision${await commandFlags(paths.root, paths.environment, paths.app)}\` in ${ref.root} first, or ${elsewhere(ref)}`,
    );
  }
  const missing = (what: string) =>
    refusedBeforeChange(
      "PHASE_PRECONDITION",
      `This computer does not have ${what}.`,
      upperFirst(elsewhere(ref)),
    );
  const address = await serverAddress({ ...deps, paths }, plan);
  if (address === undefined) throw missing(`the address of ${name}'s server`);
  const login = await deployLogin({ paths }, plan);
  if (login === undefined) throw missing(`the deploy key of ${name}`);
  const pinned = keysFor(
    (await readTextIfExists(paths.files.knownHosts)) ?? "",
    knownHostsName(login.host, login.port),
  )[0];
  if (pinned === undefined) throw missing(`the pinned SSH host key of ${name}'s server`);
  const [type = "", key = ""] = pinned.split(" ");
  return {
    paths,
    plan,
    address,
    login,
    keyFile: paths.files.deployKey,
    hostKey: { type, key, fingerprint: hostKeyFingerprint(key) },
  };
}

/** Why the server of the first app `plan` can't take a second app, or `undefined` when it can. */
async function sharingProblem(
  paths: ProjectPaths,
  plan: DeployPlan,
  name: string,
): Promise<string | undefined> {
  if (plan.environment?.previews !== undefined) {
    return `${name} is a preview environment, whose server runs pull requests' code.`;
  }
  const previews = await sharedPreviewsOn(paths, paths.environment);
  if (previews !== undefined) {
    return `The previews of the ${previews.name} environment run on ${name}'s server, and they run pull requests' code.`;
  }
  if (plan.network?.publicSsh === false) {
    return `${name}'s server takes no public SSH (it was closed with \`opscrew secure --close-public-ssh\`), and this app's deploys reach it over public SSH.`;
  }
  if (plan.network !== undefined) {
    return `${name}'s server is on a private network, where this app's containers could reach its other servers and devices without passing a firewall.`;
  }
  return undefined;
}

/**
 * The first app as its plan describes it to the host adapter (`DesiredHost.shares.host`): its
 * name, every hostname it serves (its domain and `www.`, and Portainer's and Beszel's subdomains),
 * how it is served (behind Cloudflare's proxy, where the cloud firewall lets only Cloudflare in,
 * or DNS only) and the sum of its memory limits.
 */
export function hostDescription(plan: DeployPlan): {
  app: string;
  hostnames: string[];
  access: "web-filter" | "public";
  memoryMb: number;
} {
  const subdomains = [
    ...[plan.portainer, plan.observability?.beszel].flatMap((addon) =>
      addon?.enabled === true && addon.access === "subdomain" && addon.hostname !== undefined
        ? [addon.hostname]
        : [],
    ),
    ...(plan.gitea?.enabled === true ? [plan.gitea.hostname] : []),
  ];
  return {
    app: plan.app.name,
    hostnames: [...new Set([...siteHosts(plan), ...subdomains])].sort(),
    access: plan.dns.proxied ? "web-filter" : "public",
    memoryMb: appMemoryMb(plan),
  };
}

/** "the app in <folder>", with its app key and environment when they are not the defaults. */
function placeWords(ref: SharesReference): string {
  const which = [
    ...(ref.app === undefined ? [] : [`app ${ref.app}`]),
    ...(ref.environment === "prod" ? [] : [`environment ${ref.environment}`]),
  ];
  return `the app in ${ref.root}${which.length === 0 ? "" : ` (${listText(which)})`}`;
}

/** Where to run the command instead: on the computer that provisioned the first app. */
function elsewhere(ref: SharesReference): string {
  return `run the command on the computer that provisioned the app in ${ref.root}, or run \`opscrew interview\` again and name the folder where it is on this computer.`;
}
