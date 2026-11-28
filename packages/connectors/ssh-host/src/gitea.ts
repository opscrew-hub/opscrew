// biome-ignore-all lint/suspicious/noTemplateCurlyInString: shell scripts for remote host execution.
import { OpsCrewError, sha256Hex } from "@opscrew/core";
import { z } from "zod";
import { ADDONS_DIR, CLOUD_ADDONS_DIR, EDGE_DIR, MAX_COMPOSE_BYTES } from "./constants";
import type { HostPlan, HostStep, SecretName } from "./types";
import { AppNameSchema, HOST_PLAN_SCHEMA_VERSION, HostnameSchema } from "./types";

/** Compose project name for self-hosted Gitea. */
export const GITEA_HOST_PROJECT = "opscrew-gitea";

/** Prefix for proxy site file params stored inside a Gitea host step (never secrets). */
export const GITEA_PROXY_PARAM_PREFIX = "proxy:";

/** Supported server edge proxies for Gitea site installation and reload. */
export const GiteaEdgeProxySchema = z.enum(["caddy", "nginx", "openlitespeed"]);
export type GiteaEdgeProxy = z.infer<typeof GiteaEdgeProxySchema>;

const ProxyFilenameSchema = z.string().regex(/^opscrew-gitea\.(?:caddy|conf|vhost|map|vhconf)$/, {
  message: "must be an opscrew-gitea reverse proxy site file name",
});

/** Directory holding Gitea's Compose file and 0600 secret env files on the server. */
export function giteaHostDir(runAs: "root" | "login"): string {
  return `${runAs === "root" ? ADDONS_DIR : CLOUD_ADDONS_DIR}/gitea`;
}

export interface GiteaEnablePlanInput {
  composeYaml: string;
  proxy: GiteaEdgeProxy;
  proxyFiles: readonly { filename: string; content: string }[];
  bootstrapScript: string;
  usePostgres: boolean;
  appIntegrationEnabled?: boolean;
  hostname: string;
  version: string;
  rewrite?: boolean;
}

export interface GiteaDisablePlanInput {
  proxy: GiteaEdgeProxy;
  /** Default `true` (keep Docker volumes). `false` destroys volumes (`allowDestroy` required). */
  keepData?: boolean;
}

export interface PlanGiteaOptions {
  app: string;
  runAs: "root" | "login";
  enable?: GiteaEnablePlanInput;
  disable?: GiteaDisablePlanInput;
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

/**
 * Builds a deterministic, hash-bindable {@link HostPlan} to install, update, or remove self-hosted
 * Gitea on a server. Holds zero secrets; all secret env files arrive on stdin at apply time.
 */
export function planGitea(options: PlanGiteaOptions): HostPlan {
  const parsedApp = AppNameSchema.safeParse(options.app);
  if (!parsedApp.success) {
    throw new OpsCrewError("INVALID_INPUT", "The app name for Gitea host planning is not valid.");
  }
  const { app, runAs, enable, disable } = options;
  if ((enable === undefined) === (disable === undefined)) {
    throw new OpsCrewError("INVALID_INPUT", "Turn self-hosted Gitea either on or off, not both.");
  }

  if (disable !== undefined) {
    const proxy = GiteaEdgeProxySchema.parse(disable.proxy);
    const keepData = disable.keepData !== false;
    const step: HostStep = {
      id: "gitea",
      title: keepData
        ? `Stop and remove self-hosted Gitea containers and proxy route (keep data volumes)`
        : `Remove self-hosted Gitea containers, proxy route, and ALL data volumes`,
      state: "change",
      scope: "shared",
      params: {
        runAs,
        owner: app,
        remove: true,
        keepData,
        proxy,
      },
    };
    return {
      schemaVersion: HOST_PLAN_SCHEMA_VERSION,
      purpose: "teardown",
      app,
      findings: [],
      steps: [step],
      ...(keepData ? {} : { deleteData: true }),
    };
  }

  const input = enable as GiteaEnablePlanInput;
  if (!HostnameSchema.safeParse(input.hostname).success) {
    throw new OpsCrewError("INVALID_INPUT", `Invalid Gitea hostname: ${input.hostname}.`);
  }
  if (Buffer.byteLength(input.composeYaml, "utf8") > MAX_COMPOSE_BYTES) {
    throw new OpsCrewError("INVALID_INPUT", "The rendered Gitea Compose file is too large.");
  }
  const proxy = GiteaEdgeProxySchema.parse(input.proxy);
  if (input.proxyFiles.length === 0) {
    throw new OpsCrewError(
      "INVALID_INPUT",
      "Gitea host plan requires at least one edge proxy file.",
    );
  }

  const proxyParams: Record<string, string> = {};
  for (const file of input.proxyFiles) {
    const validName = ProxyFilenameSchema.safeParse(file.filename);
    if (!validName.success) {
      throw new OpsCrewError("INVALID_INPUT", `Invalid Gitea proxy file name: ${file.filename}.`);
    }
    proxyParams[`${GITEA_PROXY_PARAM_PREFIX}${file.filename}`] = file.content;
  }

  const step: HostStep = {
    id: "gitea",
    title: `Deploy self-hosted Gitea ${input.version} at https://${input.hostname}/ (${input.usePostgres ? "PostgreSQL" : "SQLite"})`,
    state: "change",
    scope: "shared",
    params: {
      runAs,
      owner: app,
      hostname: input.hostname,
      version: input.version,
      proxy,
      usePostgres: input.usePostgres,
      appIntegrationEnabled: input.appIntegrationEnabled !== false,
      composeYaml: input.composeYaml,
      composeSha256: sha256Hex(input.composeYaml),
      bootstrapScript: input.bootstrapScript,
      ...(input.rewrite === true ? { rewrite: true } : {}),
      ...proxyParams,
    },
  };

  return {
    schemaVersion: HOST_PLAN_SCHEMA_VERSION,
    purpose: "setup",
    app,
    findings: [],
    steps: [step],
  };
}

/** Reloads the shared OpsCrew edge proxy container after installing or removing Gitea's site file. */
function reloadEdgeCommand(proxy: GiteaEdgeProxy): string {
  if (proxy === "caddy") {
    return "docker compose -p opscrew-edge exec -T caddy caddy reload --config /etc/caddy/Caddyfile >/dev/null 2>&1 || true";
  }
  if (proxy === "nginx") {
    return "docker compose -p opscrew-edge exec -T nginx sh -c 'nginx -t && nginx -s reload' >/dev/null 2>&1 || true";
  }
  return "docker compose -p opscrew-edge exec -T openlitespeed sh /etc/opscrew/reload.sh >/dev/null 2>&1 || true";
}

/**
 * Shell guard that refuses to modify or remove a server-wide Gitea installation owned by another
 * OpsCrew app (`$DIR/.owner` mismatch). Runs before any check decision or mutation.
 */
function ownerGuardLines(dir: string, owner: string): string[] {
  return [
    `OWNER_FILE=${shellQuote(`${dir}/.owner`)}`,
    'if [ -f "$OWNER_FILE" ]; then',
    '  CUR_OWNER="$(cat "$OWNER_FILE")"',
    `  if [ "$CUR_OWNER" != ${shellQuote(owner)} ]; then`,
    `    echo "Self-hosted Gitea on this server is owned by app \\"$CUR_OWNER\\", not ${shellQuote(owner)}. Refusing to modify or remove another app's Gitea instance." >&2`,
    "    exit 1",
    "  fi",
    "fi",
  ];
}

/**
 * Generates check, apply, and verify shell scripts for the `"gitea"` host step.
 * Secrets arrive strictly on stdin as base64-encoded lines (`giteaEnv`, optional
 * `giteaPostgresEnv`, `giteaBootstrapEnv`) and are written atomically with mode `0600`.
 */
export function giteaStepScripts(step: HostStep): {
  doing: string;
  timeoutMs: number;
  check: string;
  apply: string;
  verify: string;
  secrets?: { names: readonly SecretName[]; required: boolean };
} {
  const runAs: "root" | "login" = step.params.runAs === "login" ? "login" : "root";
  const owner = AppNameSchema.parse(step.params.owner);
  const dir = giteaHostDir(runAs);
  const proxy = GiteaEdgeProxySchema.parse(step.params.proxy ?? "caddy");
  const remove = step.params.remove === true;
  const ownerGuard = ownerGuardLines(dir, owner);

  if (remove) {
    const keepData = step.params.keepData !== false;
    const downFlags = keepData ? "" : " -v";
    const dataVolumes = [
      `${GITEA_HOST_PROJECT}_gitea_data`,
      `${GITEA_HOST_PROJECT}_gitea_config`,
      `${GITEA_HOST_PROJECT}_gitea_db`,
    ];
    return {
      doing: keepData
        ? "removing self-hosted Gitea (keeping data volumes)"
        : "removing self-hosted Gitea and its data volumes",
      timeoutMs: 180_000,
      check: [
        "set -eu",
        ...ownerGuard,
        `if [ -d ${shellQuote(dir)} ] || [ -n "$(docker compose -p ${GITEA_HOST_PROJECT} ps -aq 2>/dev/null || true)" ] || ls ${EDGE_DIR}/sites/opscrew-gitea.* >/dev/null 2>&1${
          keepData
            ? ""
            : ` || docker volume inspect ${dataVolumes[0]} >/dev/null 2>&1 || docker volume inspect ${dataVolumes[1]} >/dev/null 2>&1 || docker volume inspect ${dataVolumes[2]} >/dev/null 2>&1`
        }; then`,
        "  echo state=change",
        "else",
        "  echo state=in-place",
        "fi",
      ].join("\n"),
      apply: [
        "set -eu",
        ...ownerGuard,
        `if [ -f ${shellQuote(`${dir}/compose.yaml`)} ]; then`,
        `  docker compose -p ${GITEA_HOST_PROJECT} -f ${shellQuote(`${dir}/compose.yaml`)} down${downFlags} >/dev/null 2>&1 || true`,
        "else",
        `  docker compose -p ${GITEA_HOST_PROJECT} down${downFlags} >/dev/null 2>&1 || true`,
        "fi",
        ...(keepData
          ? []
          : [`docker volume rm -f ${dataVolumes.join(" ")} >/dev/null 2>&1 || true`]),
        `rm -f ${EDGE_DIR}/sites/opscrew-gitea.caddy ${EDGE_DIR}/sites/opscrew-gitea.conf ${EDGE_DIR}/sites/opscrew-gitea.vhost ${EDGE_DIR}/sites/opscrew-gitea.map ${EDGE_DIR}/sites/opscrew-gitea.vhconf`,
        reloadEdgeCommand(proxy),
        `rm -rf ${shellQuote(dir)}`,
      ].join("\n"),
      verify: [
        "set -eu",
        `[ ! -d ${shellQuote(dir)} ] || { echo "Gitea directory still present" >&2; exit 1; }`,
        `[ -z "$(docker compose -p ${GITEA_HOST_PROJECT} ps -aq 2>/dev/null || true)" ] || { echo "Gitea containers still running" >&2; exit 1; }`,
        ...(keepData
          ? []
          : [
              `for _v in ${dataVolumes.join(" ")}; do if docker volume inspect "$_v" >/dev/null 2>&1; then echo "Gitea data volume $_v still exists" >&2; exit 1; fi; done`,
            ]),
      ].join("\n"),
    };
  }

  const composeYaml = String(step.params.composeYaml ?? "");
  const composeSha = String(step.params.composeSha256 ?? "");
  const bootstrapScript = String(step.params.bootstrapScript ?? "");
  const usePostgres = step.params.usePostgres === true;
  const appIntegrationEnabled = step.params.appIntegrationEnabled !== false;
  const rewrite = step.params.rewrite === true;

  const proxyEntries = Object.entries(step.params)
    .filter(([key]) => key.startsWith(GITEA_PROXY_PARAM_PREFIX))
    .map(([key, val]) => ({
      filename: key.slice(GITEA_PROXY_PARAM_PREFIX.length),
      content: String(val),
    }))
    .sort((a, b) => a.filename.localeCompare(b.filename));

  const secretNames: SecretName[] = usePostgres
    ? ["giteaEnv", "giteaPostgresEnv", "giteaBootstrapEnv"]
    : ["giteaEnv", "giteaBootstrapEnv"];

  const checkLines = [
    "set -eu",
    ...ownerGuard,
    ...(rewrite ? ["echo state=change", "exit 0"] : []),
    `COMPOSE=${shellQuote(`${dir}/compose.yaml`)}`,
    `if [ ! -f "$COMPOSE" ] || [ ! -f ${shellQuote(`${dir}/gitea.env`)} ] || [ ! -f ${shellQuote(`${dir}/.owner`)} ] || [ ! -f ${shellQuote(`${dir}/.bootstrapped`)} ]; then echo state=change; exit 0; fi`,
    ...(appIntegrationEnabled
      ? [`if [ ! -s ${shellQuote(`${dir}/.app-token`)} ]; then echo state=change; exit 0; fi`]
      : []),
    `CUR_SHA="$(sha256sum "$COMPOSE" | awk '{print $1}')"`,
    `if [ "$CUR_SHA" != ${shellQuote(composeSha)} ]; then echo state=change; exit 0; fi`,
    ...proxyEntries.map((entry) => {
      const target = `${EDGE_DIR}/sites/${entry.filename}`;
      const wantSha = sha256Hex(entry.content);
      return `if [ ! -f ${shellQuote(target)} ] || [ "$(sha256sum ${shellQuote(target)} | awk '{print $1}')" != ${shellQuote(wantSha)} ]; then echo state=change; exit 0; fi`;
    }),
    `if ! docker compose -p ${GITEA_HOST_PROJECT} -f "$COMPOSE" ps --status running --services 2>/dev/null | grep -Fxq gitea; then echo state=change; exit 0; fi`,
    ...(usePostgres
      ? [
          `if ! docker compose -p ${GITEA_HOST_PROJECT} -f "$COMPOSE" ps --status running --services 2>/dev/null | grep -Fxq gitea-db; then echo state=change; exit 0; fi`,
        ]
      : []),
    "echo state=in-place",
  ];

  const b64Compose = Buffer.from(composeYaml, "utf8").toString("base64");
  const b64Bootstrap = Buffer.from(bootstrapScript, "utf8").toString("base64");

  const applyLines = [
    "set -eu",
    "umask 077",
    ...ownerGuard,
    "IFS= read -r GITEA_ENV_B64 || true",
    ...(usePostgres ? ["IFS= read -r GITEA_PG_ENV_B64 || true"] : []),
    "IFS= read -r GITEA_BOOT_B64 || true",
    '[ -n "$GITEA_ENV_B64" ] || { echo "Missing Gitea secret env on stdin" >&2; exit 1; }',
    ...(usePostgres
      ? [
          '[ -n "$GITEA_PG_ENV_B64" ] || { echo "Missing Gitea Postgres secret env on stdin" >&2; exit 1; }',
        ]
      : []),
    '[ -n "$GITEA_BOOT_B64" ] || { echo "Missing Gitea bootstrap env on stdin" >&2; exit 1; }',
    `DIR=${shellQuote(dir)}`,
    'mkdir -p "$DIR"',
    'chmod 700 "$DIR"',
    `printf '%s\\n' ${shellQuote(owner)} > "$DIR/.owner.tmp"`,
    'chmod 600 "$DIR/.owner.tmp" && mv "$DIR/.owner.tmp" "$DIR/.owner"',
    `printf '%s' ${shellQuote(b64Compose)} | base64 -d > "$DIR/compose.yaml.tmp"`,
    'chmod 644 "$DIR/compose.yaml.tmp" && mv "$DIR/compose.yaml.tmp" "$DIR/compose.yaml"',
    'printf \'%s\' "$GITEA_ENV_B64" | base64 -d > "$DIR/gitea.env.tmp"',
    'chmod 600 "$DIR/gitea.env.tmp" && mv "$DIR/gitea.env.tmp" "$DIR/gitea.env"',
    ...(usePostgres
      ? [
          'printf \'%s\' "$GITEA_PG_ENV_B64" | base64 -d > "$DIR/postgres.env.tmp"',
          'chmod 600 "$DIR/postgres.env.tmp" && mv "$DIR/postgres.env.tmp" "$DIR/postgres.env"',
        ]
      : []),
    `mkdir -p ${shellQuote(`${EDGE_DIR}/sites`)}`,
    ...proxyEntries.flatMap((entry) => {
      const target = `${EDGE_DIR}/sites/${entry.filename}`;
      const b64 = Buffer.from(entry.content, "utf8").toString("base64");
      return [
        `printf '%s' ${shellQuote(b64)} | base64 -d > ${shellQuote(`${target}.tmp`)}`,
        `chmod 644 ${shellQuote(`${target}.tmp`)} && mv ${shellQuote(`${target}.tmp`)} ${shellQuote(target)}`,
      ];
    }),
    'cd "$DIR"',
    `docker compose -p ${GITEA_HOST_PROJECT} -f "$DIR/compose.yaml" up -d --wait >/dev/null`,
    'rm -f "$DIR/.bootstrapped"',
    `printf '%s' ${shellQuote(b64Bootstrap)} | base64 -d > "$DIR/bootstrap.sh"`,
    'chmod 700 "$DIR/bootstrap.sh"',
    'printf \'%s\' "$GITEA_BOOT_B64" | base64 -d | sh "$DIR/bootstrap.sh"',
    'rm -f "$DIR/bootstrap.sh"',
    reloadEdgeCommand(proxy),
  ];

  const verifyLines = [
    "set -eu",
    `DIR=${shellQuote(dir)}`,
    '[ -f "$DIR/.owner" ] || { echo "Missing Gitea owner marker" >&2; exit 1; }',
    `[ "$(cat "$DIR/.owner")" = ${shellQuote(owner)} ] || { echo "Gitea owner marker mismatch" >&2; exit 1; }`,
    '[ "$(stat -c %a "$DIR/.owner")" = "600" ] || { echo "Gitea owner marker must be mode 600" >&2; exit 1; }',
    '[ -f "$DIR/compose.yaml" ] || { echo "Missing Gitea compose.yaml" >&2; exit 1; }',
    '[ -f "$DIR/gitea.env" ] || { echo "Missing Gitea secret env file" >&2; exit 1; }',
    'MODE="$(stat -c %a "$DIR/gitea.env")"',
    '[ "$MODE" = "600" ] || { echo "Gitea secret env file must be mode 600" >&2; exit 1; }',
    '[ -f "$DIR/.bootstrapped" ] || { echo "Gitea bootstrap did not complete" >&2; exit 1; }',
    ...(appIntegrationEnabled
      ? [
          '[ -s "$DIR/.app-token" ] || { echo "Missing Gitea app token file" >&2; exit 1; }',
          '[ "$(stat -c %a "$DIR/.app-token")" = "600" ] || { echo "Gitea app token file must be mode 600" >&2; exit 1; }',
        ]
      : []),
    ...proxyEntries.map(
      (entry) =>
        `[ -f ${shellQuote(`${EDGE_DIR}/sites/${entry.filename}`)} ] || { echo "Missing Gitea edge site ${entry.filename}" >&2; exit 1; }`,
    ),
    `docker compose -p ${GITEA_HOST_PROJECT} -f "$DIR/compose.yaml" ps --status running --services | grep -Fxq gitea || { echo "Gitea container is not running" >&2; exit 1; }`,
    ...(usePostgres
      ? [
          `docker compose -p ${GITEA_HOST_PROJECT} -f "$DIR/compose.yaml" ps --status running --services | grep -Fxq gitea-db || { echo "Gitea PostgreSQL container is not running" >&2; exit 1; }`,
        ]
      : []),
  ];

  return {
    doing: "deploying self-hosted Gitea",
    timeoutMs: 300_000,
    check: checkLines.join("\n"),
    apply: applyLines.join("\n"),
    verify: verifyLines.join("\n"),
    secrets: { names: secretNames, required: true },
  };
}
