import path from "node:path";
import { DeployPlanSchema, readArtifact } from "@opscrew/plan-schema";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";
import { IMAGES } from "../pins";
import {
  GITEA_APP_ENV_VARS,
  GITEA_EDGE_ALIAS,
  GITEA_ENV_FILE,
  GITEA_POSTGRES_ENV_FILE,
  GITEA_PROJECT,
  giteaAppIntegration,
  giteaBootstrapScript,
  giteaWebhookAllowedHostList,
  renderGiteaCompose,
  renderGiteaProxySite,
} from "./index";

const PLAN_FIXTURE = path.resolve(
  import.meta.dirname,
  "../../../plan-schema/src/__fixtures__/plan.yaml",
);

async function planWithGitea(
  giteaOverrides: Record<string, unknown> = {},
  planOverrides: Record<string, unknown> = {},
) {
  const base = await readArtifact("plan", PLAN_FIXTURE);
  return DeployPlanSchema.parse({
    ...base,
    ...planOverrides,
    gitea: {
      enabled: true,
      version: "28.4.0",
      hostname: "git.example.com",
      adminEmail: "admin@example.com",
      ...giteaOverrides,
    },
  });
}

describe("renderGiteaCompose", () => {
  it("renders hardened single-container SQLite Gitea with digest-pinned rootless image and no public port 3000", async () => {
    const plan = await planWithGitea();
    const gitea = plan.gitea;
    if (!gitea) throw new Error("expected gitea");
    const yamlText = renderGiteaCompose(plan, gitea);
    const doc = parse(yamlText) as {
      name: string;
      services: Record<string, Record<string, unknown>>;
      networks: Record<string, Record<string, unknown>>;
      volumes: Record<string, unknown>;
    };

    expect(doc.name).toBe(GITEA_PROJECT);
    expect(Object.keys(doc.services)).toEqual(["gitea"]);
    const giteaSvc = doc.services.gitea;
    if (giteaSvc === undefined) throw new Error("expected gitea service");
    expect(giteaSvc.image).toBe(IMAGES.gitea.ref);
    expect(giteaSvc.env_file).toEqual([GITEA_ENV_FILE]);
    expect(giteaSvc.ports).toBeUndefined();
    expect(giteaSvc.security_opt).toEqual(["no-new-privileges:true"]);
    expect(giteaSvc.cap_drop).toEqual(["ALL"]);
    expect(giteaSvc.mem_limit).toBe("512m");
    expect(giteaSvc.memswap_limit).toBe("512m");

    const env = giteaSvc.environment as Record<string, string>;
    expect(env.GITEA__security__INSTALL_LOCK).toBe("true");
    expect(env.GITEA__session__COOKIE_SECURE).toBe("true");
    expect(env.GITEA__service__DISABLE_REGISTRATION).toBe("true");
    expect(env.GITEA__openid__ENABLE_OPENID_SIGNUP).toBe("false");
    expect(env.GITEA__server__ROOT_URL).toBe("https://git.example.com/");
    expect(env.GITEA__server__DISABLE_SSH).toBe("true");
    expect(env.GITEA__server__START_SSH_SERVER).toBe("false");
    expect(env.GITEA__database__DB_TYPE).toBe("sqlite3");
    expect(env.GITEA__webhook__SKIP_TLS_VERIFY).toBe("false");
    expect(env.GITEA__webhook__ALLOWED_HOST_LIST).not.toContain("*");

    // Never leaks secret env keys in compose.yaml
    expect(yamlText).not.toContain("SECRET_KEY");
    expect(yamlText).not.toContain("INTERNAL_TOKEN");
    expect(yamlText).not.toContain("PASSWD");
    expect(yamlText).not.toContain("POSTGRES_PASSWORD");

    // Joins shared edge under alias opscrew-gitea
    expect(doc.networks["opscrew-edge"]).toEqual({ external: true });
    expect(doc.networks["gitea-internal"]).toEqual({ internal: true });
    expect(doc.volumes).toHaveProperty("gitea_data");
    expect(doc.volumes).toHaveProperty("gitea_config");
  });

  it("renders dedicated isolated PostgreSQL 17 service when database is postgres and optional SSH port", async () => {
    const plan = await planWithGitea({
      database: "postgres",
      ssh: { enabled: true, port: 2222 },
      appIntegration: {
        enabled: true,
        tokenScopes: ["read:repository", "read:issue"],
        webhook: { path: "/api/webhooks/gitea", allowedHosts: ["hooks.example.com"] },
      },
    });
    const gitea = plan.gitea;
    if (!gitea) throw new Error("expected gitea");
    const yamlText = renderGiteaCompose(plan, gitea);
    const doc = parse(yamlText) as {
      services: Record<string, Record<string, unknown>>;
      volumes: Record<string, unknown>;
    };

    expect(Object.keys(doc.services)).toEqual(["gitea", "gitea-db"]);
    const giteaSvc = doc.services.gitea;
    const dbSvc = doc.services["gitea-db"];
    if (giteaSvc === undefined || dbSvc === undefined) {
      throw new Error("expected gitea and gitea-db services");
    }
    expect(dbSvc.image).toBe(IMAGES.postgres.ref);
    expect(dbSvc.env_file).toEqual([GITEA_POSTGRES_ENV_FILE]);
    expect(dbSvc.ports).toBeUndefined();
    expect(dbSvc.networks).toEqual(["gitea-internal"]);
    expect(giteaSvc.ports).toEqual(["2222:2222"]);
    expect(doc.volumes).toHaveProperty("gitea_db");

    const env = giteaSvc.environment as Record<string, string>;
    expect(env.GITEA__database__DB_TYPE).toBe("postgres");
    expect(env.GITEA__database__HOST).toBe("gitea-db:5432");
    expect(env.GITEA__server__START_SSH_SERVER).toBe("true");
    expect(env.GITEA__server__SSH_DOMAIN).toBe("git.example.com");
    expect(env.GITEA__server__SSH_PORT).toBe("2222");
    expect(giteaWebhookAllowedHostList(plan, gitea)).toContain("hooks.example.com");
  });
});

describe("renderGiteaProxySite", () => {
  it("renders hardened Caddy, nginx, and OpenLiteSpeed sites targeting opscrew-gitea:3000", async () => {
    for (const edge of ["caddy", "nginx", "openlitespeed"] as const) {
      const base = await readArtifact("plan", PLAN_FIXTURE);
      const plan = await planWithGitea({}, { target: { ...base.target, edge } });
      const gitea = plan.gitea;
      if (!gitea) throw new Error("expected gitea");
      const files = renderGiteaProxySite(plan, gitea, { acmeEmail: "ops@example.com" });
      expect(files.length).toBeGreaterThan(0);
      const combined = files.map((f) => f.content).join("\n");
      expect(combined).toContain("git.example.com");
      expect(combined).toContain(`${GITEA_EDGE_ALIAS}:3000`);
      expect(combined).toContain("Strict-Transport-Security");
      if (edge === "caddy") expect(files[0]?.filename).toBe("opscrew-gitea.caddy");
      if (edge === "nginx") expect(files[0]?.filename).toBe("opscrew-gitea.conf");
      if (edge === "openlitespeed") {
        expect(files.map((f) => f.filename).sort()).toEqual([
          "opscrew-gitea.map",
          "opscrew-gitea.vhconf",
          "opscrew-gitea.vhost",
        ]);
      }
    }
  });
});

describe("giteaAppIntegration & giteaBootstrapScript", () => {
  it("returns secret-free REST v1 API and X-Gitea-Signature webhook integration spec", async () => {
    const plan = await planWithGitea({
      appIntegration: {
        enabled: true,
        tokenScopes: ["read:repository", "read:issue", "read:organization", "read:user"],
        webhook: { path: "/api/webhooks/gitea", allowedHosts: [] },
      },
    });
    const gitea = plan.gitea;
    if (!gitea) throw new Error("expected gitea");
    const spec = giteaAppIntegration(plan, gitea);

    expect(spec.url).toBe("https://git.example.com");
    expect(spec.apiUrl).toBe("https://git.example.com/api/v1");
    expect(spec.envVars).toEqual(GITEA_APP_ENV_VARS);
    expect(spec.endpoints.listRepos).toBe("https://git.example.com/api/v1/user/repos");
    expect(spec.endpoints.listPullRequests).toContain("/pulls");
    expect(spec.webhook.signatureHeader).toBe("X-Gitea-Signature");
    expect(spec.webhook.signatureFormat).toBe("lowercase-hex-hmac-sha256");
    expect(spec.webhook.targetUrl).toBe(`https://${plan.dns.domain}/api/webhooks/gitea`);

    const script = giteaBootstrapScript(gitea);
    expect(script).toContain("umask 077");
    expect(script).toContain("gitea admin user create");
    expect(script).toContain("IFS= read -r P");
    expect(script).not.toMatch(/exec\b[^\n]*--env-file/);
    expect(script).toContain("opscrew-bot");
    expect(script).toContain("gitea admin user generate-access-token");
    expect(script).toContain("read:repository,read:issue,read:organization,read:user");
    expect(script).toContain("touch .bootstrapped && chmod 600 .bootstrapped");
  });
});
