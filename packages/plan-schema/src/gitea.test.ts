import path from "node:path";
import { describe, expect, it } from "vitest";
import { previewPlanOf } from "./__fixtures__/preview-plan";
import {
  DeployPlanSchema,
  GITEA_DEFAULT_SSH_PORT,
  GITEA_DEFAULT_TOKEN_SCOPES,
  GITEA_MEMORY_DEFAULTS,
  GiteaSchema,
  giteaOf,
  readArtifact,
} from "./index";

const PLAN_FIXTURE = path.resolve(import.meta.dirname, "__fixtures__/plan.yaml");

async function basePlan() {
  return readArtifact("plan", PLAN_FIXTURE);
}

describe("GiteaSchema and DeployPlanSchema.gitea", () => {
  it("applies hardened defaults for minimal self-hosted Gitea config", () => {
    const parsed = GiteaSchema.parse({
      enabled: true,
      version: "28.4.0",
      hostname: "git.example.com",
      adminEmail: "admin@example.com",
    });
    expect(parsed.database).toBe("sqlite");
    expect(parsed.adminUser).toBe("gitea-admin");
    expect(parsed.disableRegistration).toBe(true);
    expect(parsed.ssh).toEqual({ enabled: false, port: GITEA_DEFAULT_SSH_PORT });
    expect(parsed.appIntegration.enabled).toBe(true);
    expect(parsed.appIntegration.tokenScopes).toEqual([...GITEA_DEFAULT_TOKEN_SCOPES]);
    expect(parsed.memoryMb).toEqual(GITEA_MEMORY_DEFAULTS);
  });

  it("accepts postgres database, custom scopes, SSH port, and webhook settings", async () => {
    const base = await basePlan();
    const plan = DeployPlanSchema.parse({
      ...base,
      gitea: {
        enabled: true,
        version: "28.4.0",
        hostname: "git.example.com",
        database: "postgres",
        adminUser: "forge-admin",
        adminEmail: "ops@example.com",
        disableRegistration: true,
        ssh: { enabled: true, port: 2222 },
        appIntegration: {
          enabled: true,
          tokenScopes: ["read:repository", "write:repository", "read:issue"],
          webhook: {
            path: "/api/webhooks/gitea",
            allowedHosts: ["hooks.example.com"],
          },
        },
      },
    });
    const gitea = giteaOf(plan);
    expect(gitea?.database).toBe("postgres");
    expect(gitea?.ssh).toEqual({ enabled: true, port: 2222 });
    expect(gitea?.appIntegration.webhook?.path).toBe("/api/webhooks/gitea");
  });

  it("rejects floating tags, root adminUser, wildcard webhook host, and reserved SSH ports", () => {
    expect(
      GiteaSchema.safeParse({
        enabled: true,
        version: "latest",
        hostname: "git.example.com",
        adminEmail: "admin@example.com",
      }).success,
    ).toBe(false);

    expect(
      GiteaSchema.safeParse({
        enabled: true,
        version: "28.4.0",
        hostname: "git.example.com",
        adminUser: "root",
        adminEmail: "admin@example.com",
      }).success,
    ).toBe(false);

    expect(
      GiteaSchema.safeParse({
        enabled: true,
        version: "28.4.0",
        hostname: "git.example.com",
        adminEmail: "admin@example.com",
        ssh: { enabled: true, port: 22 },
      }).success,
    ).toBe(false);

    for (const forbidden of ["*", "all", "private", "loopback", "Private", "LOOPBACK"]) {
      expect(
        GiteaSchema.safeParse({
          enabled: true,
          version: "28.4.0",
          hostname: "git.example.com",
          adminEmail: "admin@example.com",
          appIntegration: {
            enabled: true,
            webhook: { allowedHosts: [forbidden] },
          },
        }).success,
        forbidden,
      ).toBe(false);
    }
  });

  it("rejects hostname colliding with app domain, outside Cloudflare zone, or too deep when proxied", async () => {
    const base = await basePlan();
    const sameDomain = DeployPlanSchema.safeParse({
      ...base,
      gitea: {
        enabled: true,
        version: "28.4.0",
        hostname: base.dns.domain,
        adminEmail: "admin@example.com",
      },
    });
    expect(sameDomain.success).toBe(false);

    const wrongZone = DeployPlanSchema.safeParse({
      ...base,
      dns: {
        provider: "cloudflare",
        domain: "app.example.com",
        zone: "example.com",
        proxied: true,
        www: false,
      },
      gitea: {
        enabled: true,
        version: "28.4.0",
        hostname: "git.other.org",
        adminEmail: "admin@example.com",
      },
    });
    expect(wrongZone.success).toBe(false);

    const tooDeep = DeployPlanSchema.safeParse({
      ...base,
      dns: {
        provider: "cloudflare",
        domain: "app.example.com",
        zone: "example.com",
        proxied: true,
        www: false,
      },
      gitea: {
        enabled: true,
        version: "28.4.0",
        hostname: "git.dev.example.com",
        adminEmail: "admin@example.com",
      },
    });
    expect(tooDeep.success).toBe(false);
  });

  it("refuses self-hosted Gitea in preview environments and non-server targets", async () => {
    const base = await basePlan();
    const preview = previewPlanOf(base);
    expect(
      DeployPlanSchema.safeParse({
        ...preview,
        gitea: {
          enabled: true,
          version: "28.4.0",
          hostname: "git.example-previews.com",
          adminEmail: "admin@example.com",
        },
      }).success,
    ).toBe(false);

    expect(
      DeployPlanSchema.safeParse({
        ...base,
        target: {
          provider: "localhost",
          mode: "local-compose",
          arch: "amd64",
          ports: { http: 80, https: 443 },
          image: "local-build",
          edge: "caddy",
        },
        dns: { provider: "none", proxied: false, www: false },
        gitea: {
          enabled: true,
          version: "28.4.0",
          hostname: "git.example.com",
          adminEmail: "admin@example.com",
        },
      }).success,
    ).toBe(false);
  });

  it("returns undefined from giteaOf when disabled or absent", async () => {
    const base = await basePlan();
    expect(giteaOf(base)).toBeUndefined();
    const disabled = DeployPlanSchema.parse({
      ...base,
      gitea: {
        enabled: false,
        version: "28.4.0",
        hostname: "git.example.com",
        adminEmail: "admin@example.com",
      },
    });
    expect(giteaOf(disabled)).toBeUndefined();
  });
});
