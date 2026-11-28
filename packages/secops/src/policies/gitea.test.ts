import path from "node:path";
import { DeployPlanSchema, readArtifact } from "@opscrew/plan-schema";
import { describe, expect, it } from "vitest";
import { blockingPolicyFailures, evaluateGiteaPolicies } from "../index";

const PLAN_FIXTURE = path.resolve(
  import.meta.dirname,
  "../../../plan-schema/src/__fixtures__/plan.yaml",
);

const HARDENED_COMPOSE = [
  "name: opscrew-gitea",
  "services:",
  "  gitea:",
  "    image: gitea/gitea:28.4.0-rootless@sha256:15ab7fadb44981a2b781f40c712cad07066197f395100ea1c6326e14e5bb073a",
  "    env_file:",
  "      - gitea.env",
  "    environment:",
  '      GITEA__security__INSTALL_LOCK: "true"',
  '      GITEA__service__DISABLE_REGISTRATION: "true"',
  '      GITEA__server__ROOT_URL: "https://git.example.com/"',
  '      GITEA__server__DISABLE_SSH: "true"',
  '      GITEA__server__START_SSH_SERVER: "false"',
  '      GITEA__webhook__ALLOWED_HOST_LIST: "external,app.example.com"',
  '      GITEA__webhook__SKIP_TLS_VERIFY: "false"',
].join("\n");

const HARDENED_PROXY = [
  {
    filename: "opscrew-gitea.caddy",
    content: [
      "git.example.com {",
      "\treverse_proxy opscrew-gitea:3000",
      '\theader Strict-Transport-Security "max-age=31536000; includeSubDomains"',
      "}",
    ].join("\n"),
  },
];

async function planWithGitea(overrides: Record<string, unknown> = {}) {
  const base = await readArtifact("plan", PLAN_FIXTURE);
  return DeployPlanSchema.parse({
    ...base,
    gitea: {
      enabled: true,
      version: "28.4.0",
      hostname: "git.example.com",
      adminEmail: "admin@example.com",
      ...overrides,
    },
  });
}

describe("evaluateGiteaPolicies", () => {
  it("passes all 8 policies for a hardened rendered Gitea stack", async () => {
    const plan = await planWithGitea();
    const results = evaluateGiteaPolicies(plan, {
      composeYaml: HARDENED_COMPOSE,
      proxyFiles: HARDENED_PROXY,
    });
    expect(results).toHaveLength(8);
    expect(blockingPolicyFailures(results)).toEqual([]);
    expect(results.every((r) => r.passed)).toBe(true);
  });

  it("blocks when registration is enabled, port 3000 is public, secrets appear in compose, or webhook allows '*'", async () => {
    const plan = await planWithGitea({ disableRegistration: false });
    const composeYaml = [
      "name: opscrew-gitea",
      "services:",
      "  gitea:",
      "    image: gitea/gitea:latest",
      "    ports:",
      '      - "3000:3000"',
      "    environment:",
      '      GITEA__security__INSTALL_LOCK: "false"',
      '      GITEA__service__DISABLE_REGISTRATION: "false"',
      '      GITEA__security__SECRET_KEY: "inline-bad"',
      '      GITEA__webhook__ALLOWED_HOST_LIST: "*"',
      '      GITEA__webhook__SKIP_TLS_VERIFY: "true"',
    ].join("\n");

    const results = evaluateGiteaPolicies(plan, { composeYaml, proxyFiles: [] });
    const failedIds = results.filter((r) => !r.passed).map((r) => r.policyId);
    expect(failedIds).toContain("gitea-install-lock");
    expect(failedIds).toContain("gitea-registration-disabled");
    expect(failedIds).toContain("gitea-image-pinned");
    expect(failedIds).toContain("gitea-no-public-http-port");
    expect(failedIds).toContain("gitea-no-plaintext-secrets");
    expect(failedIds).toContain("gitea-webhook-host-restricted");
    expect(failedIds).toContain("gitea-proxy-hardened");
    expect(blockingPolicyFailures(results).length).toBeGreaterThanOrEqual(7);
  });

  it("blocks Gitea built-in SSRF webhook keywords (all, private, loopback) case-insensitively", async () => {
    const plan = await planWithGitea();
    for (const keyword of ["all", "private", "loopback", "Private", "ALL"]) {
      const composeYaml = HARDENED_COMPOSE.replace(
        "external,app.example.com",
        `external,${keyword}`,
      );
      const results = evaluateGiteaPolicies(plan, { composeYaml, proxyFiles: HARDENED_PROXY });
      const webhookPolicy = results.find((r) => r.policyId === "gitea-webhook-host-restricted");
      expect(webhookPolicy?.passed, keyword).toBe(false);
    }
  });
});
