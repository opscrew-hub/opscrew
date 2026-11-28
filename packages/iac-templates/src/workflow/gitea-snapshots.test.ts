import path from "node:path";
import { DeployPlanSchema, readArtifact } from "@opscrew/plan-schema";
import { describe, expect, it } from "vitest";
import { drillPlan, drillProject } from "../drill";
import { GITEA_PROJECT } from "../gitea";
import { partRestore, restoreFunctions, snapshotFunctions, snapshotParts } from "./snapshots";

const PLAN_FIXTURE = path.resolve(
  import.meta.dirname,
  "../../../plan-schema/src/__fixtures__/plan.yaml",
);

async function planWithGitea(database: "sqlite" | "postgres") {
  const base = await readArtifact("plan", PLAN_FIXTURE);
  return DeployPlanSchema.parse({
    ...base,
    gitea: {
      enabled: true,
      version: "28.4.0",
      hostname: "git.example.com",
      database,
      adminEmail: "admin@example.com",
    },
  });
}

describe("self-hosted Gitea snapshots & restore drills", () => {
  it("includes gitea tar part in SQLite mode and renders stop-only take/restore + isolated drill commands", async () => {
    const plan = await planWithGitea("sqlite");
    const parts = snapshotParts(plan);
    const giteaPart = parts.find((p) => p.name === "gitea");
    if (giteaPart === undefined) throw new Error("expected gitea snapshot part");
    expect(giteaPart.kind).toBe("gitea");
    expect(giteaPart.file).toBe("gitea.tar");
    expect(giteaPart.online).toBe(false);
    expect(parts.find((p) => p.name === "gitea-db")).toBeUndefined();

    const restore = partRestore(giteaPart);
    expect(restore.stop).toBe(true);
    expect(restore.put?.("-")).toContain("/var/lib/gitea /etc/gitea");

    const script = snapshotFunctions(plan, "app", "/srv/apps/app").join("\n");
    expect(script).toContain(`docker compose -p ${GITEA_PROJECT} stop -t 120 gitea`);
    expect(script).toContain(`${GITEA_PROJECT}_gitea_data:/var/lib/gitea:ro`);
    expect(script).toContain(`${GITEA_PROJECT}_gitea_config:/etc/gitea:ro`);

    const drill = drillPlan(plan, { id: "20261128T090000Z", parts: ["gitea"] });
    expect(drill.app.name).toBe(`${plan.app.name}-drill`);
    const drillScript = restoreFunctions(
      plan,
      "app",
      "/srv/apps/app",
      drillProject(plan, "20261128T090000Z"),
    ).join("\n");
    expect(drillScript).toContain(`${plan.app.name}-drill_gitea_data:/var/lib/gitea`);
    expect(drillScript).toContain("--network none");
    expect(drillScript).toContain("/api/healthz");
    expect(drillScript).not.toContain(`docker compose -p ${GITEA_PROJECT} stop`);
  });

  it("includes both gitea tar and consistent stop-only gitea-db pg_dump in PostgreSQL mode with throwaway drill health probe", async () => {
    const plan = await planWithGitea("postgres");
    const parts = snapshotParts(plan);
    const giteaDb = parts.find((p) => p.name === "gitea-db");
    if (giteaDb === undefined) throw new Error("expected gitea-db snapshot part");
    expect(giteaDb.kind).toBe("gitea-db");
    expect(giteaDb.file).toBe("gitea-db.dump");
    expect(giteaDb.online).toBe(false);
    expect(partRestore(giteaDb).stop).toBe(true);

    const script = snapshotFunctions(plan, "app", "/srv/apps/app").join("\n");
    expect(script).toContain("pg_dump -U gitea -Fc gitea");
    expect(script).toContain("pg_restore -U gitea -d gitea");
    expect(script).toContain(`docker compose -p ${GITEA_PROJECT} stop -t 120 gitea`);

    const drill = drillPlan(plan, { id: "20261128T090000Z", parts: ["gitea", "gitea-db"] });
    expect(drill.app.name).toBe(`${plan.app.name}-drill`);
    const drillScript = restoreFunctions(
      plan,
      "app",
      "/srv/apps/app",
      drillProject(plan, "20261128T090000Z"),
    ).join("\n");
    expect(drillScript).toContain("docker network create --internal");
    expect(drillScript).toContain("pg_restore -U gitea -d gitea");
    expect(drillScript).toContain("/api/healthz");
    expect(drillScript).not.toContain(`docker compose -p ${GITEA_PROJECT} stop`);
  });
});
