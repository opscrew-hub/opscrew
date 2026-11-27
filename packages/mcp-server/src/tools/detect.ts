import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { summarizeFacts } from "@opscrew/agents";
import { detectProjectDetails } from "@opscrew/detect";
import type { ProjectFacts } from "@opscrew/plan-schema";
import type { ResolvedMcpDeps } from "../deps";
import { projectDirInput, runTool } from "./shared";

/** Short plain-text list of the facts an agent needs to describe the stack. */
function describeFacts(facts: ProjectFacts): string[] {
  const lines = [`App kind: ${facts.appKind}`];
  if (facts.frameworks.length > 0) {
    lines.push(`Frameworks: ${facts.frameworks.map((f) => f.name).join(", ")}`);
  }
  if (facts.languages.length > 0) lines.push(`Languages: ${facts.languages.join(", ")}`);
  lines.push(`Package manager: ${facts.packageManager}`);
  if (facts.platformExport.platform !== "none") {
    lines.push(`Built with: ${facts.platformExport.platform}`);
  }
  if (facts.port !== undefined) lines.push(`Port: ${facts.port}`);
  if (facts.build.buildCommand) lines.push(`Build command: ${facts.build.buildCommand}`);
  if (facts.build.startCommand) lines.push(`Start command: ${facts.build.startCommand}`);
  if (facts.services.length > 0) {
    lines.push(`Services: ${facts.services.map((s) => s.kind).join(", ")}`);
  }
  if (facts.envVars.length > 0) {
    const names = facts.envVars.map(
      (v) =>
        `${v.name}${v.clientExposed ? " (client-exposed)" : ""}${v.secretLikely ? " (secret)" : ""}`,
    );
    lines.push(`Environment variables: ${names.join(", ")}`);
  }
  if ((facts.statelessIssues?.length ?? 0) > 0) {
    const items = (facts.statelessIssues ?? []).map(
      (issue) =>
        `${issue.kind} (${issue.framework}${issue.file === undefined ? "" : ` in ${issue.file}`}: ${issue.evidence})`,
    );
    lines.push(`Stateless readiness notes (for multi-server scaling): ${items.join("; ")}`);
  }
  return lines;
}

/**
 * `opscrew_detect`: deterministic detection of the stack (frameworks, app kind, build/start
 * commands, port, env var names, services, builder platform) with a plain-English summary and
 * deployment risks. Read-only: writes nothing.
 */
export function registerDetectTool(server: McpServer, deps: ResolvedMcpDeps): void {
  server.registerTool(
    "opscrew_detect",
    {
      title: "Detect the app's stack",
      description:
        "Detect the app's stack (frameworks, commands, port, environment variable names, services, Docker files, builder) and its deployment risks. Writes nothing. Next: opscrew_interview_questions.",
      inputSchema: { ...projectDirInput },
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    ({ projectDir }) =>
      runTool(deps, "opscrew_detect", projectDir, async (call) => {
        const detection = await detectProjectDetails(call.projectDir);
        const { summary, risks } = summarizeFacts(detection.facts, {
          appCandidates: detection.appCandidates,
        });
        const text = [
          summary,
          "",
          ...describeFacts(detection.facts).map((line) => `- ${line}`),
          ...(risks.length > 0 ? ["", "Deployment risks:", ...risks.map((r) => `- ${r}`)] : []),
          ...(detection.appCandidates.length > 0
            ? [
                "",
                `Several deployable apps were found: ${detection.appCandidates.join(", ")}. Ask the user which one to deploy.`,
              ]
            : []),
          ...(detection.truncated
            ? [
                "",
                "The repository has more files than OpsCrew inspects; detection may be incomplete.",
              ]
            : []),
        ].join("\n");
        return {
          text,
          data: {
            facts: detection.facts,
            summary,
            risks,
            appDir: detection.appDir,
            appCandidates: detection.appCandidates,
            truncated: detection.truncated,
          },
        };
      }),
  );
}
