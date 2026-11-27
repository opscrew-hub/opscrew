import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { RUN_REPORT_SCHEMA_VERSION, type RunReport } from "@opscrew/contracts";
import { afterEach, describe, expect, it } from "vitest";
import { Redactor } from "./redact";
import {
  firstLineOf,
  RunReportSchema,
  redactRunReport,
  summarizeRunCosts,
  validateSealedKeyPair,
  writeRunReport,
} from "./report";
import { fakeSecret } from "./testing/fake-secrets";

describe("report.json v1 (Feature 041)", () => {
  const dirs: string[] = [];

  afterEach(async () => {
    for (const dir of dirs.splice(0)) {
      await rm(dir, { recursive: true, force: true });
    }
  });

  function sampleReport(overrides: Partial<RunReport> = {}): RunReport {
    return {
      schemaVersion: RUN_REPORT_SCHEMA_VERSION,
      op: "provision",
      environment: "prod",
      opscrewVersion: "0.2.13-dev",
      startedAt: "2026-11-27T09:00:00.000Z",
      finishedAt: "2026-11-27T09:00:15.000Z",
      status: "needs-approval",
      summary: "Planned 1 change.",
      plans: [
        {
          kind: "iac-apply",
          title: "Create 2 resources",
          details: "Create server and firewall",
          planHash: "a".repeat(64),
          allowDestroy: false,
          needsConfirm: false,
          costDelta: { amount: 4.5, currency: "EUR" },
          policy: [
            {
              policyId: "SEC-001",
              title: "Firewall attached",
              severity: "high",
              passed: true,
              message: "Attached.",
            },
          ],
          approved: false,
        },
      ],
      changes: [],
      secrets: [
        {
          name: "OPSCREW_APP_ENV",
          keyId: "key-123",
          encryptedValue: Buffer.from("sealed-ciphertext").toString("base64"),
          place: { kind: "environment", environment: "production" },
        },
      ],
      costs: summarizeRunCosts([]),
      nextSteps: ["Approve hash to apply."],
      ...overrides,
    };
  }

  it("summarizes AI cost entries overall and per model in deterministic order", () => {
    const summary = summarizeRunCosts([
      { at: "2026-11-27T09:00:01Z", phase: "analyze", model: "claude-sonnet-4-6", costUsd: 0.0125 },
      { at: "2026-11-27T09:00:05Z", phase: "adapt", model: "claude-opus-5-5", costUsd: 0.04 },
      { at: "2026-11-27T09:00:08Z", phase: "analyze", model: "claude-sonnet-4-6", costUsd: 0.01 },
      { at: "2026-11-27T09:00:09Z", phase: "design", costUsd: 0.002 },
    ]);

    expect(summary.totalUsd).toBe(0.0645);
    expect(summary.byModel).toEqual([
      { model: "claude-opus-5-5", costUsd: 0.04, calls: 1 },
      { model: "claude-sonnet-4-6", costUsd: 0.0225, calls: 2 },
      { model: "unknown", costUsd: 0.002, calls: 1 },
    ]);
    expect(summary.entries).toHaveLength(4);
  });

  it("redacts every non-ciphertext field before writing report.json", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "opscrew-report-test-"));
    dirs.push(dir);
    const secret = fakeSecret("anthropic-key");
    const redactor = new Redactor();
    redactor.addLiteral(secret, "test-secret");

    const file = path.join(dir, "nested", "report.json");
    const report = sampleReport({
      status: "failed",
      summary: `Failed with ${secret}`,
      plans: [
        {
          kind: "iac-apply",
          title: `Plan leaking ${secret}`,
          details: `Details leaking ${secret}`,
          allowDestroy: false,
          needsConfirm: false,
          approved: false,
          reason: `Reason leaking ${secret}`,
        },
      ],
      changes: [`Changed ${secret}`],
      failure: {
        code: "ENGINE_FAILED",
        step: "provision",
        firstLine: `Line 1 ${secret}\nLine 2 stack trace`,
        hint: `Hint ${secret}`,
      },
      nextSteps: [`Next step ${secret}`],
    });

    await writeRunReport(file, report, redactor);
    const raw = await readFile(file, "utf8");
    expect(raw).not.toContain(secret);

    const parsed = RunReportSchema.parse(JSON.parse(raw));
    expect(parsed.failure?.firstLine).toBe("Line 1 [REDACTED:test-secret]");
    expect(parsed.failure?.firstLine).not.toContain("\n");
    expect(parsed.plans[0]?.title).toContain("[REDACTED:");
    expect(parsed.nextSteps[0]).toContain("[REDACTED:");
  });

  it("validates 32-byte Curve25519 base64 public keys and rejects malformed ones", () => {
    const validKey = Buffer.alloc(32, 7).toString("base64");
    expect(validateSealedKeyPair(" 123 ", ` ${validKey} `)).toEqual({
      keyId: "123",
      publicKey: validKey,
    });

    expect(() => validateSealedKeyPair("", validKey)).toThrow(/Both key ID and base64 public key/);
    expect(() => validateSealedKeyPair("123", "not*valid!base64")).toThrow(/not valid base64/);
    expect(() => validateSealedKeyPair("123", Buffer.alloc(16, 1).toString("base64"))).toThrow(
      /32 bytes/,
    );
  });

  it("extracts the first non-empty redacted line", () => {
    const redactor = new Redactor();
    const token = fakeSecret("github-token");
    expect(firstLineOf(`\n\n  error with ${token}\nsecond line`, redactor)).toBe(
      "error with [REDACTED:github-token]",
    );
  });

  it("keeps sealed ciphertext untouched during redaction", () => {
    const redactor = new Redactor();
    const ciphertext = Buffer.from("0123456789abcdef").toString("base64");
    const out = redactRunReport(
      sampleReport({
        secrets: [
          {
            name: "OPSCREW_RECOVERY_KEY",
            keyId: "99",
            encryptedValue: ciphertext,
            place: { kind: "repo" },
          },
        ],
      }),
      redactor,
    );
    expect(out.secrets[0]?.encryptedValue).toBe(ciphertext);
  });
});
