import type { RunReportSecret, RunReportSecretPlace, SealedSecretSink } from "@opscrew/contracts";
import { ageRecipientOf, Redactor } from "@opscrew/core";
import { fakeSecret } from "@opscrew/core/testing";
import { describe, expect, it, vi } from "vitest";
import { setSecretAt } from "../provision/secrets";
import { provisionedFiles, recoveryWorld, writeLocal } from "./__fixtures__/world";
import { refreshRecoveryCopy } from "./copy";

function fakeSink(redactor: Pick<Redactor, "addLiteral">) {
  const plainByName = new Map<string, string>();
  const sealed: RunReportSecret[] = [];
  const sink: SealedSecretSink = {
    async seal(name: string, value: string, place: RunReportSecretPlace): Promise<RunReportSecret> {
      redactor.addLiteral(value, "sealed-secret");
      plainByName.set(name, value);
      const entry: RunReportSecret = {
        name,
        keyId: place.kind === "repo" ? "repo-key-1" : "env-key-1",
        encryptedValue: Buffer.from(`sealed:${name}:${value.length}`).toString("base64"),
        place,
      };
      sealed.push(entry);
      return entry;
    },
    entries: () => [...sealed],
  };
  return { sink, plainByName };
}

describe("Feature 041: sealed secrets & first-run recovery key sealing", () => {
  it("routes setSecretAt through deps.sealedSecrets without calling GitHub secret write APIs", async () => {
    const redactor = new Redactor();
    const { sink, plainByName } = fakeSink(redactor);
    const auditEntries: unknown[] = [];
    const setActionsSecret = vi.fn();
    const setEnvironmentSecret = vi.fn();
    const secretVal = fakeSecret("generic-password");

    await setSecretAt(
      { audit: { append: async (e) => void auditEntries.push(e) }, sealedSecrets: sink },
      { api: { setActionsSecret, setEnvironmentSecret }, owner: "acme", repo: "app" },
      { name: "OPSCREW_APP_ENV", environment: "production" },
      secretVal,
      "provision",
    );

    expect(setActionsSecret).not.toHaveBeenCalled();
    expect(setEnvironmentSecret).not.toHaveBeenCalled();
    expect(auditEntries).toHaveLength(1);
    expect(sink.entries()).toHaveLength(1);
    expect(sink.entries()[0]).toMatchObject({
      name: "OPSCREW_APP_ENV",
      keyId: "env-key-1",
      place: { kind: "environment", environment: "production" },
    });
    expect(plainByName.get("OPSCREW_APP_ENV")).toBe(secretVal);
    expect(JSON.stringify(sink.entries())).not.toContain(secretVal);
  });

  it("seals a newly generated recovery age key via sealFirstKey without writing a key file to disk", async () => {
    const world = await recoveryWorld();
    await writeLocal(world.deps, provisionedFiles());
    const { sink, plainByName } = fakeSink(world.deps.redactor);

    const result = await refreshRecoveryCopy(
      world.deps,
      { app: { name: "shop" } },
      {
        repositoryPrivate: async () => true,
        sealFirstKey: async (identity) => {
          await sink.seal("OPSCREW_RECOVERY_KEY", identity, { kind: "repo" });
        },
      },
    );

    expect(result.changed).toBe(true);
    if (!result.changed) return;
    expect(result.firstKey).toBeUndefined();
    expect(result.recipients).toHaveLength(1);
    expect(sink.entries()).toHaveLength(1);
    expect(sink.entries()[0]).toMatchObject({
      name: "OPSCREW_RECOVERY_KEY",
      place: { kind: "repo" },
    });

    const identity = plainByName.get("OPSCREW_RECOVERY_KEY") ?? "";
    expect(identity.startsWith("AGE-SECRET-KEY-1")).toBe(true);
    expect(ageRecipientOf(identity)).toBe(result.recipients[0]);
    expect(world.deps.redactor.redact(`leaked ${identity}`)).not.toContain(identity);
  });
});
