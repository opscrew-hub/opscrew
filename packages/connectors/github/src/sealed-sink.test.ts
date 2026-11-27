import { Redactor } from "@opscrew/core";
import { fakeSecret } from "@opscrew/core/testing";
import sodium from "libsodium-wrappers";
import { describe, expect, it } from "vitest";
import { createSealedSecretSink } from "./sealed-sink";

async function generateKeyPair() {
  await sodium.ready;
  const kp = sodium.crypto_box_keypair();
  return {
    publicKey: sodium.to_base64(kp.publicKey, sodium.base64_variants.ORIGINAL),
    publicKeyBytes: kp.publicKey,
    privateKeyBytes: kp.privateKey,
  };
}

describe("createSealedSecretSink (Feature 041)", () => {
  it("seals repo and environment secrets with libsodium crypto_box_seal and registers plaintext with redactor", async () => {
    const repoKp = await generateKeyPair();
    const envKp = await generateKeyPair();
    const redactor = new Redactor();
    const sink = createSealedSecretSink(
      {
        repo: { keyId: "repo-key-1", publicKey: repoKp.publicKey },
        environment: { name: "production", keyId: "env-key-2", publicKey: envKp.publicKey },
      },
      redactor,
    );

    const recoverySecret = fakeSecret("generic-password");
    const appEnvSecret = `DATABASE_URL=postgres://app:${fakeSecret("generic-password")}@db/app\nKEY=val`;

    const repoEntry = await sink.seal("OPSCREW_RECOVERY_KEY", recoverySecret, { kind: "repo" });
    const envEntry = await sink.seal("OPSCREW_APP_ENV", appEnvSecret, {
      kind: "environment",
      environment: "production",
    });

    expect(repoEntry.keyId).toBe("repo-key-1");
    expect(envEntry.keyId).toBe("env-key-2");
    expect(JSON.stringify(sink.entries())).not.toContain(recoverySecret);
    expect(JSON.stringify(sink.entries())).not.toContain(appEnvSecret);
    expect(redactor.redact(`leaked ${recoverySecret}`)).not.toContain(recoverySecret);

    const openRepo = sodium.to_string(
      sodium.crypto_box_seal_open(
        sodium.from_base64(repoEntry.encryptedValue, sodium.base64_variants.ORIGINAL),
        repoKp.publicKeyBytes,
        repoKp.privateKeyBytes,
      ),
    );
    const openEnv = sodium.to_string(
      sodium.crypto_box_seal_open(
        sodium.from_base64(envEntry.encryptedValue, sodium.base64_variants.ORIGINAL),
        envKp.publicKeyBytes,
        envKp.privateKeyBytes,
      ),
    );
    expect(openRepo).toBe(recoverySecret);
    expect(openEnv).toBe(appEnvSecret);
  });

  it("refuses environment secret sealing when no environment key was provided", async () => {
    const repoKp = await generateKeyPair();
    const sink = createSealedSecretSink(
      { repo: { keyId: "repo-key-1", publicKey: repoKp.publicKey } },
      new Redactor(),
    );

    await expect(
      sink.seal("OPSCREW_APP_ENV", fakeSecret("generic-password"), {
        kind: "environment",
        environment: "production",
      }),
    ).rejects.toThrow(/no environment secrets public key/);
  });

  it("deduplicates repeated writes to the same secret name and place", async () => {
    const repoKp = await generateKeyPair();
    const sink = createSealedSecretSink(
      { repo: { keyId: "repo-key-1", publicKey: repoKp.publicKey } },
      new Redactor(),
    );

    const first = fakeSecret("generic-password");
    const second = fakeSecret("generic-password");
    await sink.seal("OPSCREW_RECOVERY_KEY", first, { kind: "repo" });
    await sink.seal("OPSCREW_RECOVERY_KEY", second, { kind: "repo" });

    expect(sink.entries()).toHaveLength(1);
    const decrypted = sodium.to_string(
      sodium.crypto_box_seal_open(
        sodium.from_base64(sink.entries()[0]!.encryptedValue, sodium.base64_variants.ORIGINAL),
        repoKp.publicKeyBytes,
        repoKp.privateKeyBytes,
      ),
    );
    expect(decrypted).toBe(second);
  });
});
