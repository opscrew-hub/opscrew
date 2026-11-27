import type { RunReportSecret, RunReportSecretPlace, SealedSecretSink } from "@opscrew/contracts";
import { OpsCrewError, type Redactor, validateSealedKeyPair } from "@opscrew/core";
import { sealSecret } from "./seal";

/** Non-secret GitHub Actions public keys passed into an Actions run (Feature 041). */
export interface SealedSecretTargets {
  /** Repository Actions secrets public key (`GET /repos/{owner}/{repo}/actions/secrets/public-key`). */
  repo: { keyId: string; publicKey: string };
  /** Optional GitHub Environment Actions secrets public key (when secrets target an environment). */
  environment?: { name?: string; keyId: string; publicKey: string };
}

/**
 * Creates a {@link SealedSecretSink} that validates both Curve25519 public keys up front,
 * registers every plaintext secret with `redactor` before encrypting, seals values with libsodium
 * `crypto_box_seal`, and stores only ciphertext entries for `report.json`.
 */
export function createSealedSecretSink(
  targets: SealedSecretTargets,
  redactor: Pick<Redactor, "addLiteral">,
): SealedSecretSink {
  const repo = validateSealedKeyPair(
    targets.repo.keyId,
    targets.repo.publicKey,
    "repository secrets public key",
  );
  const environment =
    targets.environment === undefined
      ? undefined
      : {
          ...(targets.environment.name === undefined ? {} : { name: targets.environment.name }),
          ...validateSealedKeyPair(
            targets.environment.keyId,
            targets.environment.publicKey,
            "environment secrets public key",
          ),
        };
  const sealed: RunReportSecret[] = [];

  return {
    async seal(name: string, value: string, place: RunReportSecretPlace): Promise<RunReportSecret> {
      redactor.addLiteral(value, "sealed-secret");
      let target: { keyId: string; publicKey: string };
      if (place.kind === "repo") {
        target = repo;
      } else {
        if (environment === undefined) {
          throw new OpsCrewError(
            "PHASE_PRECONDITION",
            `Secret ${name} belongs to GitHub environment "${place.environment}", but no environment secrets public key was passed to this run.`,
            {
              hint: "Pass --env-secrets-key-id and --env-secrets-key (from GitHub's environment secrets public-key API) and run again.",
            },
          );
        }
        if (environment.name !== undefined && environment.name !== place.environment) {
          throw new OpsCrewError(
            "PHASE_PRECONDITION",
            `Secret ${name} targets GitHub environment "${place.environment}", but the supplied environment key is for "${environment.name}".`,
            { hint: "Pass the public key for the matching GitHub environment and run again." },
          );
        }
        target = environment;
      }
      const encryptedValue = await sealSecret(target.publicKey, value);
      const entry: RunReportSecret = {
        name,
        keyId: target.keyId,
        encryptedValue,
        place,
      };
      // Replace any earlier write to the same (name, place) within the same run.
      const index = sealed.findIndex(
        (existing) =>
          existing.name === entry.name &&
          existing.place.kind === entry.place.kind &&
          (existing.place.kind === "repo" ||
            (entry.place.kind === "environment" &&
              existing.place.environment === entry.place.environment)),
      );
      if (index >= 0) {
        sealed[index] = entry;
      } else {
        sealed.push(entry);
      }
      return entry;
    },
    entries(): readonly RunReportSecret[] {
      return [...sealed];
    },
  };
}
