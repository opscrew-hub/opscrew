import type {
  RunReportSecret,
  RunReportSecretDelete,
  RunReportSecretPlace,
  SealedSecretSink,
} from "@opscrew/contracts";
import { OpsCrewError, type Redactor, validateSealedKeyPair } from "@opscrew/core";
import { sealSecret } from "./seal";

/** Non-secret GitHub Actions public keys passed into an Actions run (Feature 041). */
export interface SealedSecretTargets {
  /** Repository Actions secrets public key (`GET /repos/{owner}/{repo}/actions/secrets/public-key`). */
  repo: { keyId: string; publicKey: string };
  /**
   * Optional GitHub Environment Actions secrets public key (when secrets target an environment).
   * `name` is required so secrets can never be accidentally sealed with the wrong environment's key.
   */
  environment?: { name: string; keyId: string; publicKey: string };
}

function samePlace(a: RunReportSecretPlace, b: RunReportSecretPlace): boolean {
  if (a.kind !== b.kind) return false;
  return a.kind === "repo" || (b.kind === "environment" && a.environment === b.environment);
}

/**
 * Creates a {@link SealedSecretSink} that validates both Curve25519 public keys up front,
 * registers every plaintext secret with `redactor` before encrypting, seals values with libsodium
 * `crypto_box_seal`, and stores only ciphertext entries (and secret deletion records) for `report.json`.
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
  let environment: { name: string; keyId: string; publicKey: string } | undefined;
  if (targets.environment !== undefined) {
    const envName = targets.environment.name.trim();
    if (envName === "") {
      throw new OpsCrewError(
        "INVALID_INPUT",
        "Environment name is required alongside the environment secrets public key.",
        {
          hint: "Pass --env-secrets-name <github-environment> (or OPSCREW_ENV_SECRETS_NAME) with --env-secrets-key-id and --env-secrets-key.",
        },
      );
    }
    environment = {
      name: envName,
      ...validateSealedKeyPair(
        targets.environment.keyId,
        targets.environment.publicKey,
        "environment secrets public key",
      ),
    };
  }
  const sealed: RunReportSecret[] = [];
  const deleted: RunReportSecretDelete[] = [];

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
              hint: "Pass --env-secrets-name, --env-secrets-key-id, and --env-secrets-key (from GitHub's environment secrets public-key API) and run again.",
            },
          );
        }
        if (environment.name !== place.environment) {
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
      // If a secret is re-created after a delete in the same run, remove the pending delete.
      const delIndex = deleted.findIndex(
        (item) => item.name === entry.name && samePlace(item.place, entry.place),
      );
      if (delIndex >= 0) deleted.splice(delIndex, 1);
      // Replace any earlier write to the same (name, place) within the same run.
      const index = sealed.findIndex(
        (existing) => existing.name === entry.name && samePlace(existing.place, entry.place),
      );
      if (index >= 0) {
        sealed[index] = entry;
      } else {
        sealed.push(entry);
      }
      return entry;
    },
    recordDelete(name: string, place: RunReportSecretPlace): void {
      const sealIndex = sealed.findIndex(
        (item) => item.name === name && samePlace(item.place, place),
      );
      if (sealIndex >= 0) sealed.splice(sealIndex, 1);
      const exists = deleted.some((item) => item.name === name && samePlace(item.place, place));
      if (!exists) deleted.push({ name, place });
    },
    entries(): readonly RunReportSecret[] {
      return [...sealed];
    },
    deletedEntries(): readonly RunReportSecretDelete[] {
      return [...deleted];
    },
  };
}
