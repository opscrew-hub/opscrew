import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { applyFastlyOriginMtls, planFastlyOriginMtls } from "./origin-mtls";

const CERT_1 = "-----BEGIN CERTIFICATE-----\nCERT-ONE-PAYLOAD\n-----END CERTIFICATE-----";
const CERT_2 = "-----BEGIN CERTIFICATE-----\nCERT-TWO-PAYLOAD\n-----END CERTIFICATE-----";
const CA_CERT_1 = "-----BEGIN CERTIFICATE-----\nORIGIN-CA-ONE\n-----END CERTIFICATE-----";
const CA_CERT_2 = "-----BEGIN CERTIFICATE-----\nORIGIN-CA-TWO\n-----END CERTIFICATE-----";
const KEY_1 = generateKeyPairSync("ec", { namedCurve: "prime256v1" })
  .privateKey.export({ type: "pkcs8", format: "pem" })
  .toString();
const KEY_2 = generateKeyPairSync("ec", { namedCurve: "prime256v1" })
  .privateKey.export({ type: "pkcs8", format: "pem" })
  .toString();

function fakeFastly(initialCert: string | null = null, initialCaCert: string | null = null) {
  let activeVersion = 1;
  let cert = initialCert;
  let caCert = initialCaCert;
  let address = "203.0.113.10";
  const events: string[] = [];
  return {
    events,
    getCert: () => cert,
    getCaCert: () => caCert,
    getAddress: () => address,
    client: {
      async getActiveVersion() {
        return activeVersion;
      },
      async getBackend(_serviceId: string, _version: number, backendName: string) {
        return {
          name: backendName,
          address,
          ssl_client_cert: cert,
          ssl_ca_cert: caCert,
        };
      },
      async cloneVersion(_serviceId: string, version: number) {
        const next = version + 1;
        events.push(`clone:${version}->${next}`);
        return next;
      },
      async updateBackendMtls(input: {
        serviceId: string;
        version: number;
        backendName: string;
        clientCertPem: string;
        clientKeyPem: string;
        originCaCertPem?: string;
        originAddress?: string;
      }) {
        events.push(`update:v${input.version}:${input.backendName}`);
        cert = input.clientCertPem;
        if (input.originCaCertPem !== undefined) caCert = input.originCaCertPem;
        if (input.originAddress !== undefined) address = input.originAddress;
      },
      async activateVersion(_serviceId: string, version: number) {
        events.push(`activate:v${version}`);
        activeVersion = version;
      },
    },
  };
}

describe("Fastly origin mTLS plan & hash-bound apply", () => {
  it("plans configure, noop, and update while refusing hash/cert mismatches and keeping keys out of plans", async () => {
    const fake = fakeFastly(null);
    const configurePlan = await planFastlyOriginMtls(fake.client, {
      serviceId: "svc-fastly-1",
      backendName: "opscrew_origin",
      clientCertPem: CERT_1,
      clientKeyPem: KEY_1,
    });
    expect(configurePlan.action).toBe("configure");
    expect(configurePlan.activeVersion).toBe(1);
    expect(configurePlan.summary).not.toContain(KEY_1);
    expect(configurePlan.hash).toMatch(/^[0-9a-f]{64}$/);

    // Mismatched hash refused.
    await expect(
      applyFastlyOriginMtls(fake.client, configurePlan, {
        clientCertPem: CERT_1,
        clientKeyPem: KEY_1,
        approvedHash: "0".repeat(64),
      }),
    ).rejects.toMatchObject({ code: "APPROVAL_REFUSED" });
    expect(fake.events).toEqual([]);

    // Changed certificate after hashing refused.
    await expect(
      applyFastlyOriginMtls(fake.client, configurePlan, {
        clientCertPem: CERT_2,
        clientKeyPem: KEY_2,
        approvedHash: configurePlan.hash,
      }),
    ).rejects.toMatchObject({ code: "APPROVAL_REFUSED" });
    expect(fake.events).toEqual([]);

    // Approved apply clones v1 -> v2, updates backend, activates v2.
    await expect(
      applyFastlyOriginMtls(fake.client, configurePlan, {
        clientCertPem: CERT_1,
        clientKeyPem: KEY_1,
        approvedHash: configurePlan.hash,
      }),
    ).resolves.toEqual({ applied: true, activatedVersion: 2 });
    expect(fake.events).toEqual(["clone:1->2", "update:v2:opscrew_origin", "activate:v2"]);

    // Re-planning with same cert is a noop.
    const noopPlan = await planFastlyOriginMtls(fake.client, {
      serviceId: "svc-fastly-1",
      backendName: "opscrew_origin",
      clientCertPem: CERT_1,
      clientKeyPem: KEY_1,
    });
    expect(noopPlan.action).toBe("noop");
    await expect(
      applyFastlyOriginMtls(fake.client, noopPlan, {
        clientCertPem: CERT_1,
        clientKeyPem: KEY_1,
        approvedHash: noopPlan.hash,
      }),
    ).resolves.toEqual({ applied: false });

    // Rotating to CERT_2 plans update and activates v3.
    const updatePlan = await planFastlyOriginMtls(fake.client, {
      serviceId: "svc-fastly-1",
      backendName: "opscrew_origin",
      clientCertPem: CERT_2,
      clientKeyPem: KEY_2,
    });
    expect(updatePlan.action).toBe("update");
    await expect(
      applyFastlyOriginMtls(fake.client, updatePlan, {
        clientCertPem: CERT_2,
        clientKeyPem: KEY_2,
        approvedHash: updatePlan.hash,
      }),
    ).resolves.toEqual({ applied: true, activatedVersion: 3 });
    expect(fake.getCert()).toBe(CERT_2);
  });

  it("pins originCaCertPem as ssl_ca_cert alongside the client certificate and rejects CA mismatch after hashing", async () => {
    const fake = fakeFastly(null, null);
    const plan = await planFastlyOriginMtls(fake.client, {
      serviceId: "svc-fastly-2",
      backendName: "opscrew_origin",
      clientCertPem: CERT_1,
      clientKeyPem: KEY_1,
      originCaCertPem: CA_CERT_1,
    });
    expect(plan.action).toBe("configure");
    expect(plan.caCertFingerprint).toMatch(/^[0-9a-f]{12}$/);

    await expect(
      applyFastlyOriginMtls(fake.client, plan, {
        clientCertPem: CERT_1,
        clientKeyPem: KEY_1,
        originCaCertPem: CA_CERT_2,
        approvedHash: plan.hash,
      }),
    ).rejects.toMatchObject({ code: "APPROVAL_REFUSED" });

    await expect(
      applyFastlyOriginMtls(fake.client, plan, {
        clientCertPem: CERT_1,
        clientKeyPem: KEY_1,
        originCaCertPem: CA_CERT_1,
        approvedHash: plan.hash,
      }),
    ).resolves.toEqual({ applied: true, activatedVersion: 2 });
    expect(fake.getCaCert()).toBe(CA_CERT_1);

    // Same client cert + same CA cert is a noop; rotating only the CA plans an update.
    const noop = await planFastlyOriginMtls(fake.client, {
      serviceId: "svc-fastly-2",
      backendName: "opscrew_origin",
      clientCertPem: CERT_1,
      clientKeyPem: KEY_1,
      originCaCertPem: CA_CERT_1,
    });
    expect(noop.action).toBe("noop");

    const rotateCa = await planFastlyOriginMtls(fake.client, {
      serviceId: "svc-fastly-2",
      backendName: "opscrew_origin",
      clientCertPem: CERT_1,
      clientKeyPem: KEY_1,
      originCaCertPem: CA_CERT_2,
    });
    expect(rotateCa.action).toBe("update");

    // Reconciling a changed server IP plans an update even when certs already match, and rejects
    // an address changed after hashing.
    const moveOrigin = await planFastlyOriginMtls(fake.client, {
      serviceId: "svc-fastly-2",
      backendName: "opscrew_origin",
      clientCertPem: CERT_1,
      clientKeyPem: KEY_1,
      originCaCertPem: CA_CERT_1,
      originAddress: "198.51.100.77",
    });
    expect(moveOrigin.action).toBe("update");
    expect(moveOrigin.originAddress).toBe("198.51.100.77");
    await expect(
      applyFastlyOriginMtls(fake.client, moveOrigin, {
        clientCertPem: CERT_1,
        clientKeyPem: KEY_1,
        originCaCertPem: CA_CERT_1,
        originAddress: "198.51.100.88",
        approvedHash: moveOrigin.hash,
      }),
    ).rejects.toMatchObject({ code: "APPROVAL_REFUSED" });
    await expect(
      applyFastlyOriginMtls(fake.client, moveOrigin, {
        clientCertPem: CERT_1,
        clientKeyPem: KEY_1,
        originCaCertPem: CA_CERT_1,
        originAddress: "198.51.100.77",
        approvedHash: moveOrigin.hash,
      }),
    ).resolves.toEqual({ applied: true, activatedVersion: 3 });
    expect(fake.getAddress()).toBe("198.51.100.77");
  });

  it("refuses non-PEM certificates or keys", async () => {
    const fake = fakeFastly(null);
    await expect(
      planFastlyOriginMtls(fake.client, {
        serviceId: "svc-1",
        backendName: "opscrew_origin",
        clientCertPem: "not-a-cert",
        clientKeyPem: KEY_1,
      }),
    ).rejects.toMatchObject({ code: "INVALID_INPUT" });
  });
});
