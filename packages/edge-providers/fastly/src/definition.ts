/**
 * Fastly edge-only VCL proxy provider definition (ADR 0038).
 * Fastly does not host DNS; pair `dns.edge: fastly` with a supported DNS host (`bunny` or `gcore`).
 */
import { EDGE_PROVIDER_CONTRACT_VERSION, type EdgeProviderDefinition } from "@opscrew/contracts";
import { FASTLY_API_TOKEN_URL, fastlyClient } from "./client";
import { FASTLY_EDGE_MODULE_FILES, FASTLY_EDGE_MODULE_NAME } from "./module";
import { applyFastlyOriginMtls, planFastlyOriginMtls } from "./origin-mtls";
import { checkFastlyPlan, renderFastlyRoot } from "./root";

export const definition: EdgeProviderDefinition = {
  contractVersion: EDGE_PROVIDER_CONTRACT_VERSION,
  id: "fastly",
  displayName: "Fastly",
  capabilities: {
    originAuth: "mtls-client-cert",
    originIpFiltering: "compact-cidrs",
    realIpHeader: "Fastly-Client-IP",
  },
  credentials: {
    envVars: ["FASTLY_API_KEY"],
    createUrl: FASTLY_API_TOKEN_URL,
  },
  terraform: {
    provider: {
      name: "fastly",
      source: "fastly/fastly",
      version: "~> 10.4",
    },
    credentialsComment: "API token from the FASTLY_API_KEY environment variable.",
    module: {
      name: FASTLY_EDGE_MODULE_NAME,
      files: FASTLY_EDGE_MODULE_FILES,
    },
    root: {
      resourceIdOutput: "fastly_service_id",
      backendNameOutput: "fastly_backend_name",
      edgeDnsOutputs: {
        cnameTarget: "edge_cname_target",
        ipv4Targets: "edge_ipv4_targets",
        ipv6Targets: "edge_ipv6_targets",
        tlsValidationRecords: "tls_validation_records",
      },
      render: renderFastlyRoot,
    },
  },
  secops: {
    checkPlan: checkFastlyPlan,
  },
  connector: {
    verifyCredentials: ({ apiKey, fetch, redactor }) =>
      fastlyClient({
        apiKey,
        ...(fetch === undefined ? {} : { fetch }),
        ...(redactor === undefined ? {} : { redactor }),
      }).verifyCredentials(),
    getIpRanges: ({ fetch, redactor }) =>
      fastlyClient({
        apiKey: "",
        ...(fetch === undefined ? {} : { fetch }),
        ...(redactor === undefined ? {} : { redactor }),
      }).getIpRanges(),
    planOriginMtls: ({
      apiKey,
      serviceId,
      backendName,
      clientCertPem,
      clientKeyPem,
      originCaCertPem,
      originAddress,
      fetch,
      redactor,
    }) =>
      planFastlyOriginMtls(
        fastlyClient({
          apiKey,
          ...(fetch === undefined ? {} : { fetch }),
          ...(redactor === undefined ? {} : { redactor }),
        }),
        {
          serviceId,
          backendName,
          clientCertPem,
          clientKeyPem,
          ...(originCaCertPem === undefined ? {} : { originCaCertPem }),
          ...(originAddress === undefined ? {} : { originAddress }),
        },
      ),
    applyOriginMtls: ({
      apiKey,
      plan,
      clientCertPem,
      clientKeyPem,
      originCaCertPem,
      originAddress,
      approvedHash,
      fetch,
      redactor,
    }) =>
      applyFastlyOriginMtls(
        fastlyClient({
          apiKey,
          ...(fetch === undefined ? {} : { fetch }),
          ...(redactor === undefined ? {} : { redactor }),
        }),
        plan,
        {
          clientCertPem,
          clientKeyPem,
          ...(originCaCertPem === undefined ? {} : { originCaCertPem }),
          ...(originAddress === undefined ? {} : { originAddress }),
          approvedHash,
        },
      ),
  },
  texts: {
    secops: {
      edgeLabel: "Fastly's edge",
      edgeTlsHint:
        "This is what Fastly serves to visitors: check your Fastly TLS subscription and TLS configuration in the Fastly web interface.",
    },
  },
};
