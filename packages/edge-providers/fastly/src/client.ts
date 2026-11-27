/**
 * Typed Fastly API client (`https://api.fastly.com`, `Fastly-Key` header).
 * Every API response is validated with zod before use (constitution V), and the API token and
 * origin mTLS client private key are registered with the redactor so they never appear in errors
 * or logs.
 */
import type { CredentialCheck, FetchLike } from "@opscrew/contracts";
import { OpsCrewError, Redactor } from "@opscrew/core";
import { z } from "zod";

export const FASTLY_API_BASE = "https://api.fastly.com";
export const FASTLY_API_TOKEN_URL = "https://manage.fastly.com/account/personal/tokens";

const FastlyTokenSelfSchema = z.object({
  id: z.string().min(1),
});

const FastlyPublicIpListSchema = z.object({
  addresses: z.array(z.string().min(1)).min(1),
  ipv6_addresses: z.array(z.string().min(1)).default([]),
});

const FastlyVersionSchema = z.object({
  number: z.number().int().positive(),
  active: z.boolean().optional(),
});

const FastlyVersionListSchema = z.array(FastlyVersionSchema);

const FastlyBackendSchema = z.object({
  name: z.string().min(1),
  address: z.string().min(1),
  ssl_client_cert: z.string().nullable().optional(),
  ssl_ca_cert: z.string().nullable().optional(),
});

export type FastlyIpRanges = { ipv4: string[]; ipv6: string[] };
export type FastlyBackend = z.infer<typeof FastlyBackendSchema>;

export interface FastlyClientDeps {
  apiKey: string;
  fetch?: FetchLike;
  redactor?: Pick<Redactor, "addLiteral" | "redact">;
  baseUrl?: string;
}

export interface FastlyClient {
  verifyCredentials(): Promise<CredentialCheck>;
  getIpRanges(): Promise<FastlyIpRanges>;
  getActiveVersion(serviceId: string): Promise<number>;
  getBackend(serviceId: string, version: number, backendName: string): Promise<FastlyBackend>;
  cloneVersion(serviceId: string, version: number): Promise<number>;
  updateBackendMtls(input: {
    serviceId: string;
    version: number;
    backendName: string;
    clientCertPem: string;
    clientKeyPem: string;
    originCaCertPem?: string;
    originAddress?: string;
  }): Promise<void>;
  activateVersion(serviceId: string, version: number): Promise<void>;
}

/** Creates a typed Fastly API client authenticating via `Fastly-Key`. */
export function fastlyClient(deps: FastlyClientDeps): FastlyClient {
  const apiKey = deps.apiKey.trim();
  const fetchImpl = deps.fetch ?? globalThis.fetch;
  const baseUrl = (deps.baseUrl ?? FASTLY_API_BASE).replace(/\/+$/, "");
  const redactor = deps.redactor ?? new Redactor();
  if (apiKey.length > 0) redactor.addLiteral(apiKey, "fastly-api-key");

  async function request(
    method: "GET" | "PUT",
    path: string,
    opts: { auth?: boolean; body?: unknown } = {},
  ): Promise<Response> {
    const auth = opts.auth ?? true;
    if (auth && apiKey.length === 0) {
      throw new OpsCrewError("CREDENTIALS_MISSING", "FASTLY_API_KEY is not set.", {
        hint: `Create an API token at ${FASTLY_API_TOKEN_URL} and set FASTLY_API_KEY, then try again.`,
      });
    }
    const headers: Record<string, string> = {
      Accept: "application/json",
      ...(auth ? { "Fastly-Key": apiKey } : {}),
      ...(opts.body === undefined ? {} : { "Content-Type": "application/json" }),
    };
    const response = await fetchImpl(`${baseUrl}${path}`, {
      method,
      headers,
      ...(opts.body === undefined ? {} : { body: JSON.stringify(opts.body) }),
    });
    if (response.status === 401 || response.status === 403) {
      throw new OpsCrewError(
        "CREDENTIALS_INVALID",
        `Fastly rejected FASTLY_API_KEY (HTTP ${response.status}).`,
        {
          hint: `Check FASTLY_API_KEY at ${FASTLY_API_TOKEN_URL} and ensure it has global write scope, then try again.`,
        },
      );
    }
    if (!response.ok) {
      const detail = redactor.redact((await response.text()).slice(0, 200));
      throw new OpsCrewError(
        "PROVIDER_ERROR",
        `Fastly API ${method} ${path} answered HTTP ${response.status}${detail ? `: ${detail}` : ""}.`,
        { hint: "Check Fastly's status page and service settings, then try again." },
      );
    }
    return response;
  }

  async function readJson<T>(response: Response, schema: z.ZodType<T>, label: string): Promise<T> {
    let raw: unknown;
    try {
      raw = await response.json();
    } catch (error) {
      throw new OpsCrewError("PROVIDER_ERROR", `Fastly returned non-JSON for ${label}.`, {
        cause: error,
        hint: "Retry in a moment; if it keeps failing, check Fastly's API status.",
      });
    }
    const parsed = schema.safeParse(raw);
    if (!parsed.success) {
      throw new OpsCrewError("PROVIDER_ERROR", `Fastly returned an unexpected ${label} response.`, {
        hint: "Retry in a moment or report this response shape mismatch.",
      });
    }
    return parsed.data;
  }

  return {
    async verifyCredentials(): Promise<CredentialCheck> {
      if (apiKey.length === 0) {
        return {
          ok: false,
          message: `FASTLY_API_KEY is not set. Create one at ${FASTLY_API_TOKEN_URL}.`,
        };
      }
      try {
        const res = await fetchImpl(`${baseUrl}/tokens/self`, {
          method: "GET",
          headers: { "Fastly-Key": apiKey, Accept: "application/json" },
        });
        if (res.status === 401 || res.status === 403) {
          return {
            ok: false,
            message: `Fastly rejected FASTLY_API_KEY (HTTP ${res.status}). Check your token at ${FASTLY_API_TOKEN_URL}.`,
          };
        }
        if (!res.ok) {
          return {
            ok: false,
            message: `Fastly API answered HTTP ${res.status} while verifying FASTLY_API_KEY.`,
          };
        }
        await readJson(res, FastlyTokenSelfSchema, "token info");
        return { ok: true, message: "Fastly API token verified." };
      } catch (error) {
        return {
          ok: false,
          message: redactor.redact(
            `Could not verify FASTLY_API_KEY: ${error instanceof Error ? error.message : String(error)}`,
          ),
        };
      }
    },

    async getIpRanges(): Promise<FastlyIpRanges> {
      const res = await request("GET", "/public-ip-list", { auth: false });
      const data = await readJson(res, FastlyPublicIpListSchema, "public IP list");
      return { ipv4: data.addresses, ipv6: data.ipv6_addresses };
    },

    async getActiveVersion(serviceId: string): Promise<number> {
      const res = await request("GET", `/service/${encodeURIComponent(serviceId)}/version`);
      const versions = await readJson(res, FastlyVersionListSchema, "service versions");
      const active = versions.find((v) => v.active === true) ?? versions.at(-1);
      if (active === undefined) {
        throw new OpsCrewError(
          "PROVIDER_ERROR",
          `Fastly service "${serviceId}" has no versions to update.`,
        );
      }
      return active.number;
    },

    async getBackend(
      serviceId: string,
      version: number,
      backendName: string,
    ): Promise<FastlyBackend> {
      const res = await request(
        "GET",
        `/service/${encodeURIComponent(serviceId)}/version/${version}/backend/${encodeURIComponent(backendName)}`,
      );
      return readJson(res, FastlyBackendSchema, "backend");
    },

    async cloneVersion(serviceId: string, version: number): Promise<number> {
      const res = await request(
        "PUT",
        `/service/${encodeURIComponent(serviceId)}/version/${version}/clone`,
      );
      const cloned = await readJson(res, FastlyVersionSchema, "cloned version");
      return cloned.number;
    },

    async updateBackendMtls(input): Promise<void> {
      redactor.addLiteral(input.clientKeyPem, "origin-mtls-key");
      await request(
        "PUT",
        `/service/${encodeURIComponent(input.serviceId)}/version/${input.version}/backend/${encodeURIComponent(input.backendName)}`,
        {
          body: {
            ssl_client_cert: input.clientCertPem,
            ssl_client_key: input.clientKeyPem,
            ...(input.originCaCertPem === undefined ? {} : { ssl_ca_cert: input.originCaCertPem }),
            ...(input.originAddress === undefined ? {} : { address: input.originAddress }),
          },
        },
      );
    },

    async activateVersion(serviceId: string, version: number): Promise<void> {
      await request("PUT", `/service/${encodeURIComponent(serviceId)}/version/${version}/activate`);
    },
  };
}
