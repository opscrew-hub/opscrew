/**
 * The built-in DNS and edge proxy providers (ADR 0038): the one place OpsCrew reads edge provider
 * facts from. Every definition is validated when this module loads.
 */
import type { EdgeProviderDefinition } from "@opscrew/contracts";
import { listText, OpsCrewError } from "@opscrew/core";
import { definition as bunny } from "@opscrew/edge-provider-bunny";
import { definition as cloudflare } from "@opscrew/edge-provider-cloudflare";
import { definition as fastly } from "@opscrew/edge-provider-fastly";
import { definition as gcore } from "@opscrew/edge-provider-gcore";
import { validateEdgeProvider } from "./validate";

export { validateEdgeProvider } from "./validate";

/** The built-in edge proxy providers, in order. */
export const EDGE_PROVIDERS: readonly EdgeProviderDefinition[] = [
  cloudflare,
  bunny,
  gcore,
  fastly,
].map(validateEdgeProvider);

/** The definition of the edge provider `id`; throws `INVALID_INPUT` for any other id. */
export function edgeProvider(id: string): EdgeProviderDefinition {
  const found = EDGE_PROVIDERS.find((provider) => provider.id === id);
  if (found !== undefined) return found;
  throw new OpsCrewError("INVALID_INPUT", `OpsCrew does not support edge provider "${id}".`, {
    hint: `Choose one of its edge providers: ${listText(EDGE_PROVIDERS.map((provider) => provider.id))}.`,
  });
}
