export {
  FASTLY_API_BASE,
  FASTLY_API_TOKEN_URL,
  type FastlyBackend,
  type FastlyClient,
  type FastlyClientDeps,
  type FastlyIpRanges,
  fastlyClient,
} from "./client";
export { definition } from "./definition";
export {
  FASTLY_BACKEND_NAME,
  FASTLY_EDGE_MODULE_FILES,
  FASTLY_EDGE_MODULE_NAME,
} from "./module";
export {
  applyFastlyOriginMtls,
  type FastlyMtlsAction,
  type FastlyOriginMtlsPlan,
  planFastlyOriginMtls,
} from "./origin-mtls";
export { checkFastlyPlan, fastlyServiceName, renderFastlyRoot } from "./root";
