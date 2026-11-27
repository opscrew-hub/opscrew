export { type AzureDesignResult, type RunAzureDesignOptions, runAzureDesign } from "./design";
export {
  type AzurePluginOptions,
  type LoadedAzurePlugin,
  loadAzurePlugin,
  requireAzureTarget,
  resolveAzureConnector,
} from "./loader";
export {
  type AzureAdviceItem,
  type AzurePlanInput,
  planAzureRetarget,
  runAzureAdvise,
  runAzureDestroy,
  runAzureDrift,
  runAzureLogs,
  runAzureRestoreDrill,
  runAzureRotateSecrets,
  runAzureSnapshotList,
  runAzureSnapshotTake,
  runAzureStatus,
  runAzureVerify,
} from "./operations";
export {
  type AzureCloudflareDnsWriter,
  type AzureProvisionResult,
  type RunAzureProvisionOptions,
  runAzureProvision,
} from "./provision";
