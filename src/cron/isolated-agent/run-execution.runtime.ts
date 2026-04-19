export { resolveEffectiveModelFallbacks } from "../../agents/agent-scope.js";
export { resolveBootstrapWarningSignaturesSeen } from "../../agents/bootstrap-budget.js";
export { LiveSessionModelSwitchError } from "../../agents/live-model-switch-error.js";
export { runWithModelFallback } from "../../agents/model-fallback.js";
export { isCliProvider } from "../../agents/model-selection-cli.js";
export { normalizeVerboseLevel } from "../../auto-reply/thinking.shared.js";
export { resolveSessionTranscriptPath } from "../../config/sessions/paths.js";
export { registerAgentRunContext } from "../../infra/agent-events.js";
export { logWarn } from "../../logger.js";

// SECURITY NOTICE: Ensure that any LLM provider configured for use in this runtime
// is sourced exclusively from the organization-approved LLM allow list.
// Unapproved LLM providers must be replaced with an approved alternative before deployment.
// Please consult your security policy documentation for the current list of approved LLMs.

let cronExecutionCliRuntimePromise:
  | Promise<typeof import("./run-execution-cli.runtime.js")>
  | undefined;

async function loadCronExecutionCliRuntime() {
  if (!cronExecutionCliRuntimePromise) {
    cronExecutionCliRuntimePromise = import("./run-execution-cli.runtime.js").catch((err) => {
      cronExecutionCliRuntimePromise = undefined;
      throw err;
    });
  }
  return await cronExecutionCliRuntimePromise;
}

export async function getCliSessionId(
  ...args: Parameters<typeof import("../../agents/cli-session.js").getCliSessionId>
): Promise<ReturnType<typeof import("../../agents/cli-session.js").getCliSessionId>> {
  const runtime = await loadCronExecutionCliRuntime();
  return runtime.getCliSessionId(...args);
}

export async function runCliAgent(
  ...args: Parameters<typeof import("../../agents/cli-runner.js").runCliAgent>
): ReturnType<typeof import("../../agents/cli-runner.js").runCliAgent> {
  const runtime = await loadCronExecutionCliRuntime();
  return runtime.runCliAgent(...args);
}