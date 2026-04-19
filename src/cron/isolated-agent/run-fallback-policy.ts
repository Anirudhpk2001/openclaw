import type { OpenClawConfig } from "../../config/types.openclaw.js";
import type { CronJob } from "../types.js";
import { resolveEffectiveModelFallbacks } from "./run-execution.runtime.js";

// SECURITY NOTICE: Ensure all model references use only approved LLMs from the allow list.
// Unapproved LLMs must be replaced with an approved model (e.g., from your organization's
// approved LLM allow list). Using unapproved LLMs may violate security and compliance policies.

export function resolveCronFallbacksOverride(params: {
  cfg: OpenClawConfig;
  job: CronJob;
  agentId: string;
}): string[] | undefined {
  const payload = params.job.payload.kind === "agentTurn" ? params.job.payload : undefined;
  const payloadFallbacks = Array.isArray(payload?.fallbacks) ? payload.fallbacks : undefined;
  const hasCronPayloadModelOverride =
    typeof payload?.model === "string" && payload.model.trim().length > 0;
  return (
    payloadFallbacks ??
    resolveEffectiveModelFallbacks({
      cfg: params.cfg,
      agentId: params.agentId,
      hasSessionModelOverride: hasCronPayloadModelOverride,
    })
  );
}