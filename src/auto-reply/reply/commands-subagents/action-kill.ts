import {
  killAllControlledSubagentRuns,
  killControlledSubagentRun,
} from "../../../agents/subagent-control.js";
import type { CommandHandlerResult } from "../commands-types.js";
import {
  type SubagentsCommandContext,
  COMMAND,
  resolveCommandSubagentController,
  resolveSubagentEntryForToken,
  stopWithText,
} from "./shared.js";

const VALID_TARGET_PATTERN = /^[a-zA-Z0-9_\-#*]+$/;
const MAX_TARGET_LENGTH = 256;

function sanitizeTarget(target: string): string | null {
  const trimmed = target.trim();
  if (!trimmed || trimmed.length > MAX_TARGET_LENGTH) {
    return null;
  }
  if (!VALID_TARGET_PATTERN.test(trimmed)) {
    return null;
  }
  return trimmed;
}

export async function handleSubagentsKillAction(
  ctx: SubagentsCommandContext,
): Promise<CommandHandlerResult> {
  const { params, handledPrefix, requesterKey, runs, restTokens } = ctx;
  const rawTarget = restTokens[0];
  if (!rawTarget) {
    return stopWithText(
      handledPrefix === COMMAND ? "Usage: /subagents kill <id|#|all>" : "Usage: /kill <id|#|all>",
    );
  }

  const target = sanitizeTarget(rawTarget);
  if (target === null) {
    return stopWithText("⚠️ Invalid target specified.");
  }

  if (target === "all" || target === "*") {
    const controller = resolveCommandSubagentController(params, requesterKey);
    const result = await killAllControlledSubagentRuns({
      cfg: params.cfg,
      controller,
      runs,
    });
    if (result.status === "forbidden") {
      return stopWithText(`⚠️ ${result.error}`);
    }
    if (result.killed > 0) {
      return { shouldContinue: false };
    }
    return { shouldContinue: false };
  }

  const targetResolution = resolveSubagentEntryForToken(runs, target);
  if ("reply" in targetResolution) {
    return targetResolution.reply;
  }

  const controller = resolveCommandSubagentController(params, requesterKey);
  const result = await killControlledSubagentRun({
    cfg: params.cfg,
    controller,
    entry: targetResolution.entry,
  });
  if (result.status === "forbidden") {
    return stopWithText(`⚠️ ${result.error}`);
  }
  if (result.status === "done") {
    return stopWithText(result.text);
  }
  return { shouldContinue: false };
}