import { countPendingDescendantRuns } from "../../../agents/subagent-registry.js";
import { loadSessionStore, resolveStorePath } from "../../../config/sessions.js";
import { formatDurationCompact } from "../../../shared/subagents-format.js";
import { findTaskByRunId } from "../../../tasks/task-registry.js";
import type { CommandHandlerResult } from "../commands-types.js";
import { formatRunLabel } from "../subagents-utils.js";
import {
  type SubagentsCommandContext,
  formatTimestampWithAge,
  loadSubagentSessionEntry,
  resolveDisplayStatus,
  resolveSubagentEntryForToken,
  stopWithText,
} from "./shared.js";

function sanitizeText(value: unknown): string {
  if (value === null || value === undefined) {
    return "n/a";
  }
  return String(value)
    .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, "")
    .slice(0, 2048);
}

function sanitizeToken(value: unknown): string {
  if (value === null || value === undefined) {
    return "";
  }
  return String(value)
    .replace(/[^a-zA-Z0-9_\-#.]/g, "")
    .slice(0, 256);
}

export function handleSubagentsInfoAction(ctx: SubagentsCommandContext): CommandHandlerResult {
  const { params, runs, restTokens } = ctx;
  const rawTarget = restTokens[0];
  if (!rawTarget) {
    return stopWithText("ℹ️ Usage: /subagents info <id|#>");
  }

  const target = sanitizeToken(rawTarget);
  if (!target) {
    return stopWithText("ℹ️ Usage: /subagents info <id|#>");
  }

  const targetResolution = resolveSubagentEntryForToken(runs, target);
  if ("reply" in targetResolution) {
    return targetResolution.reply;
  }

  const run = targetResolution.entry;
  const { entry: sessionEntry } = loadSubagentSessionEntry(params, run.childSessionKey, {
    loadSessionStore,
    resolveStorePath,
  });
  const runtime =
    run.startedAt && Number.isFinite(run.startedAt)
      ? (formatDurationCompact((run.endedAt ?? Date.now()) - run.startedAt) ?? "n/a")
      : "n/a";
  const outcome = run.outcome
    ? `${sanitizeText(run.outcome.status)}${run.outcome.error ? ` (${sanitizeText(run.outcome.error)})` : ""}`
    : "n/a";
  const linkedTask = findTaskByRunId(run.runId);

  const lines = [
    "ℹ️ Subagent info",
    `Status: ${sanitizeText(resolveDisplayStatus(run, { pendingDescendants: countPendingDescendantRuns(run.childSessionKey) }))}`,
    `Label: ${sanitizeText(formatRunLabel(run))}`,
    `Task: ${sanitizeText(run.task)}`,
    `Run: ${sanitizeText(run.runId)}`,
    linkedTask ? `TaskId: ${sanitizeText(linkedTask.taskId)}` : undefined,
    linkedTask ? `TaskStatus: ${sanitizeText(linkedTask.status)}` : undefined,
    `Session: ${sanitizeText(run.childSessionKey)}`,
    `SessionId: ${sanitizeText(sessionEntry?.sessionId)}`,
    `Transcript: ${sanitizeText(sessionEntry?.sessionFile)}`,
    `Runtime: ${sanitizeText(runtime)}`,
    `Created: ${formatTimestampWithAge(run.createdAt)}`,
    `Started: ${formatTimestampWithAge(run.startedAt)}`,
    `Ended: ${formatTimestampWithAge(run.endedAt)}`,
    `Cleanup: ${sanitizeText(run.cleanup)}`,
    run.archiveAtMs ? `Archive: ${formatTimestampWithAge(run.archiveAtMs)}` : undefined,
    run.cleanupHandled ? "Cleanup handled: yes" : undefined,
    `Outcome: ${outcome}`,
    linkedTask?.progressSummary ? `Progress: ${sanitizeText(linkedTask.progressSummary)}` : undefined,
    linkedTask?.terminalSummary ? `Task summary: ${sanitizeText(linkedTask.terminalSummary)}` : undefined,
    linkedTask?.error ? `Task error: ${sanitizeText(linkedTask.error)}` : undefined,
    linkedTask ? `Delivery: ${sanitizeText(linkedTask.deliveryStatus)}` : undefined,
  ].filter(Boolean);

  return stopWithText(lines.join("\n"));
}