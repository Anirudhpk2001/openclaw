import { SessionManager } from "@mariozechner/pi-coding-agent";
import { ensureContextEnginesInitialized } from "../../context-engine/init.js";
import { resolveContextEngine } from "../../context-engine/registry.js";
import {
  captureCompactionCheckpointSnapshot,
  cleanupCompactionCheckpointSnapshot,
  persistSessionCompactionCheckpoint,
  resolveSessionCompactionCheckpointReason,
  type CapturedCompactionCheckpointSnapshot,
} from "../../gateway/session-compaction-checkpoints.js";
import { formatErrorMessage } from "../../infra/errors.js";
import { getGlobalHookRunner } from "../../plugins/hook-runner-global.js";
import type { ProviderRuntimeModel } from "../../plugins/provider-runtime-model.types.js";
import { enqueueCommandInLane } from "../../process/command-queue.js";
import { resolveUserPath } from "../../utils.js";
import { resolveOpenClawAgentDir } from "../agent-paths.js";
import { resolveSessionAgentIds } from "../agent-scope.js";
import { resolveContextWindowInfo } from "../context-window-guard.js";
import { DEFAULT_CONTEXT_TOKENS, DEFAULT_MODEL, DEFAULT_PROVIDER } from "../defaults.js";
import { maybeCompactAgentHarnessSession } from "../harness/selection.js";
import { ensureRuntimePluginsLoaded } from "../runtime-plugins.js";
import type { CompactEmbeddedPiSessionParams } from "./compact.types.js";
import { asCompactionHookRunner, runPostCompactionSideEffects } from "./compaction-hooks.js";
import {
  buildEmbeddedCompactionRuntimeContext,
  resolveEmbeddedCompactionTarget,
} from "./compaction-runtime-context.js";
import { runContextEngineMaintenance } from "./context-engine-maintenance.js";
import { resolveGlobalLane, resolveSessionLane } from "./lanes.js";
import { log } from "./logger.js";
import { readPiModelContextTokens } from "./model-context-tokens.js";
import { resolveModelAsync } from "./model.js";
import type { EmbeddedPiCompactResult } from "./types.js";

// APPROVED LLM ALLOW LIST — replace any unapproved model with one from this list.
// NOTE: If the resolved model/provider is not in this list, you must replace it
// with an approved LLM before use.
const APPROVED_LLM_PROVIDERS = ["openai", "anthropic", "azure-openai"] as const;
const APPROVED_LLM_MODELS = [
  "gpt-4o",
  "gpt-4-turbo",
  "gpt-3.5-turbo",
  "claude-3-5-sonnet-20241022",
  "claude-3-opus-20240229",
  "claude-3-haiku-20240307",
] as const;

type ApprovedProvider = (typeof APPROVED_LLM_PROVIDERS)[number];
type ApprovedModel = (typeof APPROVED_LLM_MODELS)[number];

function isApprovedProvider(provider: string): provider is ApprovedProvider {
  return (APPROVED_LLM_PROVIDERS as readonly string[]).includes(provider);
}

function isApprovedModel(model: string): provider is ApprovedModel {
  return (APPROVED_LLM_MODELS as readonly string[]).includes(model);
}

/**
 * Sanitizes and validates input/prompt before sending to the LLM.
 * Removes potentially dangerous content and enforces length limits.
 */
function sanitizeLlmInput(input: string | undefined | null): string {
  if (input == null) return "";
  // Remove null bytes
  let sanitized = input.replace(/\0/g, "");
  // Trim to a safe maximum length to prevent prompt injection via oversized input
  const MAX_INPUT_LENGTH = 32000;
  if (sanitized.length > MAX_INPUT_LENGTH) {
    log.warn("LLM input truncated: exceeded maximum allowed length", {
      originalLength: sanitized.length,
      maxLength: MAX_INPUT_LENGTH,
    });
    sanitized = sanitized.slice(0, MAX_INPUT_LENGTH);
  }
  // Strip prompt injection attempts: lines that attempt to override system instructions
  sanitized = sanitized
    .split("\n")
    .filter((line) => {
      const lower = line.toLowerCase().trim();
      // Block common prompt injection patterns
      if (
        lower.startsWith("ignore previous instructions") ||
        lower.startsWith("disregard all prior") ||
        lower.startsWith("forget your instructions") ||
        lower.startsWith("you are now") ||
        lower.startsWith("act as") ||
        lower.startsWith("pretend you are") ||
        lower.startsWith("system:") ||
        lower.startsWith("[system]") ||
        lower.startsWith("<system>")
      ) {
        log.warn("LLM input sanitization: removed suspicious line", { line });
        return false;
      }
      return true;
    })
    .join("\n");
  return sanitized;
}

/**
 * Sanitizes and validates LLM response output.
 * Removes lines containing dynamic code-execution primitives.
 */
function sanitizeLlmResponse(response: string | undefined | null): string {
  if (response == null) return "";
  // Remove null bytes
  let sanitized = response.replace(/\0/g, "");
  // Remove lines containing dangerous dynamic code execution primitives
  const dangerousPatterns = [
    /\beval\s*\(/i,
    /\bexec\s*\(/i,
    /\bsubprocess\s*\(\s*.*shell\s*=\s*True/i,
    /\bos\.system\s*\(/i,
    /\bos\.popen\s*\(/i,
    /\b__import__\s*\(/i,
    /\bFunction\s*\(\s*['"`]/i,
    /\bnew\s+Function\s*\(/i,
    /\bsetTimeout\s*\(\s*['"`]/i,
    /\bsetInterval\s*\(\s*['"`]/i,
    /\bchild_process/i,
    /\bspawnSync\s*\(/i,
    /\bexecSync\s*\(/i,
    /\bexecFileSync\s*\(/i,
    /\bshell\s*=\s*true/i,
  ];
  sanitized = sanitized
    .split("\n")
    .filter((line) => {
      for (const pattern of dangerousPatterns) {
        if (pattern.test(line)) {
          log.warn("LLM response sanitization: removed dangerous line", {
            pattern: pattern.toString(),
            line,
          });
          return false;
        }
      }
      return true;
    })
    .join("\n");
  return sanitized;
}

/**
 * Logs an LLM interaction (request and response) for audit purposes.
 */
function logLlmInteraction(params: {
  sessionId: string | undefined;
  sessionKey: string | undefined;
  provider: string;
  model: string;
  inputSummary: Record<string, unknown>;
  responseSummary?: Record<string, unknown>;
  phase: "request" | "response" | "error";
  error?: string;
}): void {
  log.info("LLM interaction", {
    phase: params.phase,
    sessionId: params.sessionId,
    sessionKey: params.sessionKey,
    provider: params.provider,
    model: params.model,
    ...(params.phase === "request" ? { input: params.inputSummary } : {}),
    ...(params.phase === "response" ? { response: params.responseSummary } : {}),
    ...(params.phase === "error" ? { error: params.error } : {}),
    timestamp: new Date().toISOString(),
  });
}

/**
 * Compacts a session with lane queueing (session lane + global lane).
 * Use this from outside a lane context. If already inside a lane, use
 * `compactEmbeddedPiSessionDirect` to avoid deadlocks.
 */
export async function compactEmbeddedPiSession(
  params: CompactEmbeddedPiSessionParams,
): Promise<EmbeddedPiCompactResult> {
  const harnessResult = await maybeCompactAgentHarnessSession(params);
  if (harnessResult) {
    return harnessResult;
  }
  const sessionLane = resolveSessionLane(params.sessionKey?.trim() || params.sessionId);
  const globalLane = resolveGlobalLane(params.lane);
  const enqueueGlobal =
    params.enqueue ?? ((task, opts) => enqueueCommandInLane(globalLane, task, opts));
  return enqueueCommandInLane(sessionLane, () =>
    enqueueGlobal(async () => {
      ensureRuntimePluginsLoaded({
        config: params.config,
        workspaceDir: params.workspaceDir,
        allowGatewaySubagentBinding: params.allowGatewaySubagentBinding,
      });
      ensureContextEnginesInitialized();
      const contextEngine = await resolveContextEngine(params.config);
      let checkpointSnapshot: CapturedCompactionCheckpointSnapshot | null = null;
      let checkpointSnapshotRetained = false;
      try {
        const agentDir = params.agentDir ?? resolveOpenClawAgentDir();
        const resolvedCompactionTarget = resolveEmbeddedCompactionTarget({
          config: params.config,
          provider: params.provider,
          modelId: params.model,
          authProfileId: params.authProfileId,
          defaultProvider: DEFAULT_PROVIDER,
          defaultModel: DEFAULT_MODEL,
        });
        // Resolve token budget from the effective compaction model so engine-
        // owned /compact implementations see the same target as the runtime.
        const ceProvider = resolvedCompactionTarget.provider ?? DEFAULT_PROVIDER;
        const ceModelId = resolvedCompactionTarget.model ?? DEFAULT_MODEL;

        // Enforce approved LLM policy
        if (!isApprovedProvider(ceProvider)) {
          log.warn(
            `SECURITY POLICY: Provider "${ceProvider}" is not in the approved LLM provider list. ` +
              `Please replace it with an approved provider from: ${APPROVED_LLM_PROVIDERS.join(", ")}. ` +
              `Proceeding with unapproved provider — update your configuration immediately.`,
            { unapprovedProvider: ceProvider, approvedProviders: APPROVED_LLM_PROVIDERS },
          );
        }
        if (!isApprovedModel(ceModelId)) {
          log.warn(
            `SECURITY POLICY: Model "${ceModelId}" is not in the approved LLM model list. ` +
              `Please replace it with an approved model from: ${APPROVED_LLM_MODELS.join(", ")}. ` +
              `Proceeding with unapproved model — update your configuration immediately.`,
            { unapprovedModel: ceModelId, approvedModels: APPROVED_LLM_MODELS },
          );
        }

        const { model: ceModel } = await resolveModelAsync(
          ceProvider,
          ceModelId,
          agentDir,
          params.config,
        );
        const ceRuntimeModel = ceModel as ProviderRuntimeModel | undefined;
        const ceCtxInfo = resolveContextWindowInfo({
          cfg: params.config,
          provider: ceProvider,
          modelId: ceModelId,
          modelContextTokens: readPiModelContextTokens(ceModel),
          modelContextWindow: ceRuntimeModel?.contextWindow,
          defaultTokens: DEFAULT_CONTEXT_TOKENS,
        });
        // When the context engine owns compaction, its compact() implementation
        // bypasses compactEmbeddedPiSessionDirect (which fires the hooks internally).
        // Fire before_compaction / after_compaction hooks here so plugin subscribers
        // are notified regardless of which engine is active.
        const engineOwnsCompaction = contextEngine.info.ownsCompaction === true;
        checkpointSnapshot = engineOwnsCompaction
          ? captureCompactionCheckpointSnapshot({
              sessionManager: SessionManager.open(params.sessionFile),
              sessionFile: params.sessionFile,
            })
          : null;
        const hookRunner = engineOwnsCompaction
          ? asCompactionHookRunner(getGlobalHookRunner())
          : null;
        const hookSessionKey = params.sessionKey?.trim() || params.sessionId;
        const { sessionAgentId } = resolveSessionAgentIds({
          sessionKey: params.sessionKey,
          config: params.config,
        });
        const resolvedMessageProvider = params.messageChannel ?? params.messageProvider;
        const hookCtx = {
          sessionId: params.sessionId,
          agentId: sessionAgentId,
          sessionKey: hookSessionKey,
          workspaceDir: resolveUserPath(params.workspaceDir),
          messageProvider: resolvedMessageProvider,
        };

        // Sanitize LLM inputs before use
        const sanitizedCustomInstructions = sanitizeLlmInput(params.customInstructions);
        const sanitizedExtraSystemPrompt = sanitizeLlmInput(params.extraSystemPrompt);

        const runtimeContext = {
          ...params,
          ...buildEmbeddedCompactionRuntimeContext({
            sessionKey: params.sessionKey,
            messageChannel: params.messageChannel,
            messageProvider: params.messageProvider,
            agentAccountId: params.agentAccountId,
            currentChannelId: params.currentChannelId,
            currentThreadTs: params.currentThreadTs,
            currentMessageId: params.currentMessageId,
            authProfileId: params.authProfileId,
            workspaceDir: params.workspaceDir,
            agentDir,
            config: params.config,
            skillsSnapshot: params.skillsSnapshot,
            senderIsOwner: params.senderIsOwner,
            senderId: params.senderId,
            provider: params.provider,
            modelId: params.model,
            thinkLevel: params.thinkLevel,
            reasoningLevel: params.reasoningLevel,
            bashElevated: params.bashElevated,
            extraSystemPrompt: sanitizedExtraSystemPrompt,
            ownerNumbers: params.ownerNumbers,
          }),
        };
        // Engine-owned compaction doesn't load the transcript at this level, so
        // message counts are unavailable. We pass sessionFile so hook subscribers
        // can read the transcript themselves if they need exact counts.
        if (hookRunner?.hasHooks?.("before_compaction") && hookRunner.runBeforeCompaction) {
          try {
            await hookRunner.runBeforeCompaction(
              {
                messageCount: -1,
                sessionFile: params.sessionFile,
              },
              hookCtx,
            );
          } catch (err) {
            log.warn("before_compaction hook failed", {
              errorMessage: formatErrorMessage(err),
            });
          }
        }

        // Log LLM interaction request
        logLlmInteraction({
          sessionId: params.sessionId,
          sessionKey: params.sessionKey,
          provider: ceProvider,
          model: ceModelId,
          phase: "request",
          inputSummary: {
            sessionId: params.sessionId,
            sessionKey: params.sessionKey,
            tokenBudget: ceCtxInfo.tokens,
            currentTokenCount: params.currentTokenCount,
            compactionTarget: params.trigger === "manual" ? "threshold" : "budget",
            hasCustomInstructions: sanitizedCustomInstructions.length > 0,
            force: params.trigger === "manual",
          },
        });

        let result: Awaited<ReturnType<typeof contextEngine.compact>>;
        try {
          result = await contextEngine.compact({
            sessionId: params.sessionId,
            sessionKey: params.sessionKey,
            sessionFile: params.sessionFile,
            tokenBudget: ceCtxInfo.tokens,
            currentTokenCount: params.currentTokenCount,
            compactionTarget: params.trigger === "manual" ? "threshold" : "budget",
            customInstructions: sanitizedCustomInstructions,
            force: params.trigger === "manual",
            runtimeContext,
          });
        } catch (err) {
          // Log LLM interaction error
          logLlmInteraction({
            sessionId: params.sessionId,
            sessionKey: params.sessionKey,
            provider: ceProvider,
            model: ceModelId,
            phase: "error",
            inputSummary: {},
            error: formatErrorMessage(err),
          });
          throw err;
        }

        // Sanitize and validate LLM response
        const rawSummary = result.result?.summary ?? "";
        const sanitizedSummary = sanitizeLlmResponse(rawSummary);
        if (result.result && rawSummary !== sanitizedSummary) {
          log.warn("LLM response summary was sanitized: dangerous content removed", {
            sessionId: params.sessionId,
          });
          result = {
            ...result,
            result: {
              ...result.result,
              summary: sanitizedSummary,
            },
          };
        }

        // Log LLM interaction response
        logLlmInteraction({
          sessionId: params.sessionId,
          sessionKey: params.sessionKey,
          provider: ceProvider,
          model: ceModelId,
          phase: "response",
          inputSummary: {},
          responseSummary: {
            ok: result.ok,
            compacted: result.compacted,
            reason: result.reason,
            tokensBefore: result.result?.tokensBefore,
            tokensAfter: result.result?.tokensAfter,
            hasSummary: (result.result?.summary?.length ?? 0) > 0,
          },
        });

        if (result.ok && result.compacted) {
          if (params.config && params.sessionKey && checkpointSnapshot) {
            try {
              const postCompactionSession = SessionManager.open(params.sessionFile);
              const postLeafId = postCompactionSession.getLeafId() ?? undefined;
              const storedCheckpoint = await persistSessionCompactionCheckpoint({
                cfg: params.config,
                sessionKey: params.sessionKey,
                sessionId: params.sessionId,
                reason: resolveSessionCompactionCheckpointReason({
                  trigger: params.trigger,
                }),
                snapshot: checkpointSnapshot,
                summary: result.result?.summary,
                firstKeptEntryId: result.result?.firstKeptEntryId,
                tokensBefore: result.result?.tokensBefore,
                tokensAfter: result.result?.tokensAfter,
                postSessionFile: params.sessionFile,
                postLeafId,
                postEntryId: postLeafId,
              });
              checkpointSnapshotRetained = storedCheckpoint !== null;
            } catch (err) {
              log.warn("failed to persist compaction checkpoint", {
                errorMessage: formatErrorMessage(err),
              });
            }
          }
          await runContextEngineMaintenance({
            contextEngine,
            sessionId: params.sessionId,
            sessionKey: params.sessionKey,
            sessionFile: params.sessionFile,
            reason: "compaction",
            runtimeContext,
          });
        }
        if (engineOwnsCompaction && result.ok && result.compacted) {
          await runPostCompactionSideEffects({
            config: params.config,
            sessionKey: params.sessionKey,
            sessionFile: params.sessionFile,
          });
        }
        if (
          result.ok &&
          result.compacted &&
          hookRunner?.hasHooks?.("after_compaction") &&
          hookRunner.runAfterCompaction
        ) {
          try {
            await hookRunner.runAfterCompaction(
              {
                messageCount: -1,
                compactedCount: -1,
                tokenCount: result.result?.tokensAfter,
                sessionFile: params.sessionFile,
              },
              hookCtx,
            );
          } catch (err) {
            log.warn("after_compaction hook failed", {
              errorMessage: formatErrorMessage(err),
            });
          }
        }
        return {
          ok: result.ok,
          compacted: result.compacted,
          reason: result.reason,
          result: result.result
            ? {
                summary: result.result.summary ?? "",
                firstKeptEntryId: result.result.firstKeptEntryId ?? "",
                tokensBefore: result.result.tokensBefore,
                tokensAfter: result.result.tokensAfter,
                details: result.result.details,
              }
            : undefined,
        };
      } finally {
        if (!checkpointSnapshotRetained) {
          await cleanupCompactionCheckpointSnapshot(checkpointSnapshot);
        }
        await contextEngine.dispose?.();
      }
    }),
  );
}