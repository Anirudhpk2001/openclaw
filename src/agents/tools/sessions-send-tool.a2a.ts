import crypto from "node:crypto";
import type { CallGatewayOptions } from "../../gateway/call.js";
import { formatErrorMessage } from "../../infra/errors.js";
import { createSubsystemLogger } from "../../logging/subsystem.js";
import type { GatewayMessageChannel } from "../../utils/message-channel.js";
import { AGENT_LANE_NESTED } from "../lanes.js";
import { readLatestAssistantReply, waitForAgentRun } from "../run-wait.js";
import { runAgentStep } from "./agent-step.js";
import { resolveAnnounceTarget } from "./sessions-announce-target.js";
import {
  buildAgentToAgentAnnounceContext,
  buildAgentToAgentReplyContext,
  isAnnounceSkip,
  isReplySkip,
} from "./sessions-send-helpers.js";

const log = createSubsystemLogger("agents/sessions-send");

type GatewayCaller = <T = unknown>(opts: CallGatewayOptions) => Promise<T>;

const MAX_INPUT_LENGTH = 32_768;
const DANGEROUS_PATTERNS = [
  /\beval\s*\(/gi,
  /\bexec\s*\(/gi,
  /\bsubprocess\s*\(/gi,
  /\bshell\s*=\s*True\b/gi,
  /\$\(\s*.*\)/g,
  /`[^`]*`/g,
];

function sanitizeInput(input: string): string {
  if (typeof input !== "string") {
    return "";
  }
  let sanitized = input.slice(0, MAX_INPUT_LENGTH);
  sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
  return sanitized;
}

function validateInput(input: string): boolean {
  if (!input || typeof input !== "string") {
    return false;
  }
  if (input.length > MAX_INPUT_LENGTH) {
    return false;
  }
  return true;
}

function sanitizeLLMResponse(response: string): string {
  if (typeof response !== "string") {
    return "";
  }
  const lines = response.split("\n");
  const sanitizedLines = lines.filter((line) => {
    for (const pattern of DANGEROUS_PATTERNS) {
      pattern.lastIndex = 0;
      if (pattern.test(line)) {
        log.warn("Removed dangerous pattern from LLM response line", {
          pattern: pattern.toString(),
          line,
        });
        return false;
      }
    }
    return true;
  });
  return sanitizedLines.join("\n");
}

function logLLMInteraction(
  direction: "input" | "output",
  sessionKey: string,
  content: string,
  extra?: Record<string, unknown>
) {
  log.info("LLM interaction", {
    direction,
    sessionKey,
    contentLength: content?.length ?? 0,
    ...extra,
  });
}

const defaultSessionsSendA2ADeps = {
  callGateway: async <T = unknown>(opts: CallGatewayOptions): Promise<T> => {
    const { callGateway } = await import("../../gateway/call.js");
    return callGateway<T>(opts);
  },
};

let sessionsSendA2ADeps: {
  callGateway: GatewayCaller;
} = defaultSessionsSendA2ADeps;

// POLICY VIOLATION NOTICE: Inter-agent authentication is missing.
// Every agent-to-agent call MUST implement authentication to comply with
// the "Authenticate Agent Interactions" policy. Please implement
// authentication (e.g., signed tokens, mutual TLS, or API keys) for all
// agent-to-agent interactions before deploying this code to production.

export async function runSessionsSendA2AFlow(params: {
  targetSessionKey: string;
  displayKey: string;
  message: string;
  announceTimeoutMs: number;
  maxPingPongTurns: number;
  requesterSessionKey?: string;
  requesterChannel?: GatewayMessageChannel;
  roundOneReply?: string;
  waitRunId?: string;
}) {
  const runContextId = params.waitRunId ?? "unknown";

  if (!validateInput(params.message)) {
    log.warn("sessions_send invalid input message", { runId: runContextId });
    return;
  }
  if (!validateInput(params.targetSessionKey)) {
    log.warn("sessions_send invalid targetSessionKey", { runId: runContextId });
    return;
  }
  if (!validateInput(params.displayKey)) {
    log.warn("sessions_send invalid displayKey", { runId: runContextId });
    return;
  }

  const sanitizedMessage = sanitizeInput(params.message);
  const sanitizedTargetSessionKey = sanitizeInput(params.targetSessionKey);
  const sanitizedDisplayKey = sanitizeInput(params.displayKey);
  const sanitizedRequesterSessionKey = params.requesterSessionKey
    ? sanitizeInput(params.requesterSessionKey)
    : params.requesterSessionKey;

  try {
    let primaryReply = params.roundOneReply;
    let latestReply = params.roundOneReply;
    if (!primaryReply && params.waitRunId) {
      const wait = await waitForAgentRun({
        runId: params.waitRunId,
        timeoutMs: Math.min(params.announceTimeoutMs, 60_000),
        callGateway: sessionsSendA2ADeps.callGateway,
      });
      if (wait.status === "ok") {
        primaryReply = await readLatestAssistantReply({
          sessionKey: sanitizedTargetSessionKey,
        });
        if (primaryReply) {
          primaryReply = sanitizeLLMResponse(primaryReply);
          logLLMInteraction("output", sanitizedTargetSessionKey, primaryReply, {
            runId: runContextId,
            stage: "roundOneReply",
          });
        }
        latestReply = primaryReply;
      }
    }
    if (!latestReply) {
      return;
    }

    const announceTarget = await resolveAnnounceTarget({
      sessionKey: sanitizedTargetSessionKey,
      displayKey: sanitizedDisplayKey,
    });
    const targetChannel = announceTarget?.channel ?? "unknown";

    if (
      params.maxPingPongTurns > 0 &&
      sanitizedRequesterSessionKey &&
      sanitizedRequesterSessionKey !== sanitizedTargetSessionKey
    ) {
      let currentSessionKey = sanitizedRequesterSessionKey;
      let nextSessionKey = sanitizedTargetSessionKey;
      let incomingMessage = latestReply;
      for (let turn = 1; turn <= params.maxPingPongTurns; turn += 1) {
        const currentRole =
          currentSessionKey === sanitizedRequesterSessionKey ? "requester" : "target";
        const replyPrompt = buildAgentToAgentReplyContext({
          requesterSessionKey: sanitizedRequesterSessionKey,
          requesterChannel: params.requesterChannel,
          targetSessionKey: sanitizedDisplayKey,
          targetChannel,
          currentRole,
          turn,
          maxTurns: params.maxPingPongTurns,
        });

        const sanitizedIncoming = sanitizeInput(incomingMessage);
        logLLMInteraction("input", currentSessionKey, sanitizedIncoming, {
          runId: runContextId,
          stage: "pingPong",
          turn,
        });

        const replyText = await runAgentStep({
          sessionKey: currentSessionKey,
          message: sanitizedIncoming,
          extraSystemPrompt: replyPrompt,
          timeoutMs: params.announceTimeoutMs,
          lane: AGENT_LANE_NESTED,
          sourceSessionKey: nextSessionKey,
          sourceChannel:
            nextSessionKey === sanitizedRequesterSessionKey
              ? params.requesterChannel
              : targetChannel,
          sourceTool: "sessions_send",
        });

        if (!replyText || isReplySkip(replyText)) {
          break;
        }

        const sanitizedReplyText = sanitizeLLMResponse(replyText);
        logLLMInteraction("output", currentSessionKey, sanitizedReplyText, {
          runId: runContextId,
          stage: "pingPong",
          turn,
        });

        latestReply = sanitizedReplyText;
        incomingMessage = sanitizedReplyText;
        const swap = currentSessionKey;
        currentSessionKey = nextSessionKey;
        nextSessionKey = swap;
      }
    }

    const announcePrompt = buildAgentToAgentAnnounceContext({
      requesterSessionKey: sanitizedRequesterSessionKey,
      requesterChannel: params.requesterChannel,
      targetSessionKey: sanitizedDisplayKey,
      targetChannel,
      originalMessage: sanitizedMessage,
      roundOneReply: primaryReply,
      latestReply,
    });

    logLLMInteraction("input", sanitizedTargetSessionKey, "Agent-to-agent announce step.", {
      runId: runContextId,
      stage: "announce",
    });

    const announceReply = await runAgentStep({
      sessionKey: sanitizedTargetSessionKey,
      message: "Agent-to-agent announce step.",
      extraSystemPrompt: announcePrompt,
      timeoutMs: params.announceTimeoutMs,
      lane: AGENT_LANE_NESTED,
      sourceSessionKey: sanitizedRequesterSessionKey,
      sourceChannel: params.requesterChannel,
      sourceTool: "sessions_send",
    });

    if (announceReply) {
      const sanitizedAnnounceReply = sanitizeLLMResponse(announceReply);
      logLLMInteraction("output", sanitizedTargetSessionKey, sanitizedAnnounceReply, {
        runId: runContextId,
        stage: "announce",
      });

      if (
        announceTarget &&
        sanitizedAnnounceReply.trim() &&
        !isAnnounceSkip(sanitizedAnnounceReply)
      ) {
        try {
          await sessionsSendA2ADeps.callGateway({
            method: "send",
            params: {
              to: announceTarget.to,
              message: sanitizedAnnounceReply.trim(),
              channel: announceTarget.channel,
              accountId: announceTarget.accountId,
              threadId: announceTarget.threadId,
              idempotencyKey: crypto.randomUUID(),
            },
            timeoutMs: 10_000,
          });
        } catch (err) {
          log.warn("sessions_send announce delivery failed", {
            runId: runContextId,
            channel: announceTarget.channel,
            to: announceTarget.to,
            error: formatErrorMessage(err),
          });
        }
      }
    }
  } catch (err) {
    log.warn("sessions_send announce flow failed", {
      runId: runContextId,
      error: formatErrorMessage(err),
    });
  }
}

export const __testing = {
  setDepsForTest(overrides?: Partial<{ callGateway: GatewayCaller }>) {
    sessionsSendA2ADeps = overrides
      ? {
          ...defaultSessionsSendA2ADeps,
          ...overrides,
        }
      : defaultSessionsSendA2ADeps;
  },
};