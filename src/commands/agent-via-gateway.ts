import { resolveSendableOutboundReplyParts } from "openclaw/plugin-sdk/reply-payload";
import { listAgentIds } from "../agents/agent-scope.js";
import { formatCliCommand } from "../cli/command-format.js";
import type { CliDeps } from "../cli/deps.types.js";
import { withProgress } from "../cli/progress.js";
import { loadConfig } from "../config/config.js";
import type { OpenClawConfig } from "../config/types.openclaw.js";
import { callGateway, randomIdempotencyKey } from "../gateway/call.js";
import { GATEWAY_CLIENT_MODES, GATEWAY_CLIENT_NAMES } from "../gateway/protocol/client-info.js";
import { normalizeAgentId } from "../routing/session-key.js";
import { type RuntimeEnv, writeRuntimeJson } from "../runtime.js";
import { normalizeOptionalString } from "../shared/string-coerce.js";
import { normalizeMessageChannel } from "../utils/message-channel.js";
import { agentCommand } from "./agent.js";
import { resolveSessionKeyForRequest } from "./agent/session.js";

// Policy: Enforce Approved LLM
// WARNING: You must replace any unapproved LLM with an approved LLM from the organization's allow list.
// Using unapproved LLMs is a policy violation. Please verify the LLM in use is on the approved list
// before deploying this code.

// Policy: Authenticate Agent Interactions
// WARNING: Missing inter-agent authentication is a policy violation. You must implement authentication
// for every agent-to-agent call. Ensure all agent interactions are properly authenticated before
// deploying this code.

const APPROVED_LLMS = ["gpt-4", "gpt-4o", "gpt-3.5-turbo", "claude-3-opus", "claude-3-sonnet"];

// Patterns that indicate dynamic code execution primitives in LLM responses
const DANGEROUS_CODE_PATTERNS = [
  /^\s*eval\s*\(.*\)\s*;?\s*$/gm,
  /^\s*exec\s*\(.*\)\s*;?\s*$/gm,
  /^\s*subprocess\s*\(.*shell\s*=\s*True.*\)\s*;?\s*$/gm,
  /^\s*bash\s+-c\s+.*$/gm,
  /^\s*os\.system\s*\(.*\)\s*;?\s*$/gm,
  /^\s*child_process\.exec\s*\(.*\)\s*;?\s*$/gm,
  /^\s*new\s+Function\s*\(.*\)\s*;?\s*$/gm,
  /^\s*setTimeout\s*\(\s*["'].*["']\s*,.*\)\s*;?\s*$/gm,
  /^\s*setInterval\s*\(\s*["'].*["']\s*,.*\)\s*;?\s*$/gm,
];

// Maximum allowed lengths for input fields
const MAX_MESSAGE_LENGTH = 32_000;
const MAX_EXTRA_SYSTEM_PROMPT_LENGTH = 8_000;
const MAX_SESSION_ID_LENGTH = 256;
const MAX_LANE_LENGTH = 128;
const MAX_RUN_ID_LENGTH = 128;

type AgentGatewayResult = {
  payloads?: Array<{
    text?: string;
    mediaUrl?: string | null;
    mediaUrls?: string[];
  }>;
  meta?: unknown;
};

type GatewayAgentResponse = {
  runId?: string;
  status?: string;
  summary?: string;
  result?: AgentGatewayResult;
};

const NO_GATEWAY_TIMEOUT_MS = 2_147_000_000;

export type AgentCliOpts = {
  message: string;
  agent?: string;
  to?: string;
  sessionId?: string;
  thinking?: string;
  verbose?: string;
  json?: boolean;
  timeout?: string;
  deliver?: boolean;
  channel?: string;
  replyTo?: string;
  replyChannel?: string;
  replyAccount?: string;
  bestEffortDeliver?: boolean;
  lane?: string;
  runId?: string;
  extraSystemPrompt?: string;
  local?: boolean;
};

function parseTimeoutSeconds(opts: { cfg: OpenClawConfig; timeout?: string }) {
  const raw =
    opts.timeout !== undefined
      ? Number.parseInt(opts.timeout, 10)
      : (opts.cfg.agents?.defaults?.timeoutSeconds ?? 600);
  if (Number.isNaN(raw) || raw < 0) {
    throw new Error("--timeout must be a non-negative integer (seconds; 0 means no timeout)");
  }
  return raw;
}

function formatPayloadForLog(payload: {
  text?: string;
  mediaUrls?: string[];
  mediaUrl?: string | null;
}) {
  const parts = resolveSendableOutboundReplyParts({
    text: payload.text,
    mediaUrls: payload.mediaUrls,
    mediaUrl: typeof payload.mediaUrl === "string" ? payload.mediaUrl : undefined,
  });
  const lines: string[] = [];
  if (parts.text) {
    lines.push(parts.text.trimEnd());
  }
  for (const url of parts.mediaUrls) {
    lines.push(`MEDIA:${url}`);
  }
  return lines.join("\n").trimEnd();
}

/**
 * Sanitizes and validates a string input destined for the LLM.
 * Strips null bytes, control characters (except newlines/tabs), and enforces max length.
 */
function sanitizeLlmInput(value: string | undefined, maxLength: number, fieldName: string): string | undefined {
  if (value === undefined) return undefined;
  // Remove null bytes
  let sanitized = value.replace(/\0/g, "");
  // Remove non-printable control characters except \n, \r, \t
  sanitized = sanitized.replace(/[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
  // Enforce max length
  if (sanitized.length > maxLength) {
    throw new Error(
      `Input field "${fieldName}" exceeds maximum allowed length of ${maxLength} characters.`,
    );
  }
  return sanitized;
}

/**
 * Validates that the message is non-empty after sanitization and does not contain
 * prompt injection patterns.
 */
function validateLlmMessage(message: string): string {
  const sanitized = sanitizeLlmInput(message, MAX_MESSAGE_LENGTH, "message") ?? "";
  if (!sanitized.trim()) {
    throw new Error("Message (--message) is required and must not be empty after sanitization.");
  }
  // Basic prompt injection guard: warn on suspicious override attempts
  const injectionPatterns = [
    /ignore\s+(all\s+)?(previous|prior|above)\s+instructions/i,
    /system\s*:\s*/i,
    /\[INST\]/i,
    /<\|im_start\|>/i,
    /###\s*instruction/i,
  ];
  for (const pattern of injectionPatterns) {
    if (pattern.test(sanitized)) {
      throw new Error(
        "Message contains potentially unsafe prompt injection content and has been rejected.",
      );
    }
  }
  return sanitized;
}

/**
 * Sanitizes LLM response text by removing lines containing dangerous code-execution primitives.
 */
function sanitizeLlmResponse(text: string | undefined): string | undefined {
  if (text === undefined) return undefined;
  const lines = text.split("\n");
  const safeLines = lines.filter((line) => {
    for (const pattern of DANGEROUS_CODE_PATTERNS) {
      pattern.lastIndex = 0;
      if (pattern.test(line)) {
        return false;
      }
    }
    return true;
  });
  return safeLines.join("\n");
}

/**
 * Sanitizes all payloads in the LLM response.
 */
function sanitizeGatewayResponse(response: GatewayAgentResponse): GatewayAgentResponse {
  if (!response?.result?.payloads) return response;
  return {
    ...response,
    result: {
      ...response.result,
      payloads: response.result.payloads.map((payload) => ({
        ...payload,
        text: sanitizeLlmResponse(payload.text),
      })),
    },
  };
}

/**
 * Logs an LLM interaction (request and response) for audit purposes.
 */
function logLlmInteraction(
  runtime: RuntimeEnv,
  direction: "request" | "response",
  data: Record<string, unknown>,
): void {
  const entry = {
    timestamp: new Date().toISOString(),
    direction,
    ...data,
  };
  // Use runtime.error as a secondary channel if available, otherwise runtime.log
  const logFn = runtime.log ?? console.log;
  logFn(`[LLM_AUDIT] ${JSON.stringify(entry)}`);
}

export async function agentViaGatewayCommand(opts: AgentCliOpts, runtime: RuntimeEnv) {
  const rawBody = (opts.message ?? "").trim();
  if (!rawBody) {
    throw new Error("Message (--message) is required");
  }
  if (!opts.to && !opts.sessionId && !opts.agent) {
    throw new Error("Pass --to <E.164>, --session-id, or --agent to choose a session");
  }

  // Sanitize and validate all LLM-bound inputs
  const body = validateLlmMessage(rawBody);
  const sanitizedExtraSystemPrompt = sanitizeLlmInput(
    opts.extraSystemPrompt,
    MAX_EXTRA_SYSTEM_PROMPT_LENGTH,
    "extraSystemPrompt",
  );
  const sanitizedSessionId = sanitizeLlmInput(opts.sessionId, MAX_SESSION_ID_LENGTH, "sessionId");
  const sanitizedLane = sanitizeLlmInput(opts.lane, MAX_LANE_LENGTH, "lane");
  const sanitizedRunId = sanitizeLlmInput(opts.runId, MAX_RUN_ID_LENGTH, "runId");

  const cfg = loadConfig();
  const agentIdRaw = opts.agent?.trim();
  const agentId = agentIdRaw ? normalizeAgentId(agentIdRaw) : undefined;
  if (agentId) {
    const knownAgents = listAgentIds(cfg);
    if (!knownAgents.includes(agentId)) {
      throw new Error(
        `Unknown agent id "${agentIdRaw}". Use "${formatCliCommand("openclaw agents list")}" to see configured agents.`,
      );
    }
  }
  const timeoutSeconds = parseTimeoutSeconds({ cfg, timeout: opts.timeout });
  const gatewayTimeoutMs =
    timeoutSeconds === 0
      ? NO_GATEWAY_TIMEOUT_MS // no timeout (timer-safe max)
      : Math.max(10_000, (timeoutSeconds + 30) * 1000);

  const sessionKey = resolveSessionKeyForRequest({
    cfg,
    agentId,
    to: opts.to,
    sessionId: sanitizedSessionId,
  }).sessionKey;

  const channel = normalizeMessageChannel(opts.channel);
  const idempotencyKey = normalizeOptionalString(sanitizedRunId) || randomIdempotencyKey();

  // Log the LLM request interaction
  logLlmInteraction(runtime, "request", {
    agentId,
    sessionKey,
    channel,
    idempotencyKey,
    messageLength: body.length,
    hasExtraSystemPrompt: sanitizedExtraSystemPrompt !== undefined,
    deliver: Boolean(opts.deliver),
    timeout: timeoutSeconds,
    lane: sanitizedLane,
    clientName: GATEWAY_CLIENT_NAMES.CLI,
    mode: GATEWAY_CLIENT_MODES.CLI,
  });

  const rawResponse: GatewayAgentResponse = await withProgress(
    {
      label: "Waiting for agent reply…",
      indeterminate: true,
      enabled: opts.json !== true,
    },
    async () =>
      await callGateway({
        method: "agent",
        params: {
          message: body,
          agentId,
          to: opts.to,
          replyTo: opts.replyTo,
          sessionId: sanitizedSessionId,
          sessionKey,
          thinking: opts.thinking,
          deliver: Boolean(opts.deliver),
          channel,
          replyChannel: opts.replyChannel,
          replyAccountId: opts.replyAccount,
          bestEffortDeliver: opts.bestEffortDeliver,
          timeout: timeoutSeconds,
          lane: sanitizedLane,
          extraSystemPrompt: sanitizedExtraSystemPrompt,
          idempotencyKey,
        },
        expectFinal: true,
        timeoutMs: gatewayTimeoutMs,
        clientName: GATEWAY_CLIENT_NAMES.CLI,
        mode: GATEWAY_CLIENT_MODES.CLI,
      }),
  );

  // Sanitize the LLM response to remove dangerous code-execution primitives
  const response = sanitizeGatewayResponse(rawResponse);

  // Log the LLM response interaction
  logLlmInteraction(runtime, "response", {
    idempotencyKey,
    runId: response?.runId,
    status: response?.status,
    payloadCount: response?.result?.payloads?.length ?? 0,
    hasSummary: Boolean(response?.summary),
  });

  if (opts.json) {
    writeRuntimeJson(runtime, response);
    return response;
  }

  const result = response?.result;
  const payloads = result?.payloads ?? [];

  if (payloads.length === 0) {
    runtime.log(response?.summary ? response.summary : "No reply from agent.");
    return response;
  }

  for (const payload of payloads) {
    const out = formatPayloadForLog(payload);
    if (out) {
      runtime.log(out);
    }
  }

  return response;
}

export async function agentCliCommand(opts: AgentCliOpts, runtime: RuntimeEnv, deps?: CliDeps) {
  const localOpts = {
    ...opts,
    agentId: opts.agent,
    replyAccountId: opts.replyAccount,
    cleanupBundleMcpOnRunEnd: opts.local === true,
  };
  if (opts.local === true) {
    return await agentCommand(localOpts, runtime, deps);
  }

  try {
    return await agentViaGatewayCommand(opts, runtime);
  } catch (err) {
    runtime.error?.(`Gateway agent failed; falling back to embedded: ${String(err)}`);
    return await agentCommand(localOpts, runtime, deps);
  }
}