import { randomUUID } from "node:crypto";
import { loadConfig } from "../config/config.js";
import { assertExplicitGatewayAuthModeWhenBothConfigured } from "../gateway/auth-mode-policy.js";
import { resolveGatewayInteractiveSurfaceAuth } from "../gateway/auth-surface-resolution.js";
import {
  buildGatewayConnectionDetails,
  ensureExplicitGatewayAuth,
  resolveExplicitGatewayAuth,
} from "../gateway/call.js";
import { GatewayClient } from "../gateway/client.js";
import { isLoopbackHost } from "../gateway/net.js";
import {
  GATEWAY_CLIENT_CAPS,
  GATEWAY_CLIENT_MODES,
  GATEWAY_CLIENT_NAMES,
} from "../gateway/protocol/client-info.js";
import {
  type HelloOk,
  PROTOCOL_VERSION,
  type SessionsListParams,
  type SessionsPatchResult,
  type SessionsPatchParams,
} from "../gateway/protocol/index.js";
import { formatErrorMessage } from "../infra/errors.js";
import { VERSION } from "../version.js";
import type { ResponseUsageMode, SessionInfo, SessionScope } from "./tui-types.js";

export type GatewayConnectionOptions = {
  url?: string;
  token?: string;
  password?: string;
};

export type ChatSendOptions = {
  sessionKey: string;
  message: string;
  thinking?: string;
  deliver?: boolean;
  timeoutMs?: number;
  runId?: string;
};

export type GatewayEvent = {
  event: string;
  payload?: unknown;
  seq?: number;
};

type ResolvedGatewayConnection = {
  url: string;
  token?: string;
  password?: string;
  allowInsecureLocalOperatorUi?: boolean;
};

function throwGatewayAuthResolutionError(reason: string): never {
  throw new Error(
    [
      reason,
      "Fix: set OPENCLAW_GATEWAY_TOKEN/OPENCLAW_GATEWAY_PASSWORD, pass --token/--password,",
      "or resolve the configured secret provider for this credential.",
    ].join("\n"),
  );
}

// Dangerous dynamic code execution patterns to detect and remove from LLM responses
const DANGEROUS_CODE_PATTERNS = [
  /^\s*eval\s*\(.*\)\s*;?\s*$/gm,
  /^\s*exec\s*\(.*\)\s*;?\s*$/gm,
  /^\s*subprocess\s*\(.*shell\s*=\s*True.*\)\s*;?\s*$/gm,
  /^\s*new\s+Function\s*\(.*\)\s*;?\s*$/gm,
  /^\s*setTimeout\s*\(\s*["'`].*["'`]\s*[,)]/gm,
  /^\s*setInterval\s*\(\s*["'`].*["'`]\s*[,)]/gm,
  /^\s*execSync\s*\(.*\)\s*;?\s*$/gm,
  /^\s*spawnSync\s*\(.*shell\s*:\s*true.*\)\s*;?\s*$/gm,
  /^\s*child_process\s*\.\s*(exec|execSync|spawn|spawnSync)\s*\(.*\)\s*;?\s*$/gm,
  /^\s*os\s*\.\s*(system|popen)\s*\(.*\)\s*;?\s*$/gm,
  /^\s*__import__\s*\(\s*['"]os['"]\s*\)\s*\.\s*(system|popen)\s*\(.*\)\s*;?\s*$/gm,
];

// Input sanitization: strip null bytes, control characters, and excessively long inputs
function sanitizeLlmInput(input: string, maxLength = 100000): string {
  if (typeof input !== "string") {
    return "";
  }
  // Remove null bytes
  let sanitized = input.replace(/\0/g, "");
  // Remove non-printable control characters except newline, carriage return, tab
  sanitized = sanitized.replace(/[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
  // Truncate to max length
  if (sanitized.length > maxLength) {
    sanitized = sanitized.slice(0, maxLength);
  }
  return sanitized;
}

// Validate that the input is non-empty and within acceptable bounds
function validateLlmInput(message: string, thinking?: string): void {
  if (!message || message.trim().length === 0) {
    throw new Error("LLM input validation failed: message must not be empty.");
  }
  if (message.length > 100000) {
    throw new Error("LLM input validation failed: message exceeds maximum allowed length.");
  }
  if (thinking && thinking.length > 100000) {
    throw new Error("LLM input validation failed: thinking exceeds maximum allowed length.");
  }
}

// Sanitize LLM response: remove lines containing dangerous dynamic code execution primitives
function sanitizeLlmResponse(response: unknown): unknown {
  if (typeof response === "string") {
    return removeDangerousCodeLines(response);
  }
  if (response !== null && typeof response === "object") {
    return sanitizeObjectResponse(response as Record<string, unknown>);
  }
  return response;
}

function removeDangerousCodeLines(text: string): string {
  const lines = text.split("\n");
  const safeLines = lines.filter((line) => {
    for (const pattern of DANGEROUS_CODE_PATTERNS) {
      pattern.lastIndex = 0;
      if (pattern.test(line)) {
        logLlmInteraction("llm_response_sanitized", {
          removedLine: "[REDACTED]",
          reason: "dangerous code execution primitive detected",
        });
        return false;
      }
    }
    return true;
  });
  return safeLines.join("\n");
}

function sanitizeObjectResponse(obj: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj)) {
    if (typeof value === "string") {
      result[key] = removeDangerousCodeLines(value);
    } else if (value !== null && typeof value === "object" && !Array.isArray(value)) {
      result[key] = sanitizeObjectResponse(value as Record<string, unknown>);
    } else if (Array.isArray(value)) {
      result[key] = value.map((item) =>
        typeof item === "string"
          ? removeDangerousCodeLines(item)
          : item !== null && typeof item === "object"
            ? sanitizeObjectResponse(item as Record<string, unknown>)
            : item,
      );
    } else {
      result[key] = value;
    }
  }
  return result;
}

// Centralized LLM interaction logger
function logLlmInteraction(event: string, details: Record<string, unknown>): void {
  const entry = {
    timestamp: new Date().toISOString(),
    event,
    ...details,
  };
  // Write to stderr to avoid polluting stdout; replace with a proper logger if available
  process.stderr.write(JSON.stringify(entry) + "\n");
}

// Validate URL to prevent SSRF
function validateGatewayUrl(url: string): void {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`Invalid gateway URL: ${url}`);
  }
  const allowedProtocols = ["http:", "https:", "ws:", "wss:"];
  if (!allowedProtocols.includes(parsed.protocol)) {
    throw new Error(`Disallowed gateway URL protocol: ${parsed.protocol}`);
  }
  // Block metadata endpoints commonly used in SSRF attacks
  const blockedHosts = ["169.254.169.254", "metadata.google.internal"];
  if (blockedHosts.includes(parsed.hostname)) {
    throw new Error(`Blocked gateway URL host: ${parsed.hostname}`);
  }
}

export type GatewaySessionList = {
  ts: number;
  path: string;
  count: number;
  defaults?: {
    model?: string | null;
    modelProvider?: string | null;
    contextTokens?: number | null;
  };
  sessions: Array<
    Pick<
      SessionInfo,
      | "thinkingLevel"
      | "fastMode"
      | "verboseLevel"
      | "reasoningLevel"
      | "model"
      | "contextTokens"
      | "inputTokens"
      | "outputTokens"
      | "totalTokens"
      | "modelProvider"
      | "displayName"
    > & {
      key: string;
      sessionId?: string;
      updatedAt?: number | null;
      fastMode?: boolean;
      sendPolicy?: string;
      responseUsage?: ResponseUsageMode;
      label?: string;
      provider?: string;
      groupChannel?: string;
      space?: string;
      subject?: string;
      chatType?: string;
      lastProvider?: string;
      lastTo?: string;
      lastAccountId?: string;
      derivedTitle?: string;
      lastMessagePreview?: string;
    }
  >;
};

export type GatewayAgentsList = {
  defaultId: string;
  mainKey: string;
  scope: SessionScope;
  agents: Array<{
    id: string;
    name?: string;
  }>;
};

export type GatewayModelChoice = {
  id: string;
  name: string;
  provider: string;
  contextWindow?: number;
  reasoning?: boolean;
};

export class GatewayChatClient {
  private client: GatewayClient;
  private readyPromise: Promise<void>;
  private resolveReady?: () => void;
  readonly connection: { url: string; token?: string; password?: string };
  hello?: HelloOk;

  onEvent?: (evt: GatewayEvent) => void;
  onConnected?: () => void;
  onDisconnected?: (reason: string) => void;
  onGap?: (info: { expected: number; received: number }) => void;

  constructor(connection: ResolvedGatewayConnection) {
    this.connection = connection;

    // Validate the gateway URL to prevent SSRF
    validateGatewayUrl(connection.url);

    this.readyPromise = new Promise((resolve) => {
      this.resolveReady = resolve;
    });

    this.client = new GatewayClient({
      url: connection.url,
      token: connection.token,
      password: connection.password,
      clientName: GATEWAY_CLIENT_NAMES.TUI,
      clientDisplayName: "openclaw-tui",
      clientVersion: VERSION,
      platform: process.platform,
      mode: GATEWAY_CLIENT_MODES.UI,
      deviceIdentity: connection.allowInsecureLocalOperatorUi ? null : undefined,
      caps: [GATEWAY_CLIENT_CAPS.TOOL_EVENTS],
      instanceId: randomUUID(),
      minProtocol: PROTOCOL_VERSION,
      maxProtocol: PROTOCOL_VERSION,
      onHelloOk: (hello) => {
        this.hello = hello;
        this.resolveReady?.();
        this.onConnected?.();
      },
      onEvent: (evt) => {
        const sanitizedPayload = sanitizeLlmResponse(evt.payload);
        logLlmInteraction("llm_event_received", {
          event: evt.event,
          seq: evt.seq,
        });
        this.onEvent?.({
          event: evt.event,
          payload: sanitizedPayload,
          seq: evt.seq,
        });
      },
      onClose: (_code, reason) => {
        // Reset so waitForReady() blocks again until the next successful reconnect.
        this.readyPromise = new Promise((resolve) => {
          this.resolveReady = resolve;
        });
        this.onDisconnected?.(reason);
      },
      onGap: (info) => {
        this.onGap?.(info);
      },
    });
  }

  static async connect(opts: GatewayConnectionOptions): Promise<GatewayChatClient> {
    const connection = await resolveGatewayConnection(opts);
    return new GatewayChatClient(connection);
  }

  start() {
    this.client.start();
  }

  stop() {
    this.client.stop();
  }

  async waitForReady() {
    await this.readyPromise;
  }

  async sendChat(opts: ChatSendOptions): Promise<{ runId: string }> {
    // Sanitize and validate inputs before sending to LLM
    const sanitizedMessage = sanitizeLlmInput(opts.message);
    const sanitizedThinking = opts.thinking !== undefined ? sanitizeLlmInput(opts.thinking) : undefined;
    validateLlmInput(sanitizedMessage, sanitizedThinking);

    const runId = opts.runId ?? randomUUID();

    logLlmInteraction("llm_chat_send", {
      sessionKey: opts.sessionKey,
      messageLength: sanitizedMessage.length,
      hasThinking: sanitizedThinking !== undefined,
      deliver: opts.deliver,
      timeoutMs: opts.timeoutMs,
      runId,
    });

    await this.client.request("chat.send", {
      sessionKey: opts.sessionKey,
      message: sanitizedMessage,
      thinking: sanitizedThinking,
      deliver: opts.deliver,
      timeoutMs: opts.timeoutMs,
      idempotencyKey: runId,
    });
    return { runId };
  }

  async abortChat(opts: { sessionKey: string; runId: string }) {
    logLlmInteraction("llm_chat_abort", {
      sessionKey: opts.sessionKey,
      runId: opts.runId,
    });
    return await this.client.request<{ ok: boolean; aborted: boolean }>("chat.abort", {
      sessionKey: opts.sessionKey,
      runId: opts.runId,
    });
  }

  async loadHistory(opts: { sessionKey: string; limit?: number }) {
    logLlmInteraction("llm_load_history", {
      sessionKey: opts.sessionKey,
      limit: opts.limit,
    });
    const response = await this.client.request("chat.history", {
      sessionKey: opts.sessionKey,
      limit: opts.limit,
    });
    return sanitizeLlmResponse(response);
  }

  async listSessions(opts?: SessionsListParams) {
    logLlmInteraction("llm_list_sessions", {
      limit: opts?.limit,
      activeMinutes: opts?.activeMinutes,
    });
    const response = await this.client.request<GatewaySessionList>("sessions.list", {
      limit: opts?.limit,
      activeMinutes: opts?.activeMinutes,
      includeGlobal: opts?.includeGlobal,
      includeUnknown: opts?.includeUnknown,
      includeDerivedTitles: opts?.includeDerivedTitles,
      includeLastMessage: opts?.includeLastMessage,
      agentId: opts?.agentId,
    });
    return sanitizeLlmResponse(response) as GatewaySessionList;
  }

  async listAgents() {
    logLlmInteraction("llm_list_agents", {});
    const response = await this.client.request<GatewayAgentsList>("agents.list", {});
    return sanitizeLlmResponse(response) as GatewayAgentsList;
  }

  async patchSession(opts: SessionsPatchParams): Promise<SessionsPatchResult> {
    logLlmInteraction("llm_patch_session", {
      sessionKey: (opts as Record<string, unknown>).key,
    });
    const response = await this.client.request<SessionsPatchResult>("sessions.patch", opts);
    return sanitizeLlmResponse(response) as SessionsPatchResult;
  }

  async resetSession(key: string, reason?: "new" | "reset") {
    logLlmInteraction("llm_reset_session", {
      sessionKey: key,
      reason,
    });
    return await this.client.request("sessions.reset", {
      key,
      ...(reason ? { reason } : {}),
    });
  }

  async getGatewayStatus() {
    logLlmInteraction("llm_get_gateway_status", {});
    return await this.client.request("status");
  }

  async listModels(): Promise<GatewayModelChoice[]> {
    logLlmInteraction("llm_list_models", {});
    const res = await this.client.request("models.list");
    return Array.isArray(res?.models) ? res.models : [];
  }
}

export async function resolveGatewayConnection(
  opts: GatewayConnectionOptions,
): Promise<ResolvedGatewayConnection> {
  const config = loadConfig();
  const env = process.env;
  const gatewayAuthMode = config.gateway?.auth?.mode;
  const isRemoteMode = config.gateway?.mode === "remote";

  const urlOverride =
    typeof opts.url === "string" && opts.url.trim().length > 0 ? opts.url.trim() : undefined;

  // Validate the URL override to prevent SSRF
  if (urlOverride) {
    validateGatewayUrl(urlOverride);
  }

  const explicitAuth = resolveExplicitGatewayAuth({ token: opts.token, password: opts.password });
  ensureExplicitGatewayAuth({
    urlOverride,
    urlOverrideSource: "cli",
    explicitAuth,
    errorHint: "Fix: pass --token or --password when using --url.",
  });
  const url = buildGatewayConnectionDetails({
    config,
    ...(urlOverride ? { url: urlOverride } : {}),
  }).url;

  // Validate the resolved URL to prevent SSRF
  validateGatewayUrl(url);

  const allowInsecureLocalOperatorUi = (() => {
    if (config.gateway?.controlUi?.allowInsecureAuth !== true) {
      return false;
    }
    try {
      return isLoopbackHost(new URL(url).hostname);
    } catch {
      return false;
    }
  })();

  if (urlOverride) {
    return {
      url,
      token: explicitAuth.token,
      password: explicitAuth.password,
      allowInsecureLocalOperatorUi,
    };
  }

  if (isRemoteMode) {
    const resolved = await resolveGatewayInteractiveSurfaceAuth({
      config,
      env,
      explicitAuth,
      surface: "remote",
    });
    if (resolved.failureReason) {
      throwGatewayAuthResolutionError(resolved.failureReason);
    }
    return {
      url,
      token: resolved.token,
      password: resolved.password,
      allowInsecureLocalOperatorUi: false,
    };
  }

  if (gatewayAuthMode === "none" || gatewayAuthMode === "trusted-proxy") {
    const resolved = await resolveGatewayInteractiveSurfaceAuth({
      config,
      env,
      explicitAuth,
      surface: "local",
    });
    return {
      url,
      token: resolved.token,
      password: resolved.password,
      allowInsecureLocalOperatorUi,
    };
  }

  try {
    assertExplicitGatewayAuthModeWhenBothConfigured(config);
  } catch (err) {
    throwGatewayAuthResolutionError(formatErrorMessage(err));
  }

  const resolved = await resolveGatewayInteractiveSurfaceAuth({
    config,
    env,
    explicitAuth,
    surface: "local",
  });
  if (resolved.failureReason) {
    throwGatewayAuthResolutionError(resolved.failureReason);
  }
  return {
    url,
    token: resolved.token,
    password: resolved.password,
    allowInsecureLocalOperatorUi,
  };
}