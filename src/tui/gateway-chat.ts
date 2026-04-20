import { randomUUID } from "node:crypto";
import { createHash } from "node:crypto";
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

// --- LLM Interaction Logger ---
function logLlmInteraction(direction: "request" | "response", data: Record<string, unknown>): void {
  const entry = {
    timestamp: new Date().toISOString(),
    direction,
    hash: createHash("sha256").update(JSON.stringify(data)).digest("hex"),
    ...data,
  };
  // Write to stderr to avoid polluting stdout; replace with a proper logger as needed.
  process.stderr.write("[LLM-LOG] " + JSON.stringify(entry) + "\n");
}

// --- Dynamic code execution pattern detection ---
const DANGEROUS_PATTERNS = [
  /\beval\s*\(/gi,
  /\bexec\s*\(/gi,
  /\bnew\s+Function\s*\(/gi,
  /\bsetTimeout\s*\(\s*["'`]/gi,
  /\bsetInterval\s*\(\s*["'`]/gi,
  /\bsubprocess\s*\.\s*\w+\s*\(.*shell\s*=\s*True/gi,
  /\bos\.system\s*\(/gi,
  /\bos\.popen\s*\(/gi,
  /\bchild_process\b/gi,
  /\bspawnSync\s*\(/gi,
  /\bexecSync\s*\(/gi,
  /\bexecFileSync\s*\(/gi,
  /\brequire\s*\(\s*["'`]child_process["'`]\s*\)/gi,
];

function sanitizeLlmResponse(text: string): string {
  const lines = text.split("\n");
  const sanitized = lines.filter((line) => {
    for (const pattern of DANGEROUS_PATTERNS) {
      pattern.lastIndex = 0;
      if (pattern.test(line)) {
        process.stderr.write(
          "[LLM-SANITIZE] Removed dangerous line from LLM response: " +
            JSON.stringify(line) +
            "\n",
        );
        return false;
      }
    }
    return true;
  });
  return sanitized.join("\n");
}

// --- Input sanitization for LLM messages ---
const MAX_MESSAGE_LENGTH = 32_768;
const PROMPT_INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?(previous|prior|above)\s+instructions?/gi,
  /disregard\s+(all\s+)?(previous|prior|above)\s+instructions?/gi,
  /forget\s+(all\s+)?(previous|prior|above)\s+instructions?/gi,
  /you\s+are\s+now\s+/gi,
  /act\s+as\s+(?:a\s+)?(?:different|new|another)\s+/gi,
  /<\s*script[^>]*>/gi,
  /javascript\s*:/gi,
  /data\s*:\s*text\/html/gi,
];

function sanitizeLlmInput(input: string): string {
  if (typeof input !== "string") {
    return "";
  }
  // Truncate to max length
  let sanitized = input.slice(0, MAX_MESSAGE_LENGTH);
  // Remove null bytes and other control characters (except common whitespace)
  sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
  // Warn and strip prompt injection attempts
  for (const pattern of PROMPT_INJECTION_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(sanitized)) {
      process.stderr.write(
        "[LLM-SANITIZE] Potential prompt injection detected and stripped.\n",
      );
      sanitized = sanitized.replace(pattern, "[REDACTED]");
    }
  }
  return sanitized;
}

function validateSessionKey(key: string): string {
  if (typeof key !== "string" || key.trim().length === 0) {
    throw new Error("Invalid sessionKey: must be a non-empty string.");
  }
  // Allow only alphanumeric, dash, underscore, dot, colon
  if (!/^[\w\-.:]+$/.test(key)) {
    throw new Error("Invalid sessionKey: contains disallowed characters.");
  }
  return key.trim();
}

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
        // Sanitize and log incoming LLM events
        const rawPayload = evt.payload;
        let sanitizedPayload = rawPayload;
        if (typeof rawPayload === "string") {
          sanitizedPayload = sanitizeLlmResponse(rawPayload);
        } else if (rawPayload && typeof rawPayload === "object") {
          try {
            const serialized = JSON.stringify(rawPayload);
            const sanitizedSerialized = sanitizeLlmResponse(serialized);
            sanitizedPayload = JSON.parse(sanitizedSerialized) as unknown;
          } catch {
            sanitizedPayload = rawPayload;
          }
        }
        logLlmInteraction("response", {
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
    const runId = opts.runId ?? randomUUID();
    const sanitizedMessage = sanitizeLlmInput(opts.message);
    const sanitizedThinking =
      opts.thinking !== undefined ? sanitizeLlmInput(opts.thinking) : undefined;
    const sanitizedSessionKey = validateSessionKey(opts.sessionKey);

    logLlmInteraction("request", {
      method: "chat.send",
      sessionKey: sanitizedSessionKey,
      messageLength: sanitizedMessage.length,
      hasThinking: sanitizedThinking !== undefined,
      deliver: opts.deliver,
      timeoutMs: opts.timeoutMs,
      runId,
    });

    await this.client.request("chat.send", {
      sessionKey: sanitizedSessionKey,
      message: sanitizedMessage,
      thinking: sanitizedThinking,
      deliver: opts.deliver,
      timeoutMs: opts.timeoutMs,
      idempotencyKey: runId,
    });
    return { runId };
  }

  async abortChat(opts: { sessionKey: string; runId: string }) {
    const sanitizedSessionKey = validateSessionKey(opts.sessionKey);
    logLlmInteraction("request", {
      method: "chat.abort",
      sessionKey: sanitizedSessionKey,
      runId: opts.runId,
    });
    return await this.client.request<{ ok: boolean; aborted: boolean }>("chat.abort", {
      sessionKey: sanitizedSessionKey,
      runId: opts.runId,
    });
  }

  async loadHistory(opts: { sessionKey: string; limit?: number }) {
    const sanitizedSessionKey = validateSessionKey(opts.sessionKey);
    logLlmInteraction("request", {
      method: "chat.history",
      sessionKey: sanitizedSessionKey,
      limit: opts.limit,
    });
    const result = await this.client.request("chat.history", {
      sessionKey: sanitizedSessionKey,
      limit: opts.limit,
    });
    logLlmInteraction("response", { method: "chat.history" });
    return result;
  }

  async listSessions(opts?: SessionsListParams) {
    logLlmInteraction("request", { method: "sessions.list" });
    return await this.client.request<GatewaySessionList>("sessions.list", {
      limit: opts?.limit,
      activeMinutes: opts?.activeMinutes,
      includeGlobal: opts?.includeGlobal,
      includeUnknown: opts?.includeUnknown,
      includeDerivedTitles: opts?.includeDerivedTitles,
      includeLastMessage: opts?.includeLastMessage,
      agentId: opts?.agentId,
    });
  }

  async listAgents() {
    logLlmInteraction("request", { method: "agents.list" });
    return await this.client.request<GatewayAgentsList>("agents.list", {});
  }

  async patchSession(opts: SessionsPatchParams): Promise<SessionsPatchResult> {
    logLlmInteraction("request", { method: "sessions.patch" });
    return await this.client.request<SessionsPatchResult>("sessions.patch", opts);
  }

  async resetSession(key: string, reason?: "new" | "reset") {
    const sanitizedKey = validateSessionKey(key);
    logLlmInteraction("request", { method: "sessions.reset", key: sanitizedKey, reason });
    return await this.client.request("sessions.reset", {
      key: sanitizedKey,
      ...(reason ? { reason } : {}),
    });
  }

  async getGatewayStatus() {
    logLlmInteraction("request", { method: "status" });
    return await this.client.request("status");
  }

  async listModels(): Promise<GatewayModelChoice[]> {
    logLlmInteraction("request", { method: "models.list" });
    const res = await this.client.request("models.list");
    logLlmInteraction("response", { method: "models.list" });
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

  // SSRF mitigation: validate URL scheme when a URL override is provided
  if (urlOverride) {
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(urlOverride);
    } catch {
      throw new Error("Invalid gateway URL provided.");
    }
    if (parsedUrl.protocol !== "https:" && parsedUrl.protocol !== "http:") {
      throw new Error("Gateway URL must use http or https protocol.");
    }
    // Disallow private/metadata IP ranges for remote URLs to prevent SSRF
    const hostname = parsedUrl.hostname;
    const metadataHosts = ["169.254.169.254", "metadata.google.internal"];
    if (metadataHosts.includes(hostname)) {
      throw new Error("Gateway URL points to a disallowed host.");
    }
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