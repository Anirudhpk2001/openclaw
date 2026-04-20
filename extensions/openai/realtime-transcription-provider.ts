import { randomUUID } from "node:crypto";
import {
  captureWsEvent,
  createDebugProxyWebSocketAgent,
  resolveDebugProxySettings,
} from "openclaw/plugin-sdk/proxy-capture";
import type {
  RealtimeTranscriptionProviderConfig,
  RealtimeTranscriptionProviderPlugin,
  RealtimeTranscriptionSession,
  RealtimeTranscriptionSessionCreateRequest,
} from "openclaw/plugin-sdk/realtime-transcription";
import { normalizeResolvedSecretInputString } from "openclaw/plugin-sdk/secret-input";
import WebSocket from "ws";
import {
  asFiniteNumber,
  readRealtimeErrorDetail,
  resolveOpenAIProviderConfigRecord,
  trimToUndefined,
} from "./realtime-provider-shared.js";

// Approved LLM models allowlist
const APPROVED_MODELS = [
  "gpt-4o-transcribe",
  "gpt-4o-mini-transcribe",
  "whisper-1",
];

// Dynamic code execution primitives to strip from LLM responses
const DANGEROUS_PATTERNS = [
  /^\s*eval\s*\(.*\)\s*;?\s*$/gm,
  /^\s*exec\s*\(.*\)\s*;?\s*$/gm,
  /^\s*subprocess\s*\(.*shell\s*=\s*True.*\)\s*;?\s*$/gm,
  /^\s*require\s*\(\s*['"`]child_process['"`]\s*\).*$/gm,
  /^\s*import\s+subprocess\s*$/gm,
  /^\s*os\.system\s*\(.*\)\s*;?\s*$/gm,
  /^\s*__import__\s*\(.*\)\s*;?\s*$/gm,
  /\beval\s*\(/g,
  /\bexec\s*\(/g,
  /\bnew\s+Function\s*\(/g,
  /\bsetTimeout\s*\(\s*['"`]/g,
  /\bsetInterval\s*\(\s*['"`]/g,
];

// Maximum agent iterations
const MAX_AGENT_ITERATIONS = 10;

function sanitizeLLMInput(input: string): string {
  if (typeof input !== "string") {
    return "";
  }
  // Remove null bytes
  let sanitized = input.replace(/\0/g, "");
  // Limit length to prevent prompt injection via oversized input
  const MAX_INPUT_LENGTH = 32_000;
  if (sanitized.length > MAX_INPUT_LENGTH) {
    sanitized = sanitized.slice(0, MAX_INPUT_LENGTH);
  }
  // Strip potential prompt injection patterns
  sanitized = sanitized.replace(/\[\s*INST\s*\]/gi, "");
  sanitized = sanitized.replace(/\[\s*\/INST\s*\]/gi, "");
  sanitized = sanitized.replace(/<\|.*?\|>/g, "");
  return sanitized;
}

function sanitizeLLMResponse(response: string): string {
  if (typeof response !== "string") {
    return "";
  }
  let sanitized = response;
  // Remove lines containing dangerous dynamic code execution primitives
  const lines = sanitized.split("\n");
  const safeLines = lines.filter((line) => {
    for (const pattern of DANGEROUS_PATTERNS) {
      pattern.lastIndex = 0;
      if (pattern.test(line)) {
        return false;
      }
    }
    return true;
  });
  sanitized = safeLines.join("\n");
  return sanitized;
}

function validateApprovedModel(model: string): string {
  if (!APPROVED_MODELS.includes(model)) {
    console.warn(
      `[SECURITY] The model "${model}" is not in the approved LLM allowlist. ` +
        `Please replace it with an approved model from the following list: ${APPROVED_MODELS.join(", ")}. ` +
        `Falling back to the default approved model "gpt-4o-transcribe".`,
    );
    return "gpt-4o-transcribe";
  }
  return model;
}

type OpenAIRealtimeTranscriptionProviderConfig = {
  apiKey?: string;
  model?: string;
  silenceDurationMs?: number;
  vadThreshold?: number;
};

type OpenAIRealtimeTranscriptionSessionConfig = RealtimeTranscriptionSessionCreateRequest & {
  apiKey: string;
  model: string;
  silenceDurationMs: number;
  vadThreshold: number;
};

type RealtimeEvent = {
  type: string;
  delta?: string;
  transcript?: string;
  error?: unknown;
};

function normalizeProviderConfig(
  config: RealtimeTranscriptionProviderConfig,
): OpenAIRealtimeTranscriptionProviderConfig {
  const raw = resolveOpenAIProviderConfigRecord(config);
  return {
    apiKey:
      normalizeResolvedSecretInputString({
        value: raw?.apiKey,
        path: "plugins.entries.voice-call.config.streaming.providers.openai.apiKey",
      }) ??
      normalizeResolvedSecretInputString({
        value: raw?.openaiApiKey,
        path: "plugins.entries.voice-call.config.streaming.openaiApiKey",
      }),
    model: trimToUndefined(raw?.model) ?? trimToUndefined(raw?.sttModel),
    silenceDurationMs: asFiniteNumber(raw?.silenceDurationMs),
    vadThreshold: asFiniteNumber(raw?.vadThreshold),
  };
}

class OpenAIRealtimeTranscriptionSession implements RealtimeTranscriptionSession {
  private static readonly MAX_RECONNECT_ATTEMPTS = 5;
  private static readonly RECONNECT_DELAY_MS = 1000;
  private static readonly CONNECT_TIMEOUT_MS = 10_000;

  private ws: WebSocket | null = null;
  private connected = false;
  private closed = false;
  private reconnectAttempts = 0;
  private pendingTranscript = "";
  private readonly flowId = randomUUID();
  private agentIterations = 0;

  constructor(private readonly config: OpenAIRealtimeTranscriptionSessionConfig) {}

  async connect(): Promise<void> {
    this.closed = false;
    this.reconnectAttempts = 0;
    this.agentIterations = 0;
    await this.doConnect();
  }

  sendAudio(audio: Buffer): void {
    if (this.ws?.readyState !== WebSocket.OPEN) {
      return;
    }
    this.sendEvent({
      type: "input_audio_buffer.append",
      audio: audio.toString("base64"),
    });
  }

  close(): void {
    this.closed = true;
    this.connected = false;
    if (this.ws) {
      this.ws.close(1000, "Transcription session closed");
      this.ws = null;
    }
  }

  isConnected(): boolean {
    return this.connected;
  }

  private async doConnect(): Promise<void> {
    if (this.agentIterations >= MAX_AGENT_ITERATIONS) {
      this.config.onError?.(
        new Error(
          `OpenAI realtime transcription session exceeded maximum iterations (${MAX_AGENT_ITERATIONS}). Exiting.`,
        ),
      );
      this.closed = true;
      return;
    }
    this.agentIterations += 1;

    await new Promise<void>((resolve, reject) => {
      const url = "wss://api.openai.com/v1/realtime?intent=transcription";
      const debugProxy = resolveDebugProxySettings();
      const proxyAgent = createDebugProxyWebSocketAgent(debugProxy);
      this.ws = new WebSocket(url, {
        headers: {
          Authorization: `Bearer ${this.config.apiKey}`,
          "OpenAI-Beta": "realtime=v1",
        },
        ...(proxyAgent ? { agent: proxyAgent } : {}),
      });

      const connectTimeout = setTimeout(() => {
        reject(new Error("OpenAI realtime transcription connection timeout"));
      }, OpenAIRealtimeTranscriptionSession.CONNECT_TIMEOUT_MS);

      this.ws.on("open", () => {
        clearTimeout(connectTimeout);
        this.connected = true;
        this.reconnectAttempts = 0;
        captureWsEvent({
          url,
          direction: "local",
          kind: "ws-open",
          flowId: this.flowId,
          meta: {
            provider: "openai",
            capability: "realtime-transcription",
          },
        });
        this.sendEvent({
          type: "transcription_session.update",
          session: {
            input_audio_format: "g711_ulaw",
            input_audio_transcription: {
              model: this.config.model,
            },
            turn_detection: {
              type: "server_vad",
              threshold: this.config.vadThreshold,
              prefix_padding_ms: 300,
              silence_duration_ms: this.config.silenceDurationMs,
            },
          },
        });
        resolve();
      });

      this.ws.on("message", (data: Buffer) => {
        captureWsEvent({
          url,
          direction: "inbound",
          kind: "ws-frame",
          flowId: this.flowId,
          payload: data,
          meta: {
            provider: "openai",
            capability: "realtime-transcription",
          },
        });
        try {
          const rawText = data.toString();
          const sanitizedText = sanitizeLLMResponse(rawText);
          this.handleEvent(JSON.parse(sanitizedText) as RealtimeEvent);
        } catch (error) {
          this.config.onError?.(error instanceof Error ? error : new Error(String(error)));
        }
      });

      this.ws.on("error", (error) => {
        captureWsEvent({
          url,
          direction: "local",
          kind: "error",
          flowId: this.flowId,
          errorText: error instanceof Error ? error.message : String(error),
          meta: {
            provider: "openai",
            capability: "realtime-transcription",
          },
        });
        if (!this.connected) {
          clearTimeout(connectTimeout);
          reject(error);
          return;
        }
        this.config.onError?.(error instanceof Error ? error : new Error(String(error)));
      });

      this.ws.on("close", (code, reasonBuffer) => {
        captureWsEvent({
          url,
          direction: "local",
          kind: "ws-close",
          flowId: this.flowId,
          closeCode: typeof code === "number" ? code : undefined,
          meta: {
            provider: "openai",
            capability: "realtime-transcription",
            reason:
              Buffer.isBuffer(reasonBuffer) && reasonBuffer.length > 0
                ? reasonBuffer.toString("utf8")
                : undefined,
          },
        });
        this.connected = false;
        if (this.closed) {
          return;
        }
        void this.attemptReconnect();
      });
    });
  }

  private async attemptReconnect(): Promise<void> {
    if (this.closed) {
      return;
    }
    if (this.reconnectAttempts >= OpenAIRealtimeTranscriptionSession.MAX_RECONNECT_ATTEMPTS) {
      this.config.onError?.(new Error("OpenAI realtime transcription reconnect limit reached"));
      return;
    }
    if (this.agentIterations >= MAX_AGENT_ITERATIONS) {
      this.config.onError?.(
        new Error(
          `OpenAI realtime transcription session exceeded maximum iterations (${MAX_AGENT_ITERATIONS}). Exiting.`,
        ),
      );
      this.closed = true;
      return;
    }
    this.reconnectAttempts += 1;
    const delay =
      OpenAIRealtimeTranscriptionSession.RECONNECT_DELAY_MS * 2 ** (this.reconnectAttempts - 1);
    await new Promise((resolve) => setTimeout(resolve, delay));
    if (this.closed) {
      return;
    }
    try {
      await this.doConnect();
    } catch (error) {
      this.config.onError?.(error instanceof Error ? error : new Error(String(error)));
      await this.attemptReconnect();
    }
  }

  private handleEvent(event: RealtimeEvent): void {
    switch (event.type) {
      case "conversation.item.input_audio_transcription.delta":
        if (event.delta) {
          const sanitizedDelta = sanitizeLLMInput(sanitizeLLMResponse(event.delta));
          this.pendingTranscript += sanitizedDelta;
          this.config.onPartial?.(this.pendingTranscript);
        }
        return;

      case "conversation.item.input_audio_transcription.completed":
        if (event.transcript) {
          const sanitizedTranscript = sanitizeLLMInput(sanitizeLLMResponse(event.transcript));
          this.config.onTranscript?.(sanitizedTranscript);
        }
        this.pendingTranscript = "";
        return;

      case "input_audio_buffer.speech_started":
        this.pendingTranscript = "";
        this.config.onSpeechStart?.();
        return;

      case "error": {
        const detail = readRealtimeErrorDetail(event.error);
        this.config.onError?.(new Error(detail));
        return;
      }

      default:
        return;
    }
  }

  private sendEvent(event: unknown): void {
    if (this.ws?.readyState === WebSocket.OPEN) {
      const payload = JSON.stringify(event);
      const sanitizedPayload = sanitizeLLMInput(payload);
      captureWsEvent({
        url: "wss://api.openai.com/v1/realtime?intent=transcription",
        direction: "outbound",
        kind: "ws-frame",
        flowId: this.flowId,
        payload: sanitizedPayload,
        meta: {
          provider: "openai",
          capability: "realtime-transcription",
        },
      });
      this.ws.send(sanitizedPayload);
    }
  }
}

export function buildOpenAIRealtimeTranscriptionProvider(): RealtimeTranscriptionProviderPlugin {
  return {
    id: "openai",
    label: "OpenAI Realtime Transcription",
    aliases: ["openai-realtime"],
    autoSelectOrder: 10,
    resolveConfig: ({ rawConfig }) => normalizeProviderConfig(rawConfig),
    isConfigured: ({ providerConfig }) =>
      Boolean(normalizeProviderConfig(providerConfig).apiKey || process.env.OPENAI_API_KEY),
    createSession: (req) => {
      const config = normalizeProviderConfig(req.providerConfig);
      const apiKey = config.apiKey || process.env.OPENAI_API_KEY;
      if (!apiKey) {
        throw new Error("OpenAI API key missing");
      }
      const rawModel = config.model ?? "gpt-4o-transcribe";
      const approvedModel = validateApprovedModel(rawModel);
      return new OpenAIRealtimeTranscriptionSession({
        ...req,
        apiKey,
        model: approvedModel,
        silenceDurationMs: config.silenceDurationMs ?? 800,
        vadThreshold: config.vadThreshold ?? 0.5,
      });
    },
  };
}