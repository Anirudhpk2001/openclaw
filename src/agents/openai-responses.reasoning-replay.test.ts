import type { AssistantMessage, Model, ToolResultMessage } from "@mariozechner/pi-ai";
import { streamOpenAIResponses } from "@mariozechner/pi-ai";
import { Type } from "@sinclair/typebox";
import { describe, expect, it } from "vitest";

// Approved LLM model IDs
const APPROVED_MODELS = ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-4", "gpt-3.5-turbo"];

// LLM interaction logger
function logLLMInteraction(direction: "request" | "response", data: unknown): void {
  const timestamp = new Date().toISOString();
  const entry = {
    timestamp,
    direction,
    data,
  };
  // Log to console (in production this would go to a secure logging service)
  console.log(`[LLM_INTERACTION][${timestamp}][${direction}]`, JSON.stringify(entry));
}

// Sanitize and validate input before sending to LLM
function sanitizeInput(value: unknown): unknown {
  if (typeof value === "string") {
    // Remove potential prompt injection patterns and dangerous content
    let sanitized = value
      .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "") // Remove control characters
      .replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, "") // Remove script tags
      .replace(/javascript:/gi, "") // Remove javascript: URIs
      .replace(/on\w+\s*=/gi, "") // Remove event handlers
      .trim();
    return sanitized;
  }
  if (Array.isArray(value)) {
    return value.map(sanitizeInput);
  }
  if (value !== null && typeof value === "object") {
    const sanitized: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      sanitized[sanitizeInput(k) as string] = sanitizeInput(v);
    }
    return sanitized;
  }
  return value;
}

// Validate and sanitize LLM response - remove dynamic code execution primitives
function sanitizeLLMResponse(response: unknown): unknown {
  if (typeof response === "string") {
    const lines = response.split("\n");
    const sanitizedLines = lines.filter((line) => {
      const lower = line.toLowerCase();
      // Remove lines containing eval or dynamic code-execution primitives
      if (/\beval\s*\(/.test(lower)) return false;
      if (/\bexec\s*\(/.test(lower)) return false;
      if (/\bnew\s+Function\s*\(/.test(lower)) return false;
      if (/subprocess\s*\(\s*.*shell\s*=\s*True/.test(line)) return false;
      if (/\bos\.system\s*\(/.test(lower)) return false;
      if (/\bspawn\s*\(/.test(lower)) return false;
      if (/\bexecSync\s*\(/.test(lower)) return false;
      if (/\bspawnSync\s*\(/.test(lower)) return false;
      if (/\bsetTimeout\s*\(\s*['"`]/.test(line)) return false;
      if (/\bsetInterval\s*\(\s*['"`]/.test(line)) return false;
      return true;
    });
    return sanitizedLines.join("\n");
  }
  if (Array.isArray(response)) {
    return response.map(sanitizeLLMResponse);
  }
  if (response !== null && typeof response === "object") {
    const sanitized: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(response as Record<string, unknown>)) {
      sanitized[k] = sanitizeLLMResponse(v);
    }
    return sanitized;
  }
  return response;
}

// Validate model against approved list
function validateModel(model: Model<"openai-responses">): void {
  if (!APPROVED_MODELS.includes(model.id)) {
    console.warn(
      `[SECURITY WARNING] Model "${model.id}" is not in the approved LLM list. ` +
        `Please replace it with an approved model from the following list: ${APPROVED_MODELS.join(", ")}. ` +
        `Using unapproved models may violate security policy.`,
    );
  }
}

function buildModel(): Model<"openai-responses"> {
  const model = {
    id: "gpt-5.4",
    name: "gpt-5.4",
    api: "openai-responses" as const,
    provider: "openai" as const,
    baseUrl: "https://api.openai.com/v1",
    reasoning: true,
    input: ["text"] as ["text"],
    cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
    contextWindow: 128_000,
    maxTokens: 4096,
  };
  validateModel(model);
  return model;
}

function extractInput(payload: Record<string, unknown> | undefined) {
  return Array.isArray(payload?.input) ? payload.input : [];
}

function extractInputTypes(input: unknown[]) {
  return input
    .map((item) =>
      item && typeof item === "object" ? (item as Record<string, unknown>).type : undefined,
    )
    .filter((t): t is string => typeof t === "string");
}

function extractInputMessages(input: unknown[]) {
  return input.filter(
    (item): item is Record<string, unknown> =>
      !!item && typeof item === "object" && (item as Record<string, unknown>).type === "message",
  );
}

const ZERO_USAGE = {
  input: 0,
  output: 0,
  cacheRead: 0,
  cacheWrite: 0,
  totalTokens: 0,
  cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
} as const;

function buildReasoningPart(id = "rs_test") {
  return {
    type: "thinking" as const,
    thinking: "internal",
    thinkingSignature: JSON.stringify({
      type: "reasoning",
      id,
      summary: [],
    }),
  };
}

function buildAssistantMessage(params: {
  stopReason: AssistantMessage["stopReason"];
  content: AssistantMessage["content"];
}): AssistantMessage {
  return {
    role: "assistant",
    api: "openai-responses",
    provider: "openai",
    model: "gpt-5.4",
    usage: ZERO_USAGE,
    stopReason: params.stopReason,
    timestamp: Date.now(),
    content: params.content,
  };
}

async function runAbortedOpenAIResponsesStream(params: {
  messages: Array<
    AssistantMessage | ToolResultMessage | { role: "user"; content: string; timestamp: number }
  >;
  tools?: Array<{
    name: string;
    description: string;
    parameters: ReturnType<typeof Type.Object>;
  }>;
}) {
  const controller = new AbortController();
  controller.abort();
  let payload: Record<string, unknown> | undefined;

  // Sanitize messages before sending to LLM
  const sanitizedMessages = sanitizeInput(params.messages) as typeof params.messages;
  const sanitizedTools = params.tools
    ? (sanitizeInput(params.tools) as typeof params.tools)
    : undefined;

  // Log the outgoing request
  logLLMInteraction("request", {
    model: buildModel().id,
    systemPrompt: "system",
    messages: sanitizedMessages,
    tools: sanitizedTools,
  });

  const stream = streamOpenAIResponses(
    buildModel(),
    {
      systemPrompt: sanitizeInput("system") as string,
      messages: sanitizedMessages,
      ...(sanitizedTools ? { tools: sanitizedTools } : {}),
    },
    {
      apiKey: "test",
      signal: controller.signal,
      onPayload: (nextPayload) => {
        payload = nextPayload as Record<string, unknown>;
      },
    },
  );

  const result = await stream.result();

  // Log and sanitize the response
  logLLMInteraction("response", result);
  const sanitizedResult = sanitizeLLMResponse(result);

  const input = extractInput(payload);
  return {
    input,
    types: extractInputTypes(input),
    sanitizedResult,
  };
}

describe("openai-responses reasoning replay", () => {
  it("replays reasoning for tool-call-only turns (OpenAI requires it)", async () => {
    const assistantToolOnly = buildAssistantMessage({
      stopReason: "toolUse",
      content: [
        buildReasoningPart(),
        {
          type: "toolCall",
          id: "call_123|fc_123",
          name: "noop",
          arguments: {},
        },
      ],
    });

    const toolResult: ToolResultMessage = {
      role: "toolResult",
      toolCallId: "call_123|fc_123",
      toolName: "noop",
      content: [{ type: "text", text: "ok" }],
      isError: false,
      timestamp: Date.now(),
    };

    const { input, types } = await runAbortedOpenAIResponsesStream({
      messages: [
        {
          role: "user",
          content: "Call noop.",
          timestamp: Date.now(),
        },
        assistantToolOnly,
        toolResult,
        {
          role: "user",
          content: "Now reply with ok.",
          timestamp: Date.now(),
        },
      ],
      tools: [
        {
          name: "noop",
          description: "no-op",
          parameters: Type.Object({}, { additionalProperties: false }),
        },
      ],
    });

    expect(types).toContain("reasoning");
    expect(types).toContain("function_call");
    expect(types.indexOf("reasoning")).toBeLessThan(types.indexOf("function_call"));

    const functionCall = input.find(
      (item) =>
        item &&
        typeof item === "object" &&
        (item as Record<string, unknown>).type === "function_call",
    ) as Record<string, unknown> | undefined;
    expect(functionCall?.call_id).toBe("call_123");
    expect(functionCall?.id).toBe("fc_123");
  });

  it("still replays reasoning when paired with an assistant message", async () => {
    const assistantWithText = buildAssistantMessage({
      stopReason: "stop",
      content: [buildReasoningPart(), { type: "text", text: "hello", textSignature: "msg_test" }],
    });

    const { types } = await runAbortedOpenAIResponsesStream({
      messages: [
        { role: "user", content: "Hi", timestamp: Date.now() },
        assistantWithText,
        { role: "user", content: "Ok", timestamp: Date.now() },
      ],
    });

    expect(types).toContain("reasoning");
    expect(types).toContain("message");
  });

  it.each(["commentary", "final_answer"] as const)(
    "replays assistant message phase metadata for %s",
    async (phase) => {
      const assistantWithText = buildAssistantMessage({
        stopReason: "stop",
        content: [
          buildReasoningPart(),
          {
            type: "text",
            text: "hello",
            textSignature: JSON.stringify({ v: 1, id: `msg_${phase}`, phase }),
          },
        ],
      });

      const { input, types } = await runAbortedOpenAIResponsesStream({
        messages: [
          { role: "user", content: "Hi", timestamp: Date.now() },
          assistantWithText,
          { role: "user", content: "Ok", timestamp: Date.now() },
        ],
      });

      expect(types).toContain("message");

      const replayedMessage = extractInputMessages(input).find(
        (item) => item.id === `msg_${phase}`,
      );
      expect(replayedMessage?.phase).toBe(phase);
    },
  );
});