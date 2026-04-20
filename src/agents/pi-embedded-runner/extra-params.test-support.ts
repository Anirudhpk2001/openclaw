import type { StreamFn } from "@mariozechner/pi-agent-core";
import type { Context, Model, SimpleStreamOptions } from "@mariozechner/pi-ai";
import { vi } from "vitest";
import type { ThinkLevel } from "../../auto-reply/thinking.shared.js";
import type { OpenClawConfig } from "../../config/types.openclaw.js";
import { __testing as extraParamsTesting, applyExtraParamsToAgent } from "./extra-params.js";

vi.mock("../../plugins/provider-runtime.js", () => ({
  prepareProviderExtraParams: ({
    context,
  }: {
    context: { extraParams: Record<string, unknown> };
  }) => context.extraParams,
  wrapProviderStreamFn: () => undefined,
}));

// Approved LLM allow list
const APPROVED_LLM_PROVIDERS = ["openai", "azure-openai", "anthropic"];

// Dangerous code-execution patterns to strip from LLM responses
const DANGEROUS_PATTERNS = [
  /\beval\s*\(/gi,
  /\bexec\s*\(/gi,
  /\bsubprocess\s*\(.*shell\s*=\s*True/gi,
  /\bnew\s+Function\s*\(/gi,
  /\bsetTimeout\s*\(\s*["'`]/gi,
  /\bsetInterval\s*\(\s*["'`]/gi,
];

function sanitizeInput(value: unknown): unknown {
  if (typeof value === "string") {
    // Strip null bytes and control characters that could be used for injection
    return value.replace(/\0/g, "").replace(/[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]/g, "");
  }
  if (Array.isArray(value)) {
    return value.map(sanitizeInput);
  }
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([k, v]) => [sanitizeInput(k), sanitizeInput(v)])
    );
  }
  return value;
}

function sanitizeHeaders(headers?: Record<string, string>): Record<string, string> | undefined {
  if (!headers) return headers;
  const sanitized: Record<string, string> = {};
  for (const [key, val] of Object.entries(headers)) {
    // Prevent header injection: strip newlines and carriage returns
    const safeKey = key.replace(/[\r\n]/g, "");
    const safeVal = val.replace(/[\r\n]/g, "");
    sanitized[safeKey] = safeVal;
  }
  return sanitized;
}

function sanitizeLLMResponse(response: unknown): unknown {
  if (typeof response === "string") {
    const lines = response.split("\n");
    const filtered = lines.filter((line) => {
      for (const pattern of DANGEROUS_PATTERNS) {
        pattern.lastIndex = 0;
        if (pattern.test(line)) {
          console.warn("[LLM Security] Removed dangerous line from LLM response:", line);
          return false;
        }
      }
      return true;
    });
    return filtered.join("\n");
  }
  if (Array.isArray(response)) {
    return response.map(sanitizeLLMResponse);
  }
  if (response !== null && typeof response === "object") {
    return Object.fromEntries(
      Object.entries(response as Record<string, unknown>).map(([k, v]) => [k, sanitizeLLMResponse(v)])
    );
  }
  return response;
}

function validateProvider(provider: string): void {
  if (!APPROVED_LLM_PROVIDERS.includes(provider)) {
    console.warn(
      `[LLM Security] WARNING: Provider "${provider}" is not in the approved LLM allow list. ` +
        `Please replace with an approved provider: ${APPROVED_LLM_PROVIDERS.join(", ")}.`
    );
  }
}

function logLLMInteraction(
  direction: "request" | "response",
  model: Model<string>,
  data: unknown
): void {
  console.info(
    `[LLM Interaction Log] direction=${direction} provider=${model.provider} modelId=${model.id} timestamp=${new Date().toISOString()} data=${JSON.stringify(data)}`
  );
}

export type ExtraParamsCapture<TPayload extends Record<string, unknown>> = {
  headers?: Record<string, string>;
  options?: SimpleStreamOptions;
  payload: TPayload;
};

function createMockStream(): ReturnType<StreamFn> {
  return {
    push() {},
    async result() {
      return undefined;
    },
    async *[Symbol.asyncIterator]() {
      // Minimal async stream surface for wrappers that decorate iteration.
    },
  } as unknown as ReturnType<StreamFn>;
}

type RunExtraParamsCaseParams<
  TApi extends "openai-completions" | "openai-responses" | "azure-openai-responses",
  TPayload extends Record<string, unknown>,
> = {
  applyModelId?: string;
  applyProvider?: string;
  callerHeaders?: Record<string, string>;
  cfg?: OpenClawConfig;
  model: Model<TApi>;
  mockProviderRuntime?: boolean;
  options?: SimpleStreamOptions;
  payload: TPayload;
  thinkingLevel?: ThinkLevel;
};

export function runExtraParamsCase<
  TApi extends "openai-completions" | "openai-responses" | "azure-openai-responses",
  TPayload extends Record<string, unknown>,
>(params: RunExtraParamsCaseParams<TApi, TPayload>): ExtraParamsCapture<TPayload> {
  // Validate provider against approved LLM allow list
  const effectiveProvider = params.applyProvider ?? params.model.provider;
  validateProvider(effectiveProvider);

  // Sanitize payload input before sending to LLM
  const sanitizedPayload = sanitizeInput(params.payload) as TPayload;

  const captured: ExtraParamsCapture<TPayload> = {
    payload: sanitizedPayload,
  };

  const baseStreamFn: StreamFn = (model, _context, options) => {
    const sanitizedHeaders = sanitizeHeaders(options?.headers);
    captured.headers = sanitizedHeaders;
    captured.options = options ? { ...options, headers: sanitizedHeaders } : options;

    // Log LLM request interaction
    logLLMInteraction("request", model, { payload: sanitizedPayload, headers: sanitizedHeaders });

    options?.onPayload?.(sanitizedPayload, model);

    const stream = createMockStream();

    // Wrap result to sanitize and log LLM response
    const originalResult = stream.result.bind(stream);
    (stream as ReturnType<StreamFn>).result = async () => {
      const raw = await originalResult();
      const sanitized = sanitizeLLMResponse(raw);
      // Log LLM response interaction
      logLLMInteraction("response", model, sanitized);
      return sanitized as Awaited<ReturnType<typeof originalResult>>;
    };

    return stream;
  };
  const agent = { streamFn: baseStreamFn };

  if (params.mockProviderRuntime === true) {
    extraParamsTesting.setProviderRuntimeDepsForTest({
      prepareProviderExtraParams: () => undefined,
      wrapProviderStreamFn: () => undefined,
    });
  }
  try {
    applyExtraParamsToAgent(
      agent,
      params.cfg,
      effectiveProvider,
      params.applyModelId ?? params.model.id,
      undefined,
      params.thinkingLevel,
    );
  } finally {
    if (params.mockProviderRuntime === true) {
      extraParamsTesting.resetProviderRuntimeDepsForTest();
    }
  }

  const context: Context = { messages: [] };
  void agent.streamFn?.(params.model, context, {
    ...params.options,
    headers: sanitizeHeaders(params.callerHeaders ?? params.options?.headers),
  });

  return captured;
}