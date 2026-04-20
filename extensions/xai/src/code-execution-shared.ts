import { postTrustedWebToolsJson } from "@openclaw/plugin-sdk/provider-web-search";
import {
  buildXaiResponsesToolBody,
  resolveXaiResponseTextAndCitations,
  XAI_RESPONSES_ENDPOINT,
} from "./responses-tool-shared.js";
import {
  coerceXaiToolConfig,
  resolveNormalizedXaiToolModel,
  resolvePositiveIntegerToolConfig,
} from "./tool-config-shared.js";
import { type XaiWebSearchResponse } from "./web-search-shared.js";

export const XAI_CODE_EXECUTION_ENDPOINT = XAI_RESPONSES_ENDPOINT;
export const XAI_DEFAULT_CODE_EXECUTION_MODEL = "grok-4-1-fast";

// Policy: Enforce Approved LLM — notify if model is not in the approved list
const APPROVED_LLM_MODELS: readonly string[] = [
  "grok-4-1-fast",
  "grok-3",
  "grok-3-fast",
  "grok-3-mini",
  "grok-3-mini-fast",
];

function assertApprovedModel(model: string): void {
  if (!APPROVED_LLM_MODELS.includes(model)) {
    console.warn(
      `[SECURITY POLICY] The model "${model}" is not in the approved LLM allow list. ` +
        `Please replace it with an approved model: ${APPROVED_LLM_MODELS.join(", ")}.`,
    );
  }
}

// Policy: Sanitize LLM input — strip dangerous patterns from task/prompt text
const DANGEROUS_INPUT_PATTERNS: RegExp[] = [
  /ignore\s+previous\s+instructions/gi,
  /system\s*prompt/gi,
  /<\s*script[^>]*>/gi,
  /javascript\s*:/gi,
  /data\s*:\s*text\/html/gi,
  /\beval\s*\(/gi,
  /\bexec\s*\(/gi,
  /\bsubprocess\s*\(/gi,
  /\bos\.system\s*\(/gi,
  /\bshell\s*=\s*True/gi,
];

function sanitizeLlmInput(input: string): string {
  if (typeof input !== "string") return "";
  let sanitized = input.trim();
  for (const pattern of DANGEROUS_INPUT_PATTERNS) {
    sanitized = sanitized.replace(pattern, "[REDACTED]");
  }
  if (sanitized.length === 0) {
    throw new Error("[SECURITY] LLM input is empty after sanitization.");
  }
  if (sanitized.length > 32000) {
    throw new Error("[SECURITY] LLM input exceeds maximum allowed length.");
  }
  return sanitized;
}

// Policy: LLM Interaction Logging — log every interaction with the LLM
function logLlmRequest(params: {
  model: string;
  task: string;
  endpoint: string;
  timeoutSeconds: number;
  maxTurns?: number;
}): void {
  console.info("[LLM REQUEST]", {
    timestamp: new Date().toISOString(),
    endpoint: params.endpoint,
    model: params.model,
    timeoutSeconds: params.timeoutSeconds,
    maxTurns: params.maxTurns,
    taskLength: params.task.length,
    taskPreview: params.task.slice(0, 100),
  });
}

function logLlmResponse(params: {
  model: string;
  endpoint: string;
  contentLength: number;
  citationsCount: number;
  usedCodeExecution: boolean;
  outputTypes: string[];
}): void {
  console.info("[LLM RESPONSE]", {
    timestamp: new Date().toISOString(),
    endpoint: params.endpoint,
    model: params.model,
    contentLength: params.contentLength,
    citationsCount: params.citationsCount,
    usedCodeExecution: params.usedCodeExecution,
    outputTypes: params.outputTypes,
  });
}

// Policy: LLM Interaction Logging (Instruction 3) — sanitize and validate LLM responses,
// removing lines containing eval, exec, JS eval, bash eval, subprocess(shell=True)
const DANGEROUS_RESPONSE_LINE_PATTERNS: RegExp[] = [
  /\beval\s*\(/i,
  /\bexec\s*\(/i,
  /\bsubprocess\s*\(.*shell\s*=\s*True/i,
  /\bos\.system\s*\(/i,
  /\bshell\s*=\s*True/i,
  /\bnew\s+Function\s*\(/i,
  /\bsetTimeout\s*\(\s*["'`]/i,
  /\bsetInterval\s*\(\s*["'`]/i,
];

function sanitizeLlmResponse(content: string): string {
  if (typeof content !== "string") return "";
  const lines = content.split("\n");
  const sanitizedLines = lines.filter((line) => {
    for (const pattern of DANGEROUS_RESPONSE_LINE_PATTERNS) {
      if (pattern.test(line)) {
        console.warn(
          "[SECURITY] Removed dangerous line from LLM response:",
          line.slice(0, 200),
        );
        return false;
      }
    }
    return true;
  });
  return sanitizedLines.join("\n");
}

function validateLlmResponse(data: unknown): void {
  if (data === null || typeof data !== "object") {
    throw new Error("[SECURITY] LLM response is not a valid object.");
  }
}

export type XaiCodeExecutionConfig = {
  apiKey?: unknown;
  model?: unknown;
  maxTurns?: unknown;
};

export type XaiCodeExecutionResponse = XaiWebSearchResponse & {
  output?: Array<{
    type?: string;
  }>;
};

export type XaiCodeExecutionResult = {
  content: string;
  citations: string[];
  usedCodeExecution: boolean;
  outputTypes: string[];
};

export function resolveXaiCodeExecutionConfig(
  config?: Record<string, unknown>,
): XaiCodeExecutionConfig {
  return coerceXaiToolConfig<XaiCodeExecutionConfig>(config);
}

export function resolveXaiCodeExecutionModel(config?: Record<string, unknown>): string {
  return resolveNormalizedXaiToolModel({
    config,
    defaultModel: XAI_DEFAULT_CODE_EXECUTION_MODEL,
  });
}

export function resolveXaiCodeExecutionMaxTurns(
  config?: Record<string, unknown>,
): number | undefined {
  return resolvePositiveIntegerToolConfig(config, "maxTurns");
}

export function buildXaiCodeExecutionPayload(params: {
  task: string;
  model: string;
  tookMs: number;
  content: string;
  citations: string[];
  usedCodeExecution: boolean;
  outputTypes: string[];
}): Record<string, unknown> {
  return {
    task: params.task,
    provider: "xai",
    model: params.model,
    tookMs: params.tookMs,
    content: params.content,
    citations: params.citations,
    usedCodeExecution: params.usedCodeExecution,
    outputTypes: params.outputTypes,
  };
}

export async function requestXaiCodeExecution(params: {
  apiKey: string;
  model: string;
  timeoutSeconds: number;
  maxTurns?: number;
  task: string;
}): Promise<XaiCodeExecutionResult> {
  // Policy: Enforce Approved LLM
  assertApprovedModel(params.model);

  // Policy: Sanitize LLM input
  const sanitizedTask = sanitizeLlmInput(params.task);

  // Policy: LLM Interaction Logging — log request
  logLlmRequest({
    model: params.model,
    task: sanitizedTask,
    endpoint: XAI_CODE_EXECUTION_ENDPOINT,
    timeoutSeconds: params.timeoutSeconds,
    maxTurns: params.maxTurns,
  });

  return await postTrustedWebToolsJson(
    {
      url: XAI_CODE_EXECUTION_ENDPOINT,
      timeoutSeconds: params.timeoutSeconds,
      apiKey: params.apiKey,
      body: buildXaiResponsesToolBody({
        model: params.model,
        inputText: sanitizedTask,
        tools: [{ type: "code_interpreter" }],
        maxTurns: params.maxTurns,
      }),
      errorLabel: "xAI",
    },
    async (response) => {
      const data = (await response.json()) as XaiCodeExecutionResponse;

      // Policy: Validate LLM response structure
      validateLlmResponse(data);

      const { content: rawContent, citations } = resolveXaiResponseTextAndCitations(data);

      // Policy: LLM Interaction Logging (Instruction 3) — sanitize response content
      const content = sanitizeLlmResponse(rawContent);

      const outputTypes = Array.isArray(data.output)
        ? [
            ...new Set(
              data.output
                .map((entry) => entry?.type)
                .filter((value): value is string => Boolean(value)),
            ),
          ]
        : [];

      const result: XaiCodeExecutionResult = {
        content,
        citations,
        usedCodeExecution: outputTypes.includes("code_interpreter_call"),
        outputTypes,
      };

      // Policy: LLM Interaction Logging — log response
      logLlmResponse({
        model: params.model,
        endpoint: XAI_CODE_EXECUTION_ENDPOINT,
        contentLength: content.length,
        citationsCount: citations.length,
        usedCodeExecution: result.usedCodeExecution,
        outputTypes,
      });

      return result;
    },
  );
}

export const __testing = {
  buildXaiCodeExecutionPayload,
  requestXaiCodeExecution,
  resolveXaiCodeExecutionConfig,
  resolveXaiCodeExecutionMaxTurns,
  resolveXaiCodeExecutionModel,
  XAI_DEFAULT_CODE_EXECUTION_MODEL,
} as const;