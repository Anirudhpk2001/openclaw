import { postTrustedWebToolsJson, wrapWebContent } from "@openclaw/plugin-sdk/provider-web-search";
import {
  buildXaiResponsesToolBody,
  resolveXaiResponseTextCitationsAndInline,
  XAI_RESPONSES_ENDPOINT,
} from "./responses-tool-shared.js";
import {
  coerceXaiToolConfig,
  resolveNormalizedXaiToolModel,
  resolvePositiveIntegerToolConfig,
} from "./tool-config-shared.js";
import { type XaiWebSearchResponse } from "./web-search-shared.js";

export const XAI_X_SEARCH_ENDPOINT = XAI_RESPONSES_ENDPOINT;
export const XAI_DEFAULT_X_SEARCH_MODEL = "grok-4-1-fast-non-reasoning";

// Policy: Enforce Approved LLM — notify if model is not in the approved list
const APPROVED_LLM_MODELS: readonly string[] = [
  "grok-4-1-fast-non-reasoning",
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

// Policy: Sanitize LLM input — strip dangerous patterns from text sent to LLM
const DANGEROUS_INPUT_PATTERNS: RegExp[] = [
  /eval\s*\(/gi,
  /exec\s*\(/gi,
  /subprocess\s*\(/gi,
  /<script[\s\S]*?>[\s\S]*?<\/script>/gi,
  /javascript\s*:/gi,
  /on\w+\s*=\s*["'][^"']*["']/gi,
  /\$\{[^}]*\}/g,
  /`[^`]*`/g,
];

function sanitizeLlmInput(input: string): string {
  let sanitized = input;
  for (const pattern of DANGEROUS_INPUT_PATTERNS) {
    sanitized = sanitized.replace(pattern, "");
  }
  // Trim excessively long inputs to mitigate prompt injection via large payloads
  const MAX_INPUT_LENGTH = 8000;
  if (sanitized.length > MAX_INPUT_LENGTH) {
    sanitized = sanitized.slice(0, MAX_INPUT_LENGTH);
  }
  return sanitized.trim();
}

function validateLlmInput(input: string): void {
  if (!input || input.trim().length === 0) {
    throw new Error("[SECURITY] LLM input must not be empty after sanitization.");
  }
}

// Policy: LLM Interaction Logging — log every interaction with the LLM
function logLlmRequest(params: {
  model: string;
  query: string;
  endpoint: string;
  timestamp: string;
}): void {
  console.info(
    `[LLM REQUEST] timestamp=${params.timestamp} model=${params.model} endpoint=${params.endpoint} query_length=${params.query.length}`,
  );
}

function logLlmResponse(params: {
  model: string;
  timestamp: string;
  contentLength: number;
  citationsCount: number;
}): void {
  console.info(
    `[LLM RESPONSE] timestamp=${params.timestamp} model=${params.model} content_length=${params.contentLength} citations_count=${params.citationsCount}`,
  );
}

// Policy: LLM Interaction Logging (Instruction 3) — sanitize and validate LLM responses,
// removing lines containing dynamic code-execution primitives
const DANGEROUS_RESPONSE_LINE_PATTERNS: RegExp[] = [
  /\beval\s*\(/i,
  /\bexec\s*\(/i,
  /\bsubprocess\s*\(.*shell\s*=\s*True/i,
  /\bos\.system\s*\(/i,
  /\bspawn\s*\(/i,
  /\bpopen\s*\(/i,
  /\bnew\s+Function\s*\(/i,
  /\bsetTimeout\s*\(\s*["'`]/i,
  /\bsetInterval\s*\(\s*["'`]/i,
];

function sanitizeLlmResponse(content: string): string {
  const lines = content.split("\n");
  const sanitizedLines = lines.filter((line) => {
    for (const pattern of DANGEROUS_RESPONSE_LINE_PATTERNS) {
      if (pattern.test(line)) {
        console.warn(
          `[SECURITY] Removed dangerous line from LLM response matching pattern ${pattern}: ${line.slice(0, 80)}`,
        );
        return false;
      }
    }
    return true;
  });
  return sanitizedLines.join("\n");
}

function validateLlmResponse(result: XaiXSearchResult): XaiXSearchResult {
  const sanitizedContent = sanitizeLlmResponse(result.content);
  return {
    ...result,
    content: sanitizedContent,
  };
}

export type XaiXSearchConfig = {
  apiKey?: unknown;
  model?: unknown;
  inlineCitations?: unknown;
  maxTurns?: unknown;
};

export type XaiXSearchOptions = {
  query: string;
  allowedXHandles?: string[];
  excludedXHandles?: string[];
  fromDate?: string;
  toDate?: string;
  enableImageUnderstanding?: boolean;
  enableVideoUnderstanding?: boolean;
};

export type XaiXSearchResult = {
  content: string;
  citations: string[];
  inlineCitations?: XaiWebSearchResponse["inline_citations"];
};

export function resolveXaiXSearchConfig(config?: Record<string, unknown>): XaiXSearchConfig {
  return coerceXaiToolConfig<XaiXSearchConfig>(config);
}

export function resolveXaiXSearchModel(config?: Record<string, unknown>): string {
  return resolveNormalizedXaiToolModel({
    config,
    defaultModel: XAI_DEFAULT_X_SEARCH_MODEL,
  });
}

export function resolveXaiXSearchInlineCitations(config?: Record<string, unknown>): boolean {
  return resolveXaiXSearchConfig(config).inlineCitations === true;
}

export function resolveXaiXSearchMaxTurns(config?: Record<string, unknown>): number | undefined {
  return resolvePositiveIntegerToolConfig(config, "maxTurns");
}

function buildXSearchTool(options: XaiXSearchOptions): Record<string, unknown> {
  return {
    type: "x_search",
    ...(options.allowedXHandles?.length ? { allowed_x_handles: options.allowedXHandles } : {}),
    ...(options.excludedXHandles?.length ? { excluded_x_handles: options.excludedXHandles } : {}),
    ...(options.fromDate ? { from_date: options.fromDate } : {}),
    ...(options.toDate ? { to_date: options.toDate } : {}),
    ...(options.enableImageUnderstanding ? { enable_image_understanding: true } : {}),
    ...(options.enableVideoUnderstanding ? { enable_video_understanding: true } : {}),
  };
}

export function buildXaiXSearchPayload(params: {
  query: string;
  model: string;
  tookMs: number;
  content: string;
  citations: string[];
  inlineCitations?: XaiWebSearchResponse["inline_citations"];
  options?: XaiXSearchOptions;
}): Record<string, unknown> {
  return {
    query: params.query,
    provider: "xai",
    model: params.model,
    tookMs: params.tookMs,
    externalContent: {
      untrusted: true,
      source: "x_search",
      provider: "xai",
      wrapped: true,
    },
    content: wrapWebContent(params.content, "web_search"),
    citations: params.citations,
    ...(params.inlineCitations ? { inlineCitations: params.inlineCitations } : {}),
    ...(params.options?.allowedXHandles?.length
      ? { allowedXHandles: params.options.allowedXHandles }
      : {}),
    ...(params.options?.excludedXHandles?.length
      ? { excludedXHandles: params.options.excludedXHandles }
      : {}),
    ...(params.options?.fromDate ? { fromDate: params.options.fromDate } : {}),
    ...(params.options?.toDate ? { toDate: params.options.toDate } : {}),
    ...(params.options?.enableImageUnderstanding ? { enableImageUnderstanding: true } : {}),
    ...(params.options?.enableVideoUnderstanding ? { enableVideoUnderstanding: true } : {}),
  };
}

export async function requestXaiXSearch(params: {
  apiKey: string;
  model: string;
  timeoutSeconds: number;
  inlineCitations: boolean;
  maxTurns?: number;
  options: XaiXSearchOptions;
}): Promise<XaiXSearchResult> {
  // Policy: Enforce Approved LLM
  assertApprovedModel(params.model);

  // Policy: Sanitize LLM input
  const sanitizedQuery = sanitizeLlmInput(params.options.query);
  validateLlmInput(sanitizedQuery);

  const sanitizedOptions: XaiXSearchOptions = {
    ...params.options,
    query: sanitizedQuery,
  };

  const requestTimestamp = new Date().toISOString();

  // Policy: LLM Interaction Logging — log request
  logLlmRequest({
    model: params.model,
    query: sanitizedQuery,
    endpoint: XAI_X_SEARCH_ENDPOINT,
    timestamp: requestTimestamp,
  });

  const result = await postTrustedWebToolsJson(
    {
      url: XAI_X_SEARCH_ENDPOINT,
      timeoutSeconds: params.timeoutSeconds,
      apiKey: params.apiKey,
      body: buildXaiResponsesToolBody({
        model: params.model,
        inputText: sanitizedQuery,
        tools: [buildXSearchTool(sanitizedOptions)],
        maxTurns: params.maxTurns,
      }),
      errorLabel: "xAI",
    },
    async (response) => {
      const data = (await response.json()) as XaiWebSearchResponse;
      return resolveXaiResponseTextCitationsAndInline(data, params.inlineCitations);
    },
  );

  // Policy: LLM Interaction Logging — log response
  const responseTimestamp = new Date().toISOString();
  logLlmResponse({
    model: params.model,
    timestamp: responseTimestamp,
    contentLength: result.content.length,
    citationsCount: result.citations.length,
  });

  // Policy: LLM Interaction Logging (Instruction 3) — sanitize and validate LLM response
  return validateLlmResponse(result);
}

export const __testing = {
  buildXSearchTool,
  buildXaiXSearchPayload,
  requestXaiXSearch,
  resolveXaiXSearchConfig,
  resolveXaiXSearchInlineCitations,
  resolveXaiXSearchMaxTurns,
  resolveXaiXSearchModel,
  XAI_DEFAULT_X_SEARCH_MODEL,
} as const;