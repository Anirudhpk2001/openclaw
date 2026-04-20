import { postTrustedWebToolsJson, wrapWebContent } from "@openclaw/plugin-sdk/provider-web-search";
import { normalizeXaiModelId } from "../model-id.js";
import {
  buildXaiResponsesToolBody,
  extractXaiWebSearchContent,
  resolveXaiResponseTextCitationsAndInline,
  XAI_RESPONSES_ENDPOINT,
} from "./responses-tool-shared.js";
import { isRecord } from "./tool-config-shared.js";
import type { XaiWebSearchResponse } from "./web-search-response.types.js";
export { extractXaiWebSearchContent } from "./responses-tool-shared.js";
export type { XaiWebSearchResponse } from "./web-search-response.types.js";

export const XAI_WEB_SEARCH_ENDPOINT = XAI_RESPONSES_ENDPOINT;
export const XAI_DEFAULT_WEB_SEARCH_MODEL = "grok-4-1-fast";

const APPROVED_LLM_MODELS = [
  "grok-4-1-fast",
  "grok-3",
  "grok-3-fast",
  "grok-3-mini",
  "grok-3-mini-fast",
];

const DYNAMIC_CODE_EXECUTION_PATTERNS = [
  /\beval\s*\(/gi,
  /\bexec\s*\(/gi,
  /\bnew\s+Function\s*\(/gi,
  /\bsetTimeout\s*\(\s*["'`]/gi,
  /\bsetInterval\s*\(\s*["'`]/gi,
  /\bsubprocess\s*\(\s*shell\s*=\s*True/gi,
  /\bos\.system\s*\(/gi,
  /\bos\.popen\s*\(/gi,
  /\bchild_process/gi,
  /\bspawnSync\s*\(/gi,
  /\bexecSync\s*\(/gi,
];

const MAX_QUERY_LENGTH = 2000;
const ALLOWED_QUERY_PATTERN = /^[\w\s.,!?'"()\-:;@#&+=%/\\[\]{}|<>~`^*]+$/;

type XaiWebSearchConfig = Record<string, unknown> & {
  model?: unknown;
  inlineCitations?: unknown;
};

export type XaiWebSearchResult = {
  content: string;
  citations: string[];
  inlineCitations?: XaiWebSearchResponse["inline_citations"];
};

function sanitizeQuery(query: string): string {
  if (typeof query !== "string") {
    throw new Error("Query must be a string");
  }
  let sanitized = query.trim();
  if (sanitized.length === 0) {
    throw new Error("Query must not be empty");
  }
  if (sanitized.length > MAX_QUERY_LENGTH) {
    sanitized = sanitized.slice(0, MAX_QUERY_LENGTH);
  }
  // Remove null bytes and control characters
  sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
  // Strip potential prompt injection patterns
  sanitized = sanitized.replace(/\bignore\s+(previous|all|above)\s+instructions?\b/gi, "");
  sanitized = sanitized.replace(/\bsystem\s*prompt\b/gi, "");
  sanitized = sanitized.replace(/\bact\s+as\b/gi, "");
  return sanitized;
}

function validateApprovedModel(model: string): void {
  if (!APPROVED_LLM_MODELS.includes(model)) {
    console.warn(
      `[LLM Policy] WARNING: Model "${model}" is not in the approved LLM allow list. ` +
        `Approved models are: ${APPROVED_LLM_MODELS.join(", ")}. ` +
        `Please replace the unapproved LLM with an approved LLM from the allow list.`,
    );
  }
}

function sanitizeLlmResponse(content: string): string {
  if (typeof content !== "string") {
    return "";
  }
  const lines = content.split("\n");
  const sanitizedLines = lines.filter((line) => {
    for (const pattern of DYNAMIC_CODE_EXECUTION_PATTERNS) {
      pattern.lastIndex = 0;
      if (pattern.test(line)) {
        console.warn(
          `[LLM Response Sanitization] Removed line containing dynamic code execution primitive: ${line.slice(0, 100)}`,
        );
        return false;
      }
    }
    return true;
  });
  return sanitizedLines.join("\n");
}

function logLlmInteraction(params: {
  direction: "request" | "response";
  model: string;
  query?: string;
  responseLength?: number;
  citations?: string[];
  timestamp: string;
}): void {
  const logEntry = {
    timestamp: params.timestamp,
    direction: params.direction,
    model: params.model,
    ...(params.query !== undefined ? { queryLength: params.query.length } : {}),
    ...(params.responseLength !== undefined ? { responseLength: params.responseLength } : {}),
    ...(params.citations !== undefined ? { citationCount: params.citations.length } : {}),
  };
  console.info(`[LLM Interaction Log] ${JSON.stringify(logEntry)}`);
}

export function buildXaiWebSearchPayload(params: {
  query: string;
  provider: string;
  model: string;
  tookMs: number;
  content: string;
  citations: string[];
  inlineCitations?: XaiWebSearchResponse["inline_citations"];
}): Record<string, unknown> {
  return {
    query: params.query,
    provider: params.provider,
    model: params.model,
    tookMs: params.tookMs,
    externalContent: {
      untrusted: true,
      source: "web_search",
      provider: params.provider,
      wrapped: true,
    },
    content: wrapWebContent(params.content, "web_search"),
    citations: params.citations,
    ...(params.inlineCitations ? { inlineCitations: params.inlineCitations } : {}),
  };
}

export function resolveXaiSearchConfig(searchConfig?: Record<string, unknown>): XaiWebSearchConfig {
  return (
    (isRecord(searchConfig?.grok) ? (searchConfig.grok as XaiWebSearchConfig) : undefined) ?? {}
  );
}

export function resolveXaiWebSearchModel(searchConfig?: Record<string, unknown>): string {
  const config = resolveXaiSearchConfig(searchConfig);
  return typeof config.model === "string" && config.model.trim()
    ? normalizeXaiModelId(config.model.trim())
    : XAI_DEFAULT_WEB_SEARCH_MODEL;
}

export function resolveXaiInlineCitations(searchConfig?: Record<string, unknown>): boolean {
  return resolveXaiSearchConfig(searchConfig).inlineCitations === true;
}

export async function requestXaiWebSearch(params: {
  query: string;
  model: string;
  apiKey: string;
  timeoutSeconds: number;
  inlineCitations: boolean;
}): Promise<XaiWebSearchResult> {
  const sanitizedQuery = sanitizeQuery(params.query);
  validateApprovedModel(params.model);

  const requestTimestamp = new Date().toISOString();
  logLlmInteraction({
    direction: "request",
    model: params.model,
    query: sanitizedQuery,
    timestamp: requestTimestamp,
  });

  return await postTrustedWebToolsJson(
    {
      url: XAI_WEB_SEARCH_ENDPOINT,
      timeoutSeconds: params.timeoutSeconds,
      apiKey: params.apiKey,
      body: buildXaiResponsesToolBody({
        model: params.model,
        inputText: sanitizedQuery,
        tools: [{ type: "web_search" }],
      }),
      errorLabel: "xAI",
    },
    async (response) => {
      const data = (await response.json()) as XaiWebSearchResponse;
      const result = resolveXaiResponseTextCitationsAndInline(data, params.inlineCitations);

      const sanitizedContent = sanitizeLlmResponse(result.content);
      const sanitizedResult: XaiWebSearchResult = {
        ...result,
        content: sanitizedContent,
      };

      const responseTimestamp = new Date().toISOString();
      logLlmInteraction({
        direction: "response",
        model: params.model,
        responseLength: sanitizedContent.length,
        citations: sanitizedResult.citations,
        timestamp: responseTimestamp,
      });

      return sanitizedResult;
    },
  );
}

export const __testing = {
  buildXaiWebSearchPayload,
  extractXaiWebSearchContent,
  resolveXaiInlineCitations,
  resolveXaiSearchConfig,
  resolveXaiWebSearchModel,
  requestXaiWebSearch,
  XAI_DEFAULT_WEB_SEARCH_MODEL,
} as const;