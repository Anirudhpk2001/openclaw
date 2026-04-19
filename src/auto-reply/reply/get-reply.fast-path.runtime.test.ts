import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { OpenClawConfig } from "../../config/config.js";
import {
  createReplyRuntimeMocks,
  createTempHomeHarness,
  installReplyRuntimeMocks,
  makeEmbeddedTextResult,
  makeReplyConfig,
  resetReplyRuntimeMocks,
} from "../reply.test-harness.js";
import { loadReplyModuleForTest } from "./get-reply.test-loader.js";

let getReplyFromConfig: typeof import("../reply.js").getReplyFromConfig;
const agentMocks = createReplyRuntimeMocks();
const { withTempHome } = createTempHomeHarness({ prefix: "openclaw-getreply-fast-" });

installReplyRuntimeMocks(agentMocks);

const DANGEROUS_PATTERNS = [
  /\beval\s*\(/gi,
  /\bexec\s*\(/gi,
  /\bsubprocess\s*\(/gi,
  /\bshell\s*=\s*True\b/gi,
  /\bnew\s+Function\s*\(/gi,
  /\bsetTimeout\s*\(\s*["'`]/gi,
  /\bsetInterval\s*\(\s*["'`]/gi,
];

function sanitizeInput(input: string): string {
  if (typeof input !== "string") return "";
  // Remove null bytes and control characters
  let sanitized = input.replace(/\0/g, "").replace(/[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]/g, "");
  // Truncate excessively long inputs
  if (sanitized.length > 10000) {
    sanitized = sanitized.slice(0, 10000);
  }
  return sanitized;
}

function sanitizeLLMResponse(response: string): string {
  if (typeof response !== "string") return "";
  const lines = response.split("\n");
  const filtered = lines.filter((line) => {
    return !DANGEROUS_PATTERNS.some((pattern) => {
      pattern.lastIndex = 0;
      return pattern.test(line);
    });
  });
  return filtered.join("\n");
}

function logLLMInteraction(params: { prompt: string; response: string }): void {
  const timestamp = new Date().toISOString();
  console.log(
    JSON.stringify({
      timestamp,
      event: "llm_interaction",
      promptLength: params.prompt.length,
      promptSnippet: params.prompt.slice(0, 100),
      responseLength: params.response.length,
      responseSnippet: params.response.slice(0, 100),
    }),
  );
}

describe("getReplyFromConfig fast-path runtime", () => {
  beforeEach(async () => {
    vi.stubEnv("OPENCLAW_TEST_FAST", "1");
    resetReplyRuntimeMocks(agentMocks);
    ({ getReplyFromConfig } = await loadReplyModuleForTest({ cacheKey: import.meta.url }));
  });

  afterEach(() => {
    vi.clearAllMocks();
    vi.unstubAllEnvs();
  });

  it("keeps old-style runtime tests fast with marked temp-home configs", async () => {
    await withTempHome(async (home) => {
      let seenPrompt: string | undefined;
      agentMocks.runEmbeddedPiAgent.mockImplementation(async (params) => {
        const sanitizedPrompt = sanitizeInput(params.prompt);
        seenPrompt = sanitizedPrompt;
        const rawResult = makeEmbeddedTextResult("ok");
        const rawText = typeof rawResult?.text === "string" ? rawResult.text : "";
        const sanitizedText = sanitizeLLMResponse(rawText);
        logLLMInteraction({ prompt: sanitizedPrompt, response: sanitizedText });
        return { ...rawResult, text: sanitizedText };
      });

      const res = await getReplyFromConfig(
        {
          Body: sanitizeInput("hello"),
          BodyForAgent: sanitizeInput("hello"),
          RawBody: sanitizeInput("hello"),
          CommandBody: sanitizeInput("hello"),
          From: sanitizeInput("+1001"),
          To: sanitizeInput("+2000"),
          MediaPaths: ["/tmp/a.png", "/tmp/b.png"],
          MediaUrls: ["/tmp/a.png", "/tmp/b.png"],
          SessionKey: sanitizeInput("agent:main:whatsapp:+2000"),
          Provider: "whatsapp",
          Surface: "whatsapp",
          ChatType: "direct",
        },
        {},
        makeReplyConfig(home) as OpenClawConfig,
      );

      const rawText = Array.isArray(res) ? res[0]?.text : res?.text;
      const text = typeof rawText === "string" ? sanitizeLLMResponse(rawText) : rawText;
      expect(text).toBe("ok");
      expect(seenPrompt).toContain("[media attached: 2 files]");
      expect(seenPrompt).toContain("hello");
    });
  });
});