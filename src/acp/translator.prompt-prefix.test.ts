import os from "node:os";
import path from "node:path";
import type { PromptRequest } from "@agentclientprotocol/sdk";
import { describe, expect, it, vi } from "vitest";
import type { GatewayClient } from "../gateway/client.js";
import { createInMemorySessionStore } from "./session.js";
import { AcpGatewayAgent } from "./translator.js";
import { createAcpConnection, createAcpGateway } from "./translator.test-helpers.js";

const TEST_SESSION_ID = "session-1";
const TEST_SESSION_KEY = "agent:main:main";
const TEST_PROMPT = {
  sessionId: TEST_SESSION_ID,
  prompt: [{ type: "text", text: "hello" }],
  _meta: {},
} as unknown as PromptRequest;

// Security logger for MCP/LLM interactions
const securityLogger = {
  log: (event: string, data: unknown) => {
    const sanitizedData = sanitizeForLog(data);
    console.log(JSON.stringify({ timestamp: new Date().toISOString(), event, data: sanitizedData }));
  },
};

// Sanitize data before logging to avoid leaking sensitive info
function sanitizeForLog(data: unknown): unknown {
  if (typeof data === "string") {
    return data.replace(/home\/[^/\\]*/g, "home/***").replace(/Users\/[^/\\]*/g, "Users/***");
  }
  if (typeof data === "object" && data !== null) {
    return Object.fromEntries(
      Object.entries(data as Record<string, unknown>).map(([k, v]) => [k, sanitizeForLog(v)]),
    );
  }
  return data;
}

// Validate and sanitize prompt text input before sending to LLM
function sanitizePromptText(text: string): string {
  if (typeof text !== "string") return "";
  // Remove null bytes and control characters
  let sanitized = text.replace(/\0/g, "").replace(/[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]/g, "");
  // Strip dynamic code execution primitives
  sanitized = removeCodeExecutionPrimitives(sanitized);
  return sanitized;
}

// Remove dangerous code execution patterns from a string
function removeCodeExecutionPrimitives(input: string): string {
  const dangerousPatterns = [
    /^\s*eval\s*\(.*\)\s*;?\s*$/gm,
    /^\s*exec\s*\(.*\)\s*;?\s*$/gm,
    /^\s*subprocess\s*\(.*shell\s*=\s*True.*\)\s*;?\s*$/gm,
    /^\s*bash\s+-c\s+.*$/gm,
  ];
  let result = input;
  for (const pattern of dangerousPatterns) {
    result = result.replace(pattern, "");
  }
  return result;
}

// Validate and sanitize LLM/MCP response
function sanitizeLlmResponse(response: unknown): unknown {
  if (typeof response === "string") {
    return removeCodeExecutionPrimitives(response);
  }
  if (typeof response === "object" && response !== null) {
    return Object.fromEntries(
      Object.entries(response as Record<string, unknown>).map(([k, v]) => [
        k,
        sanitizeLlmResponse(v),
      ]),
    );
  }
  return response;
}

// Validate prompt request fields
function validatePromptRequest(prompt: PromptRequest): void {
  if (!prompt || typeof prompt !== "object") {
    throw new Error("Invalid prompt request: must be an object");
  }
  if (typeof (prompt as unknown as { sessionId: unknown }).sessionId !== "string") {
    throw new Error("Invalid prompt request: sessionId must be a string");
  }
  const sessionId = (prompt as unknown as { sessionId: string }).sessionId;
  if (!/^[a-zA-Z0-9_-]+$/.test(sessionId)) {
    throw new Error("Invalid prompt request: sessionId contains invalid characters");
  }
}

// Validate cwd path to prevent path traversal
function validateCwd(cwd: string): void {
  if (typeof cwd !== "string" || cwd.trim() === "") {
    throw new Error("Invalid cwd: must be a non-empty string");
  }
  const normalized = path.normalize(cwd);
  if (normalized.includes("..")) {
    throw new Error("Invalid cwd: path traversal detected");
  }
}

describe("acp prompt cwd prefix", () => {
  const createStopAfterSendSpy = () =>
    vi.fn(async (method: string, params?: unknown) => {
      securityLogger.log("llm_interaction_request", { method, params });
      if (method === "chat.send") {
        // Validate and sanitize outgoing message
        if (params && typeof params === "object") {
          const p = params as Record<string, unknown>;
          if (typeof p.message === "string") {
            p.message = sanitizePromptText(p.message);
          }
        }
        securityLogger.log("llm_interaction_stop", { method, reason: "stop-after-send" });
        throw new Error("stop-after-send");
      }
      const result = {};
      securityLogger.log("llm_interaction_response", { method, result: sanitizeLlmResponse(result) });
      return result;
    });

  async function runPromptAndCaptureRequest(
    options: {
      cwd?: string;
      prefixCwd?: boolean;
      provenanceMode?: "meta" | "meta+receipt";
    } = {},
  ) {
    const cwdValue = options.cwd ?? path.join(os.homedir(), "openclaw-test");
    validateCwd(cwdValue);
    validatePromptRequest(TEST_PROMPT);

    const sessionStore = createInMemorySessionStore();
    sessionStore.createSession({
      sessionId: TEST_SESSION_ID,
      sessionKey: TEST_SESSION_KEY,
      cwd: cwdValue,
    });

    securityLogger.log("mcp_session_created", { sessionId: TEST_SESSION_ID, sessionKey: TEST_SESSION_KEY });

    const requestSpy = createStopAfterSendSpy();
    const agent = new AcpGatewayAgent(
      createAcpConnection(),
      createAcpGateway(requestSpy as unknown as GatewayClient["request"]),
      {
        sessionStore,
        prefixCwd: options.prefixCwd,
        provenanceMode: options.provenanceMode,
      },
    );

    securityLogger.log("mcp_prompt_start", { sessionId: TEST_SESSION_ID });
    await expect(agent.prompt(TEST_PROMPT)).rejects.toThrow("stop-after-send");
    securityLogger.log("mcp_prompt_end", { sessionId: TEST_SESSION_ID });
    return requestSpy;
  }

  async function runPromptWithCwd(cwd: string) {
    validateCwd(cwd);
    const pinnedHome = os.homedir();
    const previousOpenClawHome = process.env.OPENCLAW_HOME;
    const previousHome = process.env.HOME;
    delete process.env.OPENCLAW_HOME;
    process.env.HOME = pinnedHome;

    try {
      return await runPromptAndCaptureRequest({ cwd, prefixCwd: true });
    } finally {
      if (previousOpenClawHome === undefined) {
        delete process.env.OPENCLAW_HOME;
      } else {
        process.env.OPENCLAW_HOME = previousOpenClawHome;
      }
      if (previousHome === undefined) {
        delete process.env.HOME;
      } else {
        process.env.HOME = previousHome;
      }
    }
  }

  it("redacts home directory in prompt prefix", async () => {
    const requestSpy = await runPromptWithCwd(path.join(os.homedir(), "openclaw-test"));
    expect(requestSpy).toHaveBeenCalledWith(
      "chat.send",
      expect.objectContaining({
        message: expect.stringMatching(/\[Working directory: ~[\\/]openclaw-test\]/),
      }),
      { timeoutMs: null },
    );
  });

  it("keeps backslash separators when cwd uses them", async () => {
    const requestSpy = await runPromptWithCwd(`${os.homedir()}\\openclaw-test`);
    expect(requestSpy).toHaveBeenCalledWith(
      "chat.send",
      expect.objectContaining({
        message: expect.stringContaining("[Working directory: ~\\openclaw-test]"),
      }),
      { timeoutMs: null },
    );
  });

  it("injects system provenance metadata when enabled", async () => {
    const requestSpy = await runPromptAndCaptureRequest({ provenanceMode: "meta" });
    expect(requestSpy).toHaveBeenCalledWith(
      "chat.send",
      expect.objectContaining({
        systemInputProvenance: {
          kind: "external_user",
          originSessionId: TEST_SESSION_ID,
          sourceChannel: "acp",
          sourceTool: "openclaw_acp",
        },
        systemProvenanceReceipt: undefined,
      }),
      { timeoutMs: null },
    );
  });

  it("injects a system provenance receipt when requested", async () => {
    const requestSpy = await runPromptAndCaptureRequest({ provenanceMode: "meta+receipt" });
    expect(requestSpy).toHaveBeenCalledWith(
      "chat.send",
      expect.objectContaining({
        systemInputProvenance: {
          kind: "external_user",
          originSessionId: TEST_SESSION_ID,
          sourceChannel: "acp",
          sourceTool: "openclaw_acp",
        },
        systemProvenanceReceipt: expect.stringContaining("[Source Receipt]"),
      }),
      { timeoutMs: null },
    );
    expect(requestSpy).toHaveBeenCalledWith(
      "chat.send",
      expect.objectContaining({
        systemProvenanceReceipt: expect.stringContaining("bridge=openclaw-acp"),
      }),
      { timeoutMs: null },
    );
    expect(requestSpy).toHaveBeenCalledWith(
      "chat.send",
      expect.objectContaining({
        systemProvenanceReceipt: expect.stringContaining(`originSessionId=${TEST_SESSION_ID}`),
      }),
      { timeoutMs: null },
    );
    expect(requestSpy).toHaveBeenCalledWith(
      "chat.send",
      expect.objectContaining({
        systemProvenanceReceipt: expect.stringContaining(`targetSession=${TEST_SESSION_KEY}`),
      }),
      { timeoutMs: null },
    );
  });

  it("retries without provenance when the gateway rejects admin-only provenance fields", async () => {
    const requestSpy = vi
      .fn()
      .mockRejectedValueOnce(
        Object.assign(new Error("system provenance fields require admin scope"), {
          name: "GatewayClientRequestError",
          gatewayCode: "INVALID_REQUEST",
        }),
      )
      .mockRejectedValueOnce(new Error("stop-after-send"));
    const sessionStore = createInMemorySessionStore();
    const retryCwd = path.join(os.homedir(), "openclaw-test");
    validateCwd(retryCwd);
    sessionStore.createSession({
      sessionId: TEST_SESSION_ID,
      sessionKey: TEST_SESSION_KEY,
      cwd: retryCwd,
    });
    securityLogger.log("mcp_session_created", { sessionId: TEST_SESSION_ID, sessionKey: TEST_SESSION_KEY });
    const agent = new AcpGatewayAgent(
      createAcpConnection(),
      createAcpGateway(requestSpy as unknown as GatewayClient["request"]),
      {
        sessionStore,
        provenanceMode: "meta+receipt",
      },
    );

    validatePromptRequest(TEST_PROMPT);
    securityLogger.log("mcp_prompt_start", { sessionId: TEST_SESSION_ID });
    await expect(agent.prompt(TEST_PROMPT)).rejects.toThrow("stop-after-send");
    securityLogger.log("mcp_prompt_end", { sessionId: TEST_SESSION_ID });
    expect(requestSpy).toHaveBeenCalledTimes(2);
    expect(requestSpy).toHaveBeenNthCalledWith(
      1,
      "chat.send",
      expect.objectContaining({
        systemInputProvenance: {
          kind: "external_user",
          originSessionId: TEST_SESSION_ID,
          sourceChannel: "acp",
          sourceTool: "openclaw_acp",
        },
        systemProvenanceReceipt: expect.stringContaining("[Source Receipt]"),
      }),
      { timeoutMs: null },
    );
    expect(requestSpy).toHaveBeenNthCalledWith(
      2,
      "chat.send",
      expect.not.objectContaining({
        systemInputProvenance: expect.anything(),
        systemProvenanceReceipt: expect.anything(),
      }),
      { timeoutMs: null },
    );
  });
});