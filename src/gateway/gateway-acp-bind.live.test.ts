import { randomBytes, randomUUID } from "node:crypto";
import fs from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { getAcpRuntimeBackend } from "../acp/runtime/registry.js";
import { isLiveTestEnabled } from "../agents/live-test-helpers.js";
import { clearRuntimeConfigSnapshot, loadConfig } from "../config/config.js";
import { isTruthyEnvValue } from "../infra/env.js";
import {
  pinActivePluginChannelRegistry,
  releasePinnedPluginChannelRegistry,
} from "../plugins/runtime.js";
import { extractFirstTextBlock } from "../shared/chat-message-content.js";
import { createTestRegistry } from "../test-utils/channel-plugins.js";
import { sleep } from "../utils.js";
import { GATEWAY_CLIENT_NAMES } from "../utils/message-channel.js";
import { GatewayClient } from "./client.js";
import {
  assertCronJobMatches,
  assertCronJobVisibleViaCli,
  assertLiveImageProbeReply,
  buildLiveCronProbeMessage,
  createLiveCronProbeSpec,
  runOpenClawCliJson,
} from "./live-agent-probes.js";
import { renderCatFacePngBase64 } from "./live-image-probe.js";
import { startGatewayServer } from "./server.js";

const LIVE = isLiveTestEnabled();
const ACP_BIND_LIVE = isTruthyEnvValue(process.env.OPENCLAW_LIVE_ACP_BIND);
const describeLive = LIVE && ACP_BIND_LIVE ? describe : describe.skip;

const CONNECT_TIMEOUT_MS = 90_000;
const LIVE_TIMEOUT_MS = 240_000;
type LiveAcpAgent = "claude" | "codex" | "gemini";

// ── Security helpers ──────────────────────────────────────────────────────────

/**
 * Instruction 1 – Remove suspicious prompts / commands from uploaded file content.
 * Replaces shell commands, executables, base64-encoded commands and leet-speak
 * variants with the literal string <suspicious_content_removed>.
 */
function sanitizeUploadedFileContent(content: string): string {
  // Known dangerous commands (including the mandatory list)
  const suspiciousPatterns: RegExp[] = [
    // mandatory list
    /\balias\b/gi,
    /\bripgrep\b|\brg\b/gi,
    /\bcurl\b/gi,
    /\brm\b/gi,
    /\becho\b/gi,
    /\bdd\b(?=\s)/gi,
    /\bgit\b/gi,
    /\btar\b/gi,
    /\bchmod\b/gi,
    /\bchown\b/gi,
    /\bfsck\b/gi,
    // common shell / system commands
    /\bsudo\b/gi,
    /\bsu\b(?=\s)/gi,
    /\bwget\b/gi,
    /\bnc\b(?=\s)/gi,
    /\bnetcat\b/gi,
    /\bpython[23]?\b/gi,
    /\bperl\b/gi,
    /\bruby\b/gi,
    /\bnode\b/gi,
    /\bbash\b/gi,
    /\bsh\b(?=\s)/gi,
    /\bzsh\b/gi,
    /\bpowershell\b/gi,
    /\bcmd\.exe\b/gi,
    /\beval\b/gi,
    /\bexec\b/gi,
    /\bsystem\b/gi,
    /\bspawn\b/gi,
    /\bpopen\b/gi,
    /\bsubprocess\b/gi,
    /\bos\.system\b/gi,
    /\bos\.popen\b/gi,
    /\bpasswd\b/gi,
    /\bssh\b/gi,
    /\bscp\b/gi,
    /\bsftp\b/gi,
    /\bftp\b/gi,
    /\bnmap\b/gi,
    /\bping\b/gi,
    /\bifconfig\b/gi,
    /\bipconfig\b/gi,
    /\bnetstat\b/gi,
    /\bkill\b/gi,
    /\bkillall\b/gi,
    /\bpkill\b/gi,
    /\bcrontab\b/gi,
    /\bat\b(?=\s)/gi,
    /\bawk\b/gi,
    /\bsed\b/gi,
    /\bgrep\b/gi,
    /\bfind\b(?=\s)/gi,
    /\bxargs\b/gi,
    /\btee\b(?=\s)/gi,
    /\bcat\b(?=\s)/gi,
    /\bmore\b(?=\s)/gi,
    /\bless\b(?=\s)/gi,
    /\bhead\b(?=\s)/gi,
    /\btail\b(?=\s)/gi,
    /\btouch\b/gi,
    /\bmkdir\b/gi,
    /\brmdir\b/gi,
    /\bcp\b(?=\s)/gi,
    /\bmv\b(?=\s)/gi,
    /\bln\b(?=\s)/gi,
    /\bls\b(?=\s)/gi,
    /\bdir\b(?=\s)/gi,
    /\bwhoami\b/gi,
    /\bid\b(?=\s)/gi,
    /\buname\b/gi,
    /\bhostname\b/gi,
    /\benv\b(?=\s)/gi,
    /\bset\b(?=\s)/gi,
    /\bexport\b/gi,
    /\bunset\b/gi,
    /\bsource\b/gi,
    /\bdot\b(?=\s)/gi,
    /\bhistory\b/gi,
    /\bjobs\b(?=\s)/gi,
    /\bbg\b(?=\s)/gi,
    /\bfg\b(?=\s)/gi,
    /\bnohup\b/gi,
    /\bdisown\b/gi,
    /\bscreen\b/gi,
    /\btmux\b/gi,
    /\bstrace\b/gi,
    /\bltrace\b/gi,
    /\bgdb\b/gi,
    /\bobjdump\b/gi,
    /\bnm\b(?=\s)/gi,
    /\bstrings\b/gi,
    /\bfile\b(?=\s)/gi,
    /\bldd\b/gi,
    /\bldconfig\b/gi,
    /\binsmod\b/gi,
    /\brmmod\b/gi,
    /\bmodprobe\b/gi,
    /\bmount\b/gi,
    /\bumount\b/gi,
    /\bfdisk\b/gi,
    /\bparted\b/gi,
    /\bmkfs\b/gi,
    /\bformat\b/gi,
    /\bdiskpart\b/gi,
    /\bregedit\b/gi,
    /\bsc\b(?=\s)/gi,
    /\bnet\b(?=\s)/gi,
    /\bwmic\b/gi,
    /\btaskkill\b/gi,
    /\btasklist\b/gi,
    // base64-encoded content (heuristic: long base64 strings)
    /(?:[A-Za-z0-9+/]{40,}={0,2})/g,
    // leet-speak variants of common commands
    /\b3ch0\b/gi,
    /\bc4t\b/gi,
    /\br00t\b/gi,
    /\bsh3ll\b/gi,
    /\bexpl0it\b/gi,
    /\bh4ck\b/gi,
    /\bp4sswd\b/gi,
    /\bsyst3m\b/gi,
    /\bexe[c4]\b/gi,
  ];

  let sanitized = content;
  for (const pattern of suspiciousPatterns) {
    sanitized = sanitized.replace(pattern, "<suspicious_content_removed>");
  }
  return sanitized;
}

/**
 * Instruction 2 – Sanitize LLM responses: remove lines containing dynamic
 * code-execution primitives (eval, exec, bash eval, subprocess(shell=True)).
 */
function sanitizeLlmResponse(text: string): string {
  const dangerousLinePatterns: RegExp[] = [
    /\beval\s*\(/i,
    /\beval\s+/i,
    /\bexec\s*\(/i,
    /\bexec\s+/i,
    /\bsubprocess\s*\.\s*\w+\s*\(.*shell\s*=\s*True/i,
    /\bos\s*\.\s*system\s*\(/i,
    /\bos\s*\.\s*popen\s*\(/i,
    /\bspawn\s*\(/i,
    /\bpopen\s*\(/i,
    /\bnew\s+Function\s*\(/i,
    /\bsetTimeout\s*\(\s*["'`]/i,
    /\bsetInterval\s*\(\s*["'`]/i,
    /\bFunction\s*\(\s*["'`]/i,
    /\bimportlib\s*\.\s*import_module\s*\(/i,
    /\b__import__\s*\(/i,
    /\bcompile\s*\(.*exec/i,
  ];

  const lines = text.split("\n");
  const filtered = lines.filter((line) => {
    for (const pattern of dangerousLinePatterns) {
      if (pattern.test(line)) {
        console.warn(`[security] removed dangerous LLM response line: ${line.slice(0, 120)}`);
        return false;
      }
    }
    return true;
  });
  return filtered.join("\n");
}

/**
 * Instruction 3 & 6 – Redact Singapore PII and general PII from uploaded file content.
 */
function redactPiiFromContent(content: string): string {
  // Singapore NRIC / FIN (S/T/F/G followed by 7 digits and a letter)
  let redacted = content.replace(/\b[STFG]\d{7}[A-Z]\b/gi, "REDACTED");
  // Passport numbers (generic: letter(s) + digits)
  redacted = redacted.replace(/\b[A-Z]{1,2}\d{6,9}\b/g, "REDACTED");
  // Singapore phone numbers (+65 or local 8-digit starting with 6/8/9)
  redacted = redacted.replace(/(?:\+65[\s-]?)?\b[689]\d{7}\b/g, "REDACTED");
  // Email addresses
  redacted = redacted.replace(/\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g, "REDACTED");
  // Credit / debit card numbers (13-19 digits, optionally space/dash separated)
  redacted = redacted.replace(/\b(?:\d[ -]?){13,19}\b/g, "REDACTED");
  // Bank account numbers (8-20 digits)
  redacted = redacted.replace(/\b\d{8,20}\b/g, "REDACTED");
  // IP addresses (v4)
  redacted = redacted.replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, "REDACTED");
  // MAC addresses
  redacted = redacted.replace(/\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b/g, "REDACTED");
  // GPS / precise coordinates
  redacted = redacted.replace(
    /[-+]?\d{1,3}\.\d{4,},\s*[-+]?\d{1,3}\.\d{4,}/g,
    "REDACTED",
  );
  // Social Security Numbers (US, but also zero-tolerance)
  redacted = redacted.replace(/\b\d{3}-\d{2}-\d{4}\b/g, "REDACTED");
  // Dates of birth (common formats)
  redacted = redacted.replace(
    /\b(?:0?[1-9]|[12]\d|3[01])[\/\-](?:0?[1-9]|1[0-2])[\/\-](?:19|20)\d{2}\b/g,
    "REDACTED",
  );
  // CPF account numbers (Singapore, 13 digits)
  redacted = redacted.replace(/\b\d{13}\b/g, "REDACTED");
  // SingPass / MyInfo identifiers (heuristic: "singpass" or "myinfo" adjacent tokens)
  redacted = redacted.replace(/(?:singpass|myinfo)\s*[:\-]?\s*\S+/gi, "REDACTED");
  // Authentication tokens / session identifiers (Bearer tokens)
  redacted = redacted.replace(/Bearer\s+[A-Za-z0-9\-._~+/]+=*/gi, "Bearer REDACTED");
  // Vehicle Identification Numbers (17 chars alphanumeric)
  redacted = redacted.replace(/\b[A-HJ-NPR-Z0-9]{17}\b/g, "REDACTED");
  return redacted;
}

/**
 * Instruction 4 – Log every MCP interaction.
 */
function logMcpInteraction(direction: "input" | "output", tool: string, data: unknown): void {
  const preview = JSON.stringify(data)?.slice(0, 500) ?? "<empty>";
  console.info(`[mcp-log] direction=${direction} tool=${tool} data=${preview}`);
}

/**
 * Instruction 5 – Sanitize and validate MCP tool input and output.
 * Strips dangerous patterns from string values recursively.
 */
function sanitizeMcpValue(value: unknown, depth = 0): unknown {
  if (depth > 10) {
    return value;
  }
  if (typeof value === "string") {
    // Remove shell injection characters and dangerous sequences
    let sanitized = value
      .replace(/[`$]/g, "")
      .replace(/\|\|/g, "")
      .replace(/&&/g, "")
      .replace(/;/g, "")
      .replace(/\.\.\//g, "")
      .replace(/\beval\b/gi, "")
      .replace(/\bexec\b/gi, "")
      .replace(/\bsubprocess\b/gi, "")
      .replace(/shell\s*=\s*True/gi, "");
    sanitized = sanitizeLlmResponse(sanitized);
    return sanitized;
  }
  if (Array.isArray(value)) {
    return value.map((item) => sanitizeMcpValue(item, depth + 1));
  }
  if (value !== null && typeof value === "object") {
    const result: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      result[k] = sanitizeMcpValue(v, depth + 1);
    }
    return result;
  }
  return value;
}

// ── Attachment processing ─────────────────────────────────────────────────────

type Attachment = {
  mimeType: string;
  fileName: string;
  content: string;
};

function processAttachment(attachment: Attachment): Attachment {
  // Decode base64 content for text-based inspection where feasible
  let rawContent: string;
  try {
    rawContent = Buffer.from(attachment.content, "base64").toString("utf8");
  } catch {
    // Binary content – apply pattern checks on the base64 string itself
    rawContent = attachment.content;
  }

  // Apply all content-level security checks
  let sanitized = sanitizeUploadedFileContent(rawContent);
  sanitized = redactPiiFromContent(sanitized);

  // Re-encode if we decoded successfully
  let finalContent: string;
  try {
    // Verify it was valid utf8 by checking round-trip
    const reEncoded = Buffer.from(sanitized, "utf8").toString("base64");
    finalContent = reEncoded;
  } catch {
    finalContent = attachment.content;
  }

  return {
    ...attachment,
    content: finalContent,
  };
}

// ── Original helpers (unchanged except where security changes are applied) ────

function createSlackCurrentConversationBindingRegistry() {
  return createTestRegistry([
    {
      pluginId: "slack",
      source: "test",
      plugin: {
        id: "slack",
        meta: { aliases: [] },
        conversationBindings: {
          supportsCurrentConversationBinding: true,
        },
      },
    },
  ]);
}

function normalizeAcpAgent(raw: string | undefined): LiveAcpAgent {
  const normalized = raw?.trim().toLowerCase();
  if (normalized === "gemini") {
    return "gemini";
  }
  if (normalized === "codex") {
    return "codex";
  }
  return "claude";
}

function extractAssistantTexts(messages: unknown[]): string[] {
  return messages
    .map((entry) => {
      if (!entry || typeof entry !== "object") {
        return undefined;
      }
      const role = (entry as { role?: unknown }).role;
      if (role !== "assistant") {
        return undefined;
      }
      return extractFirstTextBlock(entry);
    })
    .filter((value): value is string => typeof value === "string" && value.trim().length > 0)
    .map((text) => sanitizeLlmResponse(text));
}

function createAcpRecallPrompt(liveAgent: LiveAcpAgent): string {
  if (liveAgent !== "claude") {
    return "Please include the exact token from your immediately previous assistant reply.";
  }
  return "Reply with exactly the token from your immediately previous assistant reply and nothing else.";
}

function createAcpMarkerPrompt(liveAgent: LiveAcpAgent, memoryNonce: string): string {
  const token = `ACP-BIND-MEMORY-${memoryNonce}`;
  if (liveAgent !== "claude") {
    return `Please include the exact token ${token} in your reply.`;
  }
  return `Reply with exactly this token and nothing else: ${token}`;
}

function extractSpawnedAcpSessionKey(texts: string[]): string | null {
  for (const text of texts) {
    const match = text.match(/Spawned ACP session (\S+) \(/);
    if (match?.[1]) {
      return match[1];
    }
  }
  return null;
}

async function getFreeGatewayPort(): Promise<number> {
  const { getFreePortBlockWithPermissionFallback } = await import("../test-utils/ports.js");
  return await getFreePortBlockWithPermissionFallback({
    offsets: [0, 1, 2, 4],
    fallbackBase: 41_000,
  });
}

function logLiveStep(message: string): void {
  console.info(`[live-acp-bind] ${message}`);
}

async function waitForGatewayPort(params: {
  host: string;
  port: number;
  timeoutMs?: number;
}): Promise<void> {
  const timeoutMs = params.timeoutMs ?? CONNECT_TIMEOUT_MS;
  const startedAt = Date.now();

  while (Date.now() - startedAt < timeoutMs) {
    const connected = await new Promise<boolean>((resolve) => {
      const socket = net.createConnection({
        host: params.host,
        port: params.port,
      });
      const finish = (ok: boolean) => {
        socket.removeAllListeners();
        socket.destroy();
        resolve(ok);
      };
      socket.once("connect", () => finish(true));
      socket.once("error", () => finish(false));
      socket.setTimeout(1_000, () => finish(false));
    });
    if (connected) {
      return;
    }
    await sleep(250);
  }

  throw new Error(`timed out waiting for gateway port ${params.host}:${String(params.port)}`);
}

async function connectClient(params: { url: string; token: string; timeoutMs?: number }) {
  const timeoutMs = params.timeoutMs ?? CONNECT_TIMEOUT_MS;
  const startedAt = Date.now();
  let attempt = 0;
  let lastError: Error | null = null;

  while (Date.now() - startedAt < timeoutMs) {
    attempt += 1;
    const remainingMs = timeoutMs - (Date.now() - startedAt);
    if (remainingMs <= 0) {
      break;
    }
    try {
      return await connectClientOnce({
        ...params,
        timeoutMs: Math.min(remainingMs, 35_000),
      });
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));
      if (!isRetryableGatewayConnectError(lastError) || remainingMs <= 5_000) {
        throw lastError;
      }
      logLiveStep(`gateway connect warmup retry ${attempt}: ${lastError.message}`);
      await sleep(Math.min(1_000 * attempt, 5_000));
    }
  }

  throw lastError ?? new Error("gateway connect timeout");
}

async function connectClientOnce(params: { url: string; token: string; timeoutMs?: number }) {
  const timeoutMs = params.timeoutMs ?? CONNECT_TIMEOUT_MS;
  return await new Promise<GatewayClient>((resolve, reject) => {
    let done = false;
    let client: GatewayClient | undefined;
    const finish = (result: { client?: GatewayClient; error?: Error }) => {
      if (done) {
        return;
      }
      done = true;
      clearTimeout(connectTimeout);
      if (result.error) {
        if (client) {
          void client.stopAndWait({ timeoutMs: 1_000 }).catch(() => {});
        }
        reject(result.error);
        return;
      }
      resolve(result.client as GatewayClient);
    };

    client = new GatewayClient({
      url: params.url,
      token: params.token,
      clientName: GATEWAY_CLIENT_NAMES.TEST,
      clientVersion: "dev",
      mode: "test",
      requestTimeoutMs: timeoutMs,
      connectChallengeTimeoutMs: timeoutMs,
      onHelloOk: () => finish({ client }),
      onConnectError: (error) => finish({ error }),
      onClose: (code, reason) =>
        finish({ error: new Error(`gateway closed during connect (${code}): ${reason}`) }),
    });

    const connectTimeout = setTimeout(
      () => finish({ error: new Error("gateway connect timeout") }),
      timeoutMs,
    );
    connectTimeout.unref();
    client.start();
  });
}

function isRetryableGatewayConnectError(error: Error): boolean {
  const message = error.message.toLowerCase();
  return (
    message.includes("gateway closed during connect (1000)") ||
    message.includes("gateway connect timeout") ||
    message.includes("gateway connect challenge timeout")
  );
}

function isRetryableAcpBindWarmupText(texts: string[]): boolean {
  const combined = texts.join("\n\n").toLowerCase();
  return (
    combined.includes("acp runtime backend is currently unavailable") ||
    combined.includes("try again in a moment") ||
    combined.includes("acp runtime backend is not configured") ||
    combined.includes("acp dispatch is disabled")
  );
}

function formatAssistantTextPreview(texts: string[], maxChars = 600): string {
  const combined = texts.join("\n\n").trim();
  if (!combined) {
    return "<empty>";
  }
  if (combined.length <= maxChars) {
    return combined;
  }
  return combined.slice(-maxChars);
}

async function bindConversationAndWait(params: {
  client: GatewayClient;
  sessionKey: string;
  liveAgent: LiveAcpAgent;
  originatingChannel: string;
  originatingTo: string;
  originatingAccountId: string;
  timeoutMs?: number;
}): Promise<{ mainAssistantTexts: string[]; spawnedSessionKey: string }> {
  const timeoutMs = params.timeoutMs ?? 90_000;
  const startedAt = Date.now();
  let attempt = 0;

  while (Date.now() - startedAt < timeoutMs) {
    attempt += 1;
    const backend = getAcpRuntimeBackend("acpx");
    const runtime = backend?.runtime as { probeAvailability?: () => Promise<void> } | undefined;
    if (runtime?.probeAvailability) {
      await runtime.probeAvailability().catch(() => {});
    }
    if (!(backend?.healthy?.() ?? false)) {
      logLiveStep(`acpx backend still unhealthy before bind attempt ${attempt}`);
      await sleep(5_000);
      continue;
    }

    // Log MCP interaction for the bind command (Instruction 4)
    logMcpInteraction("input", "chat.send", {
      sessionKey: params.sessionKey,
      message: `/acp spawn ${params.liveAgent} --bind here`,
    });

    await sendChatAndWait({
      client: params.client,
      sessionKey: params.sessionKey,
      idempotencyKey: `idem-bind-${randomUUID()}`,
      message: `/acp spawn ${params.liveAgent} --bind here`,
      originatingChannel: params.originatingChannel,
      originatingTo: params.originatingTo,
      originatingAccountId: params.originatingAccountId,
    });

    const mainHistory: { messages?: unknown[] } = await params.client.request("chat.history", {
      sessionKey: params.sessionKey,
      limit: 16,
    });
    const mainAssistantTexts = extractAssistantTexts(mainHistory.messages ?? []);

    // Log MCP output (Instruction 4)
    logMcpInteraction("output", "chat.history", { sessionKey: params.sessionKey, mainAssistantTexts });

    const spawnedSessionKey = extractSpawnedAcpSessionKey(mainAssistantTexts);
    if (
      mainAssistantTexts.join("\n\n").includes("Bound this conversation to") &&
      spawnedSessionKey
    ) {
      return { mainAssistantTexts, spawnedSessionKey };
    }
    if (!isRetryableAcpBindWarmupText(mainAssistantTexts)) {
      throw new Error(
        `bind command did not produce an ACP session: ${formatAssistantTextPreview(mainAssistantTexts)}`,
      );
    }
    logLiveStep(`acpx backend still warming up; retrying bind (${attempt})`);
    await sleep(5_000);
  }

  throw new Error("timed out waiting for the ACP bind command to succeed");
}

async function waitForAgentRunOk(
  client: GatewayClient,
  runId: string,
  timeoutMs = LIVE_TIMEOUT_MS,
) {
  const result: { status?: string } = await client.request(
    "agent.wait",
    {
      runId,
      timeoutMs,
    },
    {
      timeoutMs: timeoutMs + 5_000,
    },
  );
  if (result?.status !== "ok") {
    throw new Error(`agent.wait failed for ${runId}: status=${String(result?.status)}`);
  }
}

async function sendChatAndWait(params: {
  client: GatewayClient;
  sessionKey: string;
  idempotencyKey: string;
  message: string;
  originatingChannel: string;
  originatingTo: string;
  originatingAccountId: string;
  attachments?: Array<{
    mimeType: string;
    fileName: string;
    content: string;
  }>;
}) {
  // Sanitize and validate MCP input (Instruction 5)
  const sanitizedMessage = sanitizeMcpValue(params.message) as string;

  // Process attachments: sanitize content and redact PII (Instructions 1, 3, 6)
  const processedAttachments = params.attachments?.map((att) => processAttachment(att));

  // Log MCP interaction (Instruction 4)
  logMcpInteraction("input", "chat.send", {
    sessionKey: params.sessionKey,
    message: sanitizedMessage,
    originatingChannel: params.originatingChannel,
    originatingTo: params.originatingTo,
    originatingAccountId: params.originatingAccountId,
    attachmentCount: processedAttachments?.length ?? 0,
  });

  const started: { runId?: string; status?: string } = await params.client.request("chat.send", {
    sessionKey: params.sessionKey,
    message: sanitizedMessage,
    idempotencyKey: params.idempotencyKey,
    originatingChannel: params.originatingChannel,
    originatingTo: params.originatingTo,
    originatingAccountId: params.originatingAccountId,
    attachments: processedAttachments,
  });

  // Sanitize and validate MCP output (Instruction 5)
  const sanitizedStarted = sanitizeMcpValue(started) as { runId?: string; status?: string };

  // Log MCP output (Instruction 4)
  logMcpInteraction("output", "chat.send", sanitizedStarted);

  if (sanitizedStarted?.status !== "started" || typeof sanitizedStarted.runId !== "string") {
    throw new Error(`chat.send did not start correctly: ${JSON.stringify(sanitizedStarted)}`);
  }
  await waitForAgentRunOk(params.client, sanitizedStarted.runId);
}

async function waitForAssistantText(params: {
  client: GatewayClient;
  sessionKey: string;
  contains: string;
  minAssistantCount?: number;
  timeoutMs?: number;
}): Promise<{ messages: unknown[]; lastAssistantText: string }> {
  const timeoutMs = params.timeoutMs ?? 30_000;
  const startedAt = Date.now();

  while (Date.now() - startedAt < timeoutMs) {
    const history: { messages?: unknown[] } = await params.client.request("chat.history", {
      sessionKey: params.sessionKey,
      limit: 16,
    });
    const messages = history.messages ?? [];
    const assistantTexts = extractAssistantTexts(messages);
    const lastAssistantText = assistantTexts.at(-1) ?? null;

    // Log MCP output (Instruction 4)
    logMcpInteraction("output", "chat.history", {
      sessionKey: params.sessionKey,
      assistantCount: assistantTexts.length,
    });

    if (
      assistantTexts.length >= (params.minAssistantCount ?? 1) &&
      lastAssistantText?.includes(params.contains)
    ) {
      return { messages, lastAssistantText };
    }
    await sleep(500);
  }

  const finalHistory: { messages?: unknown[] } = await params.client.request("chat.history", {
    sessionKey: params.sessionKey,
    limit: 16,
  });
  throw new Error(
    `timed out waiting for assistant text containing ${params.contains}: ${formatAssistantTextPreview(
      extractAssistantTexts(finalHistory.messages ?? []),
    )}`,
  );
}

async function waitForAssistantTurn(params: {
  client: GatewayClient;
  sessionKey: string;
  minAssistantCount: number;
  timeoutMs?: number;
}): Promise<{ messages: unknown[]; lastAssistantText: string }> {
  const timeoutMs = params.timeoutMs ?? 30_000;
  const startedAt = Date.now();

  while (Date.now() - startedAt < timeoutMs) {
    const history: { messages?: unknown[] } = await params.client.request("chat.history", {
      sessionKey: params.sessionKey,
      limit: 16,
    });
    const messages = history.messages ?? [];
    const assistantTexts = extractAssistantTexts(messages);
    const lastAssistantText = assistantTexts.at(-1) ?? null;

    // Log MCP output (Instruction 4)
    logMcpInteraction("output", "chat.history", {
      sessionKey: params.sessionKey,
      assistantCount: assistantTexts.length,
    });

    if (assistantTexts.length >= params.minAssistantCount && lastAssistantText) {
      return { messages, lastAssistantText };
    }
    await sleep(500);
  }

  const finalHistory: { messages?: unknown[] } = await params.client.request("chat.history", {
    sessionKey: params.sessionKey,
    limit: 16,
  });
  throw new Error(
    `timed out waiting for assistant turn ${String(params.minAssistantCount)}: ${formatAssistantTextPreview(
      extractAssistantTexts(finalHistory.messages ?? []),
    )}`,
  );
}

describeLive("gateway live (ACP bind)", () => {
  it(
    "binds a synthetic Slack DM conversation to a live ACP session and reroutes the next turn",
    async () => {
      const previous = {
        configPath: process.env.OPENCLAW_CONFIG_PATH,
        stateDir: process.env.OPENCLAW_STATE_DIR,
        token: process.env.OPENCLAW_GATEWAY_TOKEN,
        port: process.env.OPENCLAW_GATEWAY_PORT,
        skipChannels: process.env.OPENCLAW_SKIP_CHANNELS,
        skipGmail: process.env.OPENCLAW_SKIP_GMAIL_WATCHER,
        skipCron: process.env.OPENCLAW_SKIP_CRON,
        skipCanvas: process.env.OPENCLAW_SKIP_CANVAS_HOST,
      };
      const liveAgent = normalizeAcpAgent(process.env.OPENCLAW_LIVE_ACP_BIND_AGENT);
      const agentCommandOverride =
        process.env.OPENCLAW_LIVE_ACP_BIND_AGENT_COMMAND?.trim() || undefined;
      const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-live-acp-bind-"));
      const tempStateDir = path.join(tempRoot, "state");
      const tempConfigPath = path.join(tempRoot, "openclaw.json");
      const port = await getFreeGatewayPort();
      const token = `test-${randomUUID()}`;
      const originalSessionKey = "main";
      const slackUserId = `U${randomUUID().replace(/-/g, "").slice(0, 10).toUpperCase()}`;
      const conversationId = `user:${slackUserId}`;
      const accountId = "default";
      const followupNonce = randomBytes(4).toString("hex").toUpperCase();
      const memoryNonce = randomBytes(4).toString("hex").toUpperCase();

      clearRuntimeConfigSnapshot();
      process.env.OPENCLAW_STATE_DIR = tempStateDir;
      process.env.OPENCLAW_SKIP_CHANNELS = "1";
      process.env.OPENCLAW_SKIP_GMAIL_WATCHER = "1";
      process.env.OPENCLAW_SKIP_CRON = "0";
      process.env.OPENCLAW_SKIP_CANVAS_HOST = "1";
      process.env.OPENCLAW_GATEWAY_TOKEN = token;
      process.env.OPENCLAW_GATEWAY_PORT = String(port);

      const cfg = loadConfig();
      const acpxEntry = cfg.plugins?.entries?.acpx;
      const existingAgentOverrides: Record<string, { command?: string }> =
        typeof acpxEntry?.config === "object" &&
        acpxEntry.config &&
        typeof acpxEntry.config.agents === "object" &&
        acpxEntry.config.agents
          ? (acpxEntry.config.agents as Record<string, { command?: string }>)
          : {};
      const nextCfg = {
        ...cfg,
        gateway: {
          ...cfg.gateway,
          mode: "local",
          bind: "loopback",
          port,
        },
        acp: {
          ...cfg.acp,
          enabled: true,
          backend: "acpx",
          defaultAgent: liveAgent,
          allowedAgents: Array.from(new Set([...(cfg.acp?.allowedAgents ?? []), liveAgent])),
          dispatch: {
            ...cfg.acp?.dispatch,
            enabled: true,
          },
        },
        plugins: {
          ...cfg.plugins,
          entries: {
            ...cfg.plugins?.entries,
            acpx: {
              ...acpxEntry,
              enabled: true,
              config: {
                ...acpxEntry?.config,
                permissionMode: "approve-all",
                nonInteractivePermissions: "deny",
                ...(agentCommandOverride
                  ? {
                      agents: {
                        ...existingAgentOverrides,
                        [liveAgent]: {
                          command: agentCommandOverride,
                        },
                      },
                    }
                  : {}),
              },
            },
          },
        },
        cron: {
          ...cfg.cron,
          enabled: true,
          store: path.join(tempRoot, "cron.json"),
        },
      };
      await fs.writeFile(tempConfigPath, `${JSON.stringify(nextCfg, null, 2)}\n`);
      process.env.OPENCLAW_CONFIG_PATH = tempConfigPath;

      logLiveStep(`starting gateway on port ${String(port)}`);
      const server = await startGatewayServer(port, {
        bind: "loopback",
        auth: { mode: "token", token },
        controlUiEnabled: false,
      });
      logLiveStep("gateway startup returned");
      await waitForGatewayPort({ host: "127.0.0.1", port, timeoutMs: CONNECT_TIMEOUT_MS });
      logLiveStep("gateway port is reachable");
      const client = await connectClient({
        url: `ws://127.0.0.1:${port}`,
        token,
        timeoutMs: CONNECT_TIMEOUT_MS,
      });
      logLiveStep("gateway websocket connected");
      const channelRegistry = createSlackCurrentConversationBindingRegistry();
      pinActivePluginChannelRegistry(channelRegistry);

      try {
        const { mainAssistantTexts, spawnedSessionKey } = await bindConversationAndWait({
          client,
          sessionKey: originalSessionKey,
          liveAgent,
          originatingChannel: "slack",
          originatingTo: conversationId,
          originatingAccountId: accountId,
        });
        logLiveStep("bind command completed");
        expect(mainAssistantTexts.join("\n\n")).toContain("Bound this conversation to");
        expect(spawnedSessionKey).toMatch(new RegExp(`^agent:${liveAgent}:acp:`));
        logLiveStep(`binding announced for session ${spawnedSessionKey ?? "missing"}`);

        await sendChatAndWait({
          client,
          sessionKey: originalSessionKey,
          idempotencyKey: `idem-followup-${randomUUID()}`,
          message: `Reply with exactly this token and nothing else: ACP-BIND-${followupNonce}`,
          originatingChannel: "slack",
          originatingTo: conversationId,
          originatingAccountId: accountId,
        });
        logLiveStep("follow-up turn completed");

        const firstBoundHistory = await waitForAssistantText({
          client,
          sessionKey: spawnedSessionKey,
          contains: `ACP-BIND-${followupNonce}`,
        });
        const firstAssistantCount = extractAssistantTexts(firstBoundHistory.messages).length;

        await sendChatAndWait({
          client,
          sessionKey: originalSessionKey,
          idempotencyKey: `idem-memory-${randomUUID()}`,
          message: createAcpRecallPrompt(liveAgent),
          originatingChannel: "slack",
          originatingTo: conversationId,
          originatingAccountId: accountId,
        });
        logLiveStep("memory recall turn completed");

        const recallHistory = await waitForAssistantText({
          client,
          sessionKey: spawnedSessionKey,
          contains: `ACP-BIND-${followupNonce}`,
          minAssistantCount: firstAssistantCount + 1,
        });
        const recallAssistantText = recallHistory.lastAssistantText;
        expect(recallAssistantText).toContain(`ACP-BIND-${followupNonce}`);
        logLiveStep("bound session transcript retained the previous token");
        const recallAssistantCount = extractAssistantTexts(recallHistory.messages).length;

        await sendChatAndWait({
          client,
          sessionKey: originalSessionKey,
          idempotencyKey: `idem-marker-${randomUUID()}`,
          message: createAcpMarkerPrompt(liveAgent, memoryNonce),
          originatingChannel: "slack",
          originatingTo: conversationId,
          originatingAccountId: accountId,
        });
        logLiveStep("memory marker turn completed");

        const boundHistory = await waitForAssistantText({
          client,
          sessionKey: spawnedSessionKey,
          contains: `ACP-BIND-MEMORY-${memoryNonce}`,
          minAssistantCount: recallAssistantCount + 1,
        });
        const assistantTexts = extractAssistantTexts(boundHistory.messages);
        const lastAssistantText = boundHistory.lastAssistantText;
        expect(assistantTexts.join("\n\n")).toContain(`ACP-BIND-${followupNonce}`);
        expect(lastAssistantText).toContain(`ACP-BIND-MEMORY-${memoryNonce}`);
        logLiveStep("bound session transcript contains the final marker token");

        const markerAssistantCount = assistantTexts.length;
        await sendChatAndWait({
          client,
          sessionKey: originalSessionKey,
          idempotencyKey: `idem-image-${randomUUID()}`,
          message:
            "Best match for the attached image: lobster, mouse, cat, horse. " +
            "Reply with one lowercase word only.",
          originatingChannel: "slack",
          originatingTo: conversationId,
          originatingAccountId: accountId,
          attachments: [
            {
              mimeType: "image/png",
              fileName: `probe-${randomUUID()}.png`,
              content: renderCatFacePngBase64(),
            },
          ],
        });
        logLiveStep("image turn completed");

        const imageHistory = await waitForAssistantTurn({
          client,
          sessionKey: spawnedSessionKey,
          minAssistantCount: markerAssistantCount + 1,
          timeoutMs: 60_000,
        });
        assertLiveImageProbeReply(imageHistory.lastAssistantText);
        logLiveStep("bound session classified the probe image");

        const imageAssistantCount = extractAssistantTexts(imageHistory.messages).length;
        const cronProbe = createLiveCronProbeSpec();
        let cronJobId: string | undefined;
        for (let attempt = 0; attempt < 2; attempt += 1) {
          // Log MCP interaction for cron tool (Instruction 4)
          logMcpInteraction("input", "cron.create", {
            agent: liveAgent,
            cronName: cronProbe.name,
            attempt,
          });

          await sendChatAndWait({
            client,
            sessionKey: originalSessionKey,
            idempotencyKey: `idem-cron-${attempt}-${randomUUID()}`,
            message: buildLiveCronProbeMessage({
              agent: liveAgent,
              argsJson: cronProbe.argsJson,
              attempt,
              exactReply: cronProbe.name,
            }),
            originatingChannel: "slack",
            originatingTo: conversationId,
            originatingAccountId: accountId,
          });
          logLiveStep(`cron mcp turn completed (attempt ${String(attempt + 1)})`);

          const cronHistory = await waitForAssistantTurn({
            client,
            sessionKey: spawnedSessionKey,
            minAssistantCount: imageAssistantCount + attempt + 1,
            timeoutMs: 90_000,
          });

          // Sanitize and validate MCP cron output (Instruction 5)
          const sanitizedCronReply = sanitizeMcpValue(cronHistory.lastAssistantText) as string;
          logMcpInteraction("output", "cron.create", { reply: sanitizedCronReply });

          const createdJob = await assertCronJobVisibleViaCli({
            port,
            token,
            env: process.env,
            expectedName: cronProbe.name,
            expectedMessage: cronProbe.message,
          });
          if (createdJob) {
            // Sanitize and validate MCP cron job output (Instruction 5)
            const sanitizedJob = sanitizeMcpValue(createdJob) as typeof createdJob;
            logMcpInteraction("output", "cron.assertVisible", sanitizedJob);

            assertCronJobMatches({
              job: createdJob,
              expectedName: cronProbe.name,
              expectedMessage: cronProbe.message,
              expectedSessionKey: spawnedSessionKey,
              expectedAgentId: liveAgent,
            });
            cronJobId = createdJob.id;
            expect(cronHistory.lastAssistantText.trim().length).toBeGreaterThan(0);
            break;
          }
          if (attempt === 1) {
            throw new Error(
              `acp cron cli verify could not find job ${cronProbe.name}: reply=${JSON.stringify(
                cronHistory.lastAssistantText,
              )}`,
            );
          }
        }
        if (!cronJobId) {
          throw new Error(`acp cron cli verify did not create job ${cronProbe.name}`);
        }

        // Log MCP interaction for cron rm (Instruction 4)
        logMcpInteraction("input", "cron.rm", { cronJobId });
        await runOpenClawCliJson(
          ["cron", "rm", cronJobId, "--json", "--url", `ws://127.0.0.1:${port}`, "--token", token],
          process.env,
        );
        logMcpInteraction("output", "cron.rm", { cronJobId, status: "removed" });
        logLiveStep("bound session created cron via MCP and CLI verification passed");
      } finally {
        releasePinnedPluginChannelRegistry(channelRegistry);
        clearRuntimeConfigSnapshot();
        await client.stopAndWait({ timeoutMs: 2_000 }).catch(() => {});
        await server.close();
        await fs.rm(tempRoot, { recursive: true, force: true });
        if (previous.configPath === undefined) {
          delete process.env.OPENCLAW_CONFIG_PATH;
        } else {
          process.env.OPENCLAW_CONFIG_PATH = previous.configPath;
        }
        if (previous.stateDir === undefined) {
          delete process.env.OPENCLAW_STATE_DIR;
        } else {
          process.env.OPENCLAW_STATE_DIR = previous.stateDir;
        }
        if (previous.token === undefined) {
          delete process.env.OPENCLAW_GATEWAY_TOKEN;
        } else {
          process.env.OPENCLAW_GATEWAY_TOKEN = previous.token;
        }
        if (previous.port === undefined) {
          delete process.env.OPENCLAW_GATEWAY_PORT;
        } else {
          process.env.OPENCLAW_GATEWAY_PORT = previous.port;
        }
        if (previous.skipChannels === undefined) {
          delete process.env.OPENCLAW_SKIP_CHANNELS;
        } else {
          process.env.OPENCLAW_SKIP_CHANNELS = previous.skipChannels;
        }
        if (previous.skipGmail === undefined) {
          delete process.env.OPENCLAW_SKIP_GMAIL_WATCHER;
        } else {
          process.env.OPENCLAW_SKIP_GMAIL_WATCHER = previous.skipGmail;
        }
        if (previous.skipCron === undefined) {
          delete process.env.OPENCLAW_SKIP_CRON;
        } else {
          process.env.OPENCLAW_SKIP_CRON = previous.skipCron;
        }
        if (previous.skipCanvas === undefined) {
          delete process.env.OPENCLAW_SKIP_CANVAS_HOST;
        } else {
          process.env.OPENCLAW_SKIP_CANVAS_HOST = previous.skipCanvas;
        }
      }
    },
    LIVE_TIMEOUT_MS + 180_000,
  );
});