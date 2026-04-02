import type { SessionAcpIdentity, SessionAcpMeta } from "../../config/sessions/types.js";
import { isSessionIdentityPending, resolveSessionIdentityFromMeta } from "./session-identity.js";

export const ACP_SESSION_IDENTITY_RENDERER_VERSION = "v1";
export type AcpSessionIdentifierRenderMode = "status" | "thread";

type SessionResumeHintResolver = (params: { agentSessionId: string }) => string;

const ACP_AGENT_RESUME_HINT_BY_KEY = new Map<string, SessionResumeHintResolver>([
  [
    "codex",
    ({ agentSessionId }) =>
      `resume in Codex CLI: \`codex resume ${agentSessionId}\` (continues this conversation).`,
  ],
  [
    "openai-codex",
    ({ agentSessionId }) =>
      `resume in Codex CLI: \`codex resume ${agentSessionId}\` (continues this conversation).`,
  ],
  [
    "codex-cli",
    ({ agentSessionId }) =>
      `resume in Codex CLI: \`codex resume ${agentSessionId}\` (continues this conversation).`,
  ],
  [
    "kimi",
    ({ agentSessionId }) =>
      `resume in Kimi CLI: \`kimi resume ${agentSessionId}\` (continues this conversation).`,
  ],
  [
    "moonshot-kimi",
    ({ agentSessionId }) =>
      `resume in Kimi CLI: \`kimi resume ${agentSessionId}\` (continues this conversation).`,
  ],
]);

const MAX_INPUT_LENGTH = 1024;
const SAFE_ID_PATTERN = /^[a-zA-Z0-9_\-.:@]+$/;
const SAFE_BACKEND_PATTERN = /^[a-zA-Z0-9_\- ]+$/;
const SAFE_PATH_PATTERN = /^[^\0]+$/;

function sanitizeId(value: string): string {
  if (value.length > MAX_INPUT_LENGTH) {
    value = value.slice(0, MAX_INPUT_LENGTH);
  }
  if (!SAFE_ID_PATTERN.test(value)) {
    return value.replace(/[^a-zA-Z0-9_\-.:@]/g, "");
  }
  return value;
}

function sanitizeBackend(value: string): string {
  if (value.length > MAX_INPUT_LENGTH) {
    value = value.slice(0, MAX_INPUT_LENGTH);
  }
  if (!SAFE_BACKEND_PATTERN.test(value)) {
    return value.replace(/[^a-zA-Z0-9_\- ]/g, "");
  }
  return value;
}

function sanitizePath(value: string): string {
  if (value.length > MAX_INPUT_LENGTH) {
    value = value.slice(0, MAX_INPUT_LENGTH);
  }
  if (!SAFE_PATH_PATTERN.test(value)) {
    return value.replace(/\0/g, "");
  }
  return value;
}

function normalizeText(value: unknown): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed || undefined;
}

function normalizeAgentHintKey(value: unknown): string | undefined {
  const normalized = normalizeText(value);
  if (!normalized) {
    return undefined;
  }
  return normalized.toLowerCase().replace(/[\s_]+/g, "-");
}

function resolveAcpAgentResumeHintLine(params: {
  agentId?: string;
  agentSessionId?: string;
}): string | undefined {
  const rawAgentSessionId = normalizeText(params.agentSessionId);
  const agentKey = normalizeAgentHintKey(params.agentId);
  if (!rawAgentSessionId || !agentKey) {
    return undefined;
  }
  const agentSessionId = sanitizeId(rawAgentSessionId);
  const resolver = ACP_AGENT_RESUME_HINT_BY_KEY.get(agentKey);
  return resolver ? resolver({ agentSessionId }) : undefined;
}

export function resolveAcpSessionIdentifierLines(params: {
  sessionKey: string;
  meta?: SessionAcpMeta;
}): string[] {
  const rawBackend = normalizeText(params.meta?.backend) ?? "backend";
  const backend = sanitizeBackend(rawBackend);
  const identity = resolveSessionIdentityFromMeta(params.meta);
  return resolveAcpSessionIdentifierLinesFromIdentity({
    backend,
    identity,
    mode: "status",
  });
}

export function resolveAcpSessionIdentifierLinesFromIdentity(params: {
  backend: string;
  identity?: SessionAcpIdentity;
  mode?: AcpSessionIdentifierRenderMode;
}): string[] {
  const rawBackend = normalizeText(params.backend) ?? "backend";
  const backend = sanitizeBackend(rawBackend);
  const mode = params.mode ?? "status";
  const identity = params.identity;
  const rawAgentSessionId = normalizeText(identity?.agentSessionId);
  const rawAcpxSessionId = normalizeText(identity?.acpxSessionId);
  const rawAcpxRecordId = normalizeText(identity?.acpxRecordId);
  const agentSessionId = rawAgentSessionId ? sanitizeId(rawAgentSessionId) : undefined;
  const acpxSessionId = rawAcpxSessionId ? sanitizeId(rawAcpxSessionId) : undefined;
  const acpxRecordId = rawAcpxRecordId ? sanitizeId(rawAcpxRecordId) : undefined;
  const hasIdentifier = Boolean(agentSessionId || acpxSessionId || acpxRecordId);
  if (isSessionIdentityPending(identity) && hasIdentifier) {
    if (mode === "status") {
      return ["session ids: pending (available after the first reply)"];
    }
    return [];
  }
  const lines: string[] = [];
  if (agentSessionId) {
    lines.push(`agent session id: ${agentSessionId}`);
  }
  if (acpxSessionId) {
    lines.push(`${backend} session id: ${acpxSessionId}`);
  }
  if (acpxRecordId) {
    lines.push(`${backend} record id: ${acpxRecordId}`);
  }
  return lines;
}

export function resolveAcpSessionCwd(meta?: SessionAcpMeta): string | undefined {
  const rawRuntimeCwd = normalizeText(meta?.runtimeOptions?.cwd);
  if (rawRuntimeCwd) {
    return sanitizePath(rawRuntimeCwd);
  }
  const rawCwd = normalizeText(meta?.cwd);
  return rawCwd ? sanitizePath(rawCwd) : undefined;
}

export function resolveAcpThreadSessionDetailLines(params: {
  sessionKey: string;
  meta?: SessionAcpMeta;
}): string[] {
  const meta = params.meta;
  const identity = resolveSessionIdentityFromMeta(meta);
  const rawBackend = normalizeText(meta?.backend) ?? "backend";
  const backend = sanitizeBackend(rawBackend);
  const lines = resolveAcpSessionIdentifierLinesFromIdentity({
    backend,
    identity,
    mode: "thread",
  });
  if (lines.length === 0) {
    return lines;
  }
  const hint = resolveAcpAgentResumeHintLine({
    agentId: meta?.agent,
    agentSessionId: identity?.agentSessionId,
  });
  if (hint) {
    lines.push(hint);
  }
  return lines;
}