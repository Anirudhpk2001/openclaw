import type { GatewayClient } from "../gateway/client.js";
import { readBool, readString } from "./meta.js";
import type { AcpServerOptions } from "./types.js";

const logger = {
  info: (msg: string, data?: unknown) => console.log(JSON.stringify({ level: "info", msg, data, ts: new Date().toISOString() })),
  warn: (msg: string, data?: unknown) => console.warn(JSON.stringify({ level: "warn", msg, data, ts: new Date().toISOString() })),
  error: (msg: string, data?: unknown) => console.error(JSON.stringify({ level: "error", msg, data, ts: new Date().toISOString() })),
};

const SESSION_KEY_PATTERN = /^[a-zA-Z0-9_\-]{1,256}$/;
const SESSION_LABEL_PATTERN = /^[a-zA-Z0-9_\-\s]{1,256}$/;

function sanitizeString(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  const trimmed = value.trim();
  if (trimmed.length === 0) return undefined;
  return trimmed;
}

function validateSessionKey(key: string | undefined): string | undefined {
  if (key === undefined) return undefined;
  const sanitized = sanitizeString(key);
  if (!sanitized) return undefined;
  if (!SESSION_KEY_PATTERN.test(sanitized)) {
    logger.warn("Invalid session key format rejected", { keyLength: sanitized.length });
    throw new Error("Invalid session key format");
  }
  return sanitized;
}

function validateSessionLabel(label: string | undefined): string | undefined {
  if (label === undefined) return undefined;
  const sanitized = sanitizeString(label);
  if (!sanitized) return undefined;
  if (!SESSION_LABEL_PATTERN.test(sanitized)) {
    logger.warn("Invalid session label format rejected", { labelLength: sanitized.length });
    throw new Error("Invalid session label format");
  }
  return sanitized;
}

function sanitizeResolvedKey(key: unknown): string {
  if (typeof key !== "string" || key.trim().length === 0) {
    throw new Error("Invalid resolved session key returned from gateway");
  }
  const trimmed = key.trim();
  if (!SESSION_KEY_PATTERN.test(trimmed)) {
    logger.warn("Resolved session key failed validation", {});
    throw new Error("Resolved session key has invalid format");
  }
  return trimmed;
}

export type AcpSessionMeta = {
  sessionKey?: string;
  sessionLabel?: string;
  resetSession?: boolean;
  requireExisting?: boolean;
  prefixCwd?: boolean;
};

export function parseSessionMeta(meta: unknown): AcpSessionMeta {
  logger.info("parseSessionMeta called", { metaType: typeof meta });
  if (!meta || typeof meta !== "object") {
    return {};
  }
  const record = meta as Record<string, unknown>;
  let sessionKey: string | undefined;
  let sessionLabel: string | undefined;
  try {
    sessionKey = validateSessionKey(readString(record, ["sessionKey", "session", "key"]));
    sessionLabel = validateSessionLabel(readString(record, ["sessionLabel", "label"]));
  } catch (err) {
    logger.error("Session meta validation failed", { error: String(err) });
    throw err;
  }
  const result = {
    sessionKey,
    sessionLabel,
    resetSession: readBool(record, ["resetSession", "reset"]),
    requireExisting: readBool(record, ["requireExistingSession", "requireExisting"]),
    prefixCwd: readBool(record, ["prefixCwd"]),
  };
  logger.info("parseSessionMeta result", { hasSessionKey: !!result.sessionKey, hasSessionLabel: !!result.sessionLabel, resetSession: result.resetSession, requireExisting: result.requireExisting });
  return result;
}

export async function resolveSessionKey(params: {
  meta: AcpSessionMeta;
  fallbackKey: string;
  gateway: GatewayClient;
  opts: AcpServerOptions;
}): Promise<string> {
  logger.info("resolveSessionKey called", { hasMetaSessionKey: !!params.meta.sessionKey, hasMetaSessionLabel: !!params.meta.sessionLabel });

  let requestedLabel: string | undefined;
  let requestedKey: string | undefined;
  try {
    requestedLabel = validateSessionLabel(params.meta.sessionLabel ?? params.opts.defaultSessionLabel);
    requestedKey = validateSessionKey(params.meta.sessionKey ?? params.opts.defaultSessionKey);
  } catch (err) {
    logger.error("resolveSessionKey input validation failed", { error: String(err) });
    throw err;
  }

  const requireExisting =
    params.meta.requireExisting ?? params.opts.requireExistingSession ?? false;

  if (params.meta.sessionLabel) {
    logger.info("Resolving session by meta label");
    const resolved = await params.gateway.request<{ ok: true; key: string }>("sessions.resolve", {
      label: validateSessionLabel(params.meta.sessionLabel),
    });
    if (!resolved?.key) {
      logger.warn("Unable to resolve session label", {});
      throw new Error(`Unable to resolve session label`);
    }
    const resolvedKey = sanitizeResolvedKey(resolved.key);
    logger.info("Session resolved by meta label", { resolvedKeyLength: resolvedKey.length });
    return resolvedKey;
  }

  if (params.meta.sessionKey) {
    const validatedMetaKey = validateSessionKey(params.meta.sessionKey)!;
    if (!requireExisting) {
      logger.info("Using meta session key directly");
      return validatedMetaKey;
    }
    logger.info("Resolving session by meta key with requireExisting");
    const resolved = await params.gateway.request<{ ok: true; key: string }>("sessions.resolve", {
      key: validatedMetaKey,
    });
    if (!resolved?.key) {
      logger.warn("Session key not found", {});
      throw new Error(`Session key not found`);
    }
    const resolvedKey = sanitizeResolvedKey(resolved.key);
    logger.info("Session resolved by meta key", { resolvedKeyLength: resolvedKey.length });
    return resolvedKey;
  }

  if (requestedLabel) {
    logger.info("Resolving session by opts label");
    const resolved = await params.gateway.request<{ ok: true; key: string }>("sessions.resolve", {
      label: requestedLabel,
    });
    if (!resolved?.key) {
      logger.warn("Unable to resolve opts session label", {});
      throw new Error(`Unable to resolve session label`);
    }
    const resolvedKey = sanitizeResolvedKey(resolved.key);
    logger.info("Session resolved by opts label", { resolvedKeyLength: resolvedKey.length });
    return resolvedKey;
  }

  if (requestedKey) {
    if (!requireExisting) {
      logger.info("Using opts session key directly");
      return requestedKey;
    }
    logger.info("Resolving session by opts key with requireExisting");
    const resolved = await params.gateway.request<{ ok: true; key: string }>("sessions.resolve", {
      key: requestedKey,
    });
    if (!resolved?.key) {
      logger.warn("Opts session key not found", {});
      throw new Error(`Session key not found`);
    }
    const resolvedKey = sanitizeResolvedKey(resolved.key);
    logger.info("Session resolved by opts key", { resolvedKeyLength: resolvedKey.length });
    return resolvedKey;
  }

  logger.info("Using fallback session key");
  const validatedFallback = validateSessionKey(params.fallbackKey);
  if (!validatedFallback) {
    logger.error("Fallback session key is invalid", {});
    throw new Error("Fallback session key is invalid");
  }
  return validatedFallback;
}

export async function resetSessionIfNeeded(params: {
  meta: AcpSessionMeta;
  sessionKey: string;
  gateway: GatewayClient;
  opts: AcpServerOptions;
}): Promise<void> {
  logger.info("resetSessionIfNeeded called", { hasSessionKey: !!params.sessionKey });
  const resetSession = params.meta.resetSession ?? params.opts.resetSession ?? false;
  if (!resetSession) {
    logger.info("Session reset not required");
    return;
  }
  let validatedKey: string | undefined;
  try {
    validatedKey = validateSessionKey(params.sessionKey);
  } catch (err) {
    logger.error("resetSessionIfNeeded session key validation failed", { error: String(err) });
    throw err;
  }
  if (!validatedKey) {
    logger.error("resetSessionIfNeeded received empty session key", {});
    throw new Error("Session key is required for reset");
  }
  logger.info("Resetting session");
  await params.gateway.request("sessions.reset", { key: validatedKey });
  logger.info("Session reset completed");
}