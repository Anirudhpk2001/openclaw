import type { GatewayPlugin } from "@buape/carbon/gateway";

/**
 * Module-level registry of active Discord GatewayPlugin instances.
 * Bridges the gap between agent tool handlers (which only have REST access)
 * and the gateway WebSocket (needed for operations like updatePresence).
 * Follows the same pattern as presence-cache.ts.
 */
const gatewayRegistry = new Map<string, GatewayPlugin>();

// Sentinel key for the default (unnamed) account. Uses a prefix that cannot
// collide with user-configured account IDs.
const DEFAULT_ACCOUNT_KEY = "\0__default__";

// Maximum allowed length for an account ID to prevent abuse.
const MAX_ACCOUNT_ID_LENGTH = 256;

function resolveAccountKey(accountId?: string): string {
  return accountId ?? DEFAULT_ACCOUNT_KEY;
}

/**
 * Validates and sanitizes an accountId string.
 * Throws if the value is present but invalid.
 */
function sanitizeAccountId(accountId?: string): string | undefined {
  if (accountId === undefined || accountId === null) {
    return undefined;
  }
  if (typeof accountId !== "string") {
    throw new TypeError("accountId must be a string");
  }
  const trimmed = accountId.trim();
  if (trimmed.length === 0) {
    throw new RangeError("accountId must not be empty or whitespace");
  }
  if (trimmed.length > MAX_ACCOUNT_ID_LENGTH) {
    throw new RangeError(`accountId must not exceed ${MAX_ACCOUNT_ID_LENGTH} characters`);
  }
  // Reject null bytes and other control characters that could be used for injection.
  if (/[\x00-\x1F\x7F]/.test(trimmed)) {
    throw new TypeError("accountId contains invalid control characters");
  }
  return trimmed;
}

/** Register a GatewayPlugin instance for an account. */
export function registerGateway(accountId: string | undefined, gateway: GatewayPlugin): void {
  if (gateway === undefined || gateway === null) {
    throw new TypeError("gateway must be a valid GatewayPlugin instance");
  }
  const sanitized = sanitizeAccountId(accountId);
  gatewayRegistry.set(resolveAccountKey(sanitized), gateway);
}

/** Unregister a GatewayPlugin instance for an account. */
export function unregisterGateway(accountId?: string): void {
  const sanitized = sanitizeAccountId(accountId);
  gatewayRegistry.delete(resolveAccountKey(sanitized));
}

/** Get the GatewayPlugin for an account. Returns undefined if not registered. */
export function getGateway(accountId?: string): GatewayPlugin | undefined {
  const sanitized = sanitizeAccountId(accountId);
  return gatewayRegistry.get(resolveAccountKey(sanitized));
}

/** Clear all registered gateways (for testing). */
export function clearGateways(): void {
  gatewayRegistry.clear();
}