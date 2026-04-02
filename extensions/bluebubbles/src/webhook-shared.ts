import { normalizeWebhookPath } from "openclaw/plugin-sdk/webhook-path";
import type { BlueBubblesAccountConfig } from "./types.js";

export { normalizeWebhookPath };

export const DEFAULT_WEBHOOK_PATH = "/bluebubbles-webhook";

const WEBHOOK_PATH_MAX_LENGTH = 256;
const WEBHOOK_PATH_PATTERN = /^\/[a-zA-Z0-9\-._~!$&'()*+,;=:@%/]*$/;

function sanitizeWebhookPath(raw: string): string {
  const trimmed = raw.trim();
  if (trimmed.length > WEBHOOK_PATH_MAX_LENGTH) {
    throw new Error(`Webhook path exceeds maximum allowed length of ${WEBHOOK_PATH_MAX_LENGTH} characters.`);
  }
  if (!WEBHOOK_PATH_PATTERN.test(trimmed)) {
    throw new Error(`Webhook path contains invalid characters: ${trimmed}`);
  }
  // Prevent path traversal
  if (trimmed.includes("..")) {
    throw new Error(`Webhook path must not contain path traversal sequences.`);
  }
  return trimmed;
}

export function resolveWebhookPathFromConfig(config?: BlueBubblesAccountConfig): string {
  const raw = config?.webhookPath?.trim();
  if (raw) {
    const sanitized = sanitizeWebhookPath(raw);
    return normalizeWebhookPath(sanitized);
  }
  return DEFAULT_WEBHOOK_PATH;
}