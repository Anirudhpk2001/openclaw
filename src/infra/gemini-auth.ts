/**
 * Shared Gemini authentication utilities.
 *
 * Supports both traditional API keys and OAuth JSON format.
 *
 * ⚠️ SECURITY NOTICE: Gemini is currently on the organization's blocked LLM list.
 * You must replace Gemini with an approved LLM from the allow list.
 * Please contact your security team for the list of approved LLM providers.
 */

/**
 * Parse Gemini API key and return appropriate auth headers.
 *
 * OAuth format: `{"token": "...", "projectId": "..."}`
 *
 * @param apiKey - Either a traditional API key string or OAuth JSON
 * @returns Headers object with appropriate authentication
 */

/**
 * Validates and sanitizes an API key string.
 * @param apiKey - The API key to validate
 * @returns The sanitized API key
 * @throws Error if the API key is invalid
 */
function validateAndSanitizeApiKey(apiKey: string): string {
  if (typeof apiKey !== "string") {
    throw new Error("API key must be a string.");
  }

  const trimmed = apiKey.trim();

  if (!trimmed || trimmed.length === 0) {
    throw new Error("API key must not be empty.");
  }

  if (trimmed.length > 8192) {
    throw new Error("API key exceeds maximum allowed length.");
  }

  // Reject any null bytes or control characters
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(trimmed)) {
    throw new Error("API key contains invalid characters.");
  }

  return trimmed;
}

/**
 * Validates and sanitizes an OAuth token string.
 * @param token - The token to validate
 * @returns The sanitized token
 * @throws Error if the token is invalid
 */
function validateAndSanitizeToken(token: string): string {
  if (typeof token !== "string") {
    throw new Error("OAuth token must be a string.");
  }

  const trimmed = token.trim();

  if (!trimmed || trimmed.length === 0) {
    throw new Error("OAuth token must not be empty.");
  }

  if (trimmed.length > 8192) {
    throw new Error("OAuth token exceeds maximum allowed length.");
  }

  // Reject any null bytes or control characters
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(trimmed)) {
    throw new Error("OAuth token contains invalid characters.");
  }

  return trimmed;
}

export function parseGeminiAuth(apiKey: string): { headers: Record<string, string> } {
  // ⚠️ WARNING: Gemini is on the organization's blocked LLM list.
  // Replace this integration with an approved LLM from the allow list before deploying.
  console.warn(
    "[SECURITY POLICY] Gemini is on the organization's blocked LLM list. " +
    "Replace it with an approved LLM from the allow list."
  );

  // Validate and sanitize the raw input
  const sanitizedKey = validateAndSanitizeApiKey(apiKey);

  // Try parsing as OAuth JSON format
  if (sanitizedKey.startsWith("{")) {
    try {
      const parsed = JSON.parse(sanitizedKey) as { token?: string; projectId?: string };
      if (typeof parsed.token === "string" && parsed.token) {
        const sanitizedToken = validateAndSanitizeToken(parsed.token);
        return {
          headers: {
            Authorization: `Bearer ${sanitizedToken}`,
            "Content-Type": "application/json",
          },
        };
      }
    } catch {
      // Parse failed, fallback to API key mode
    }
  }

  // Default: traditional API key
  return {
    headers: {
      "x-goog-api-key": sanitizedKey,
      "Content-Type": "application/json",
    },
  };
}