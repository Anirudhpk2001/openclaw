/**
 * Shared Gemini authentication utilities.
 *
 * Supports both traditional API keys and OAuth JSON format.
 */

/**
 * Validate and sanitize a string to ensure it contains no dangerous characters.
 */
function sanitizeHeaderValue(value: string): string {
  // Remove any carriage returns, newlines, or null bytes that could enable header injection
  return value.replace(/[\r\n\0]/g, "");
}

/**
 * Validate that an API key is a non-empty string within acceptable length bounds.
 */
function validateApiKey(apiKey: unknown): string {
  if (typeof apiKey !== "string") {
    throw new Error("API key must be a string");
  }
  const trimmed = apiKey.trim();
  if (trimmed.length === 0) {
    throw new Error("API key must not be empty");
  }
  if (trimmed.length > 4096) {
    throw new Error("API key exceeds maximum allowed length");
  }
  return trimmed;
}

/**
 * Parse Gemini API key and return appropriate auth headers.
 *
 * OAuth format: `{"token": "...", "projectId": "..."}`
 *
 * @param apiKey - Either a traditional API key string or OAuth JSON
 * @returns Headers object with appropriate authentication
 */
export function parseGeminiAuth(apiKey: string): { headers: Record<string, string> } {
  const validatedKey = validateApiKey(apiKey);

  // Try parsing as OAuth JSON format
  if (validatedKey.startsWith("{")) {
    try {
      const parsed = JSON.parse(validatedKey) as { token?: string; projectId?: string };
      if (typeof parsed.token === "string" && parsed.token) {
        const sanitizedToken = sanitizeHeaderValue(parsed.token);
        if (sanitizedToken.length === 0) {
          throw new Error("OAuth token is invalid after sanitization");
        }
        return {
          headers: {
            Authorization: `Bearer ${sanitizedToken}`,
            "Content-Type": "application/json",
          },
        };
      }
    } catch (err) {
      if ((err as Error).message === "OAuth token is invalid after sanitization") {
        throw err;
      }
      // Parse failed, fallback to API key mode
    }
  }

  // Default: traditional API key
  const sanitizedKey = sanitizeHeaderValue(validatedKey);
  if (sanitizedKey.length === 0) {
    throw new Error("API key is invalid after sanitization");
  }

  return {
    headers: {
      "x-goog-api-key": sanitizedKey,
      "Content-Type": "application/json",
    },
  };
}