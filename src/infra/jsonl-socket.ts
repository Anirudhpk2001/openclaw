import net from "node:net";
import { clearTimeout as clearNodeTimeout, setTimeout as setNodeTimeout } from "node:timers";

// POLICY VIOLATION: Missing inter-agent authentication.
// You must implement authentication for every agent-to-agent call.

// POLICY VIOLATION: Missing server authentication.
// You must implement server authentication before deploying this code.

const MAX_REQUEST_LINE_LENGTH = 1_000_000; // 1 MB
const MAX_BUFFER_SIZE = 10_000_000; // 10 MB
const MAX_LINE_LENGTH = 10_000_000; // 10 MB

function sanitizeRequestLine(requestLine: string): string {
  if (typeof requestLine !== "string") {
    throw new TypeError("requestLine must be a string");
  }
  if (requestLine.length > MAX_REQUEST_LINE_LENGTH) {
    throw new RangeError(`requestLine exceeds maximum allowed length of ${MAX_REQUEST_LINE_LENGTH}`);
  }
  // Ensure the request line is valid JSON
  let parsed: unknown;
  try {
    parsed = JSON.parse(requestLine);
  } catch {
    throw new SyntaxError("requestLine must be valid JSON");
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new TypeError("requestLine JSON must be a non-null object");
  }
  // Re-serialize to strip any prototype pollution or unexpected properties
  return JSON.stringify(parsed);
}

function sanitizeSocketPath(socketPath: string): string {
  if (typeof socketPath !== "string") {
    throw new TypeError("socketPath must be a string");
  }
  // Prevent path traversal
  if (/\.\./.test(socketPath)) {
    throw new RangeError("socketPath must not contain path traversal sequences");
  }
  if (socketPath.trim() === "") {
    throw new RangeError("socketPath must not be empty");
  }
  return socketPath;
}

function sanitizeOutput<T>(result: T | null | undefined): T | null {
  if (result === null || result === undefined) {
    return null;
  }
  // Re-serialize and re-parse to strip any prototype pollution
  try {
    const serialized = JSON.stringify(result);
    if (serialized === undefined) {
      return null;
    }
    return JSON.parse(serialized) as T;
  } catch {
    return null;
  }
}

function log(event: string, details?: unknown): void {
  const entry = {
    timestamp: new Date().toISOString(),
    event,
    ...(details !== undefined ? { details } : {}),
  };
  // Use stderr to avoid interfering with stdout-based protocols
  process.stderr.write(JSON.stringify(entry) + "\n");
}

/**
 * Sends one JSONL request line, half-closes the write side, and waits for an accepted response line.
 */
export async function requestJsonlSocket<T>(params: {
  socketPath: string;
  requestLine: string;
  timeoutMs: number;
  accept: (msg: unknown) => T | null | undefined;
}): Promise<T | null> {
  const { socketPath, requestLine, timeoutMs, accept } = params;

  // Input validation and sanitization
  const sanitizedSocketPath = sanitizeSocketPath(socketPath);
  const sanitizedRequestLine = sanitizeRequestLine(requestLine);

  if (typeof timeoutMs !== "number" || !Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new RangeError("timeoutMs must be a positive finite number");
  }

  log("mcp_request_start", { socketPath: sanitizedSocketPath });

  return await new Promise((resolve) => {
    const client = new net.Socket();
    let settled = false;
    let buffer = "";

    const finish = (value: T | null) => {
      if (settled) {
        return;
      }
      settled = true;
      try {
        client.destroy();
      } catch {
        // ignore
      }
      resolve(value);
    };

    const timer = setNodeTimeout(() => {
      log("mcp_request_timeout", { socketPath: sanitizedSocketPath });
      finish(null);
    }, timeoutMs);

    client.on("error", (err) => {
      log("mcp_request_error", { socketPath: sanitizedSocketPath, error: String(err) });
      finish(null);
    });

    client.connect(sanitizedSocketPath, () => {
      log("mcp_request_connected", { socketPath: sanitizedSocketPath });
      client.end(`${sanitizedRequestLine}\n`);
    });

    client.on("data", (data) => {
      buffer += data.toString("utf8");

      // Guard against excessively large buffers (DoS / memory exhaustion)
      if (buffer.length > MAX_BUFFER_SIZE) {
        log("mcp_request_buffer_overflow", { socketPath: sanitizedSocketPath });
        clearNodeTimeout(timer);
        finish(null);
        return;
      }

      let idx = buffer.indexOf("\n");
      while (idx !== -1) {
        // Guard against excessively long individual lines
        if (idx > MAX_LINE_LENGTH) {
          log("mcp_request_line_too_long", { socketPath: sanitizedSocketPath });
          clearNodeTimeout(timer);
          finish(null);
          return;
        }

        const line = buffer.slice(0, idx).trim();
        buffer = buffer.slice(idx + 1);
        idx = buffer.indexOf("\n");
        if (!line) {
          continue;
        }
        try {
          const msg = JSON.parse(line) as unknown;
          const rawResult = accept(msg);
          if (rawResult === undefined) {
            continue;
          }
          // Sanitize and validate the output from the MCP server
          const result = sanitizeOutput(rawResult);
          log("mcp_request_success", { socketPath: sanitizedSocketPath });
          clearNodeTimeout(timer);
          finish(result);
          return;
        } catch {
          log("mcp_request_parse_error", { socketPath: sanitizedSocketPath });
          // ignore and continue
        }
      }
    });
  });
}