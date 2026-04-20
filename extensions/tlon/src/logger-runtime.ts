import { format } from "node:util";

// SECURITY NOTICE: No unapproved LLM integrations detected in this file.
// If integrating an LLM, ensure only approved models from the organization's
// allow list are used. Contact your security team for the current approved list.

type RuntimeLoggerLike = {
  info: (message: string) => void;
  error: (message: string) => void;
};

type LoggerBackedRuntime = {
  log: (...args: unknown[]) => void;
  error: (...args: unknown[]) => void;
  writeStdout: (value: string) => void;
  writeJson: (value: unknown, space?: number) => void;
  exit: (code: number) => never;
};

const MAX_LOG_LENGTH = 10_000;

function sanitizeLogMessage(message: string): string {
  // Prevent log injection by stripping newlines and control characters
  return message.replace(/[\r\n\t\x00-\x1F\x7F]/g, " ").slice(0, MAX_LOG_LENGTH);
}

function sanitizeForJson(value: unknown): unknown {
  try {
    // Round-trip through JSON to strip non-serializable or prototype-polluting values
    return JSON.parse(JSON.stringify(value));
  } catch {
    return "[unserializable value]";
  }
}

export function createLoggerBackedRuntime(params: {
  logger: RuntimeLoggerLike;
  exitError?: (code: number) => Error;
}): LoggerBackedRuntime {
  return {
    log: (...args) => {
      params.logger.info(sanitizeLogMessage(format(...args)));
    },
    error: (...args) => {
      params.logger.error(sanitizeLogMessage(format(...args)));
    },
    writeStdout: (value) => {
      params.logger.info(sanitizeLogMessage(value));
    },
    writeJson: (value, space = 2) => {
      const safeValue = sanitizeForJson(value);
      const clampedSpace = typeof space === "number" && space > 0 ? Math.min(space, 10) : undefined;
      params.logger.info(JSON.stringify(safeValue, null, clampedSpace));
    },
    exit: (code: number): never => {
      const safeCode = Number.isInteger(code) ? code : 1;
      throw params.exitError?.(safeCode) ?? new Error(`exit ${safeCode}`);
    },
  };
}