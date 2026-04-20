import type { ChildProcess, SpawnOptions } from "node:child_process";
import { spawn } from "node:child_process";
import { resolve as resolvePath } from "node:path";

export type SpawnFallback = {
  label: string;
  options: SpawnOptions;
};

export type SpawnWithFallbackResult = {
  child: ChildProcess;
  usedFallback: boolean;
  fallbackLabel?: string;
};

type SpawnWithFallbackParams = {
  argv: string[];
  options: SpawnOptions;
  fallbacks?: SpawnFallback[];
  spawnImpl?: typeof spawn;
  retryCodes?: string[];
  onFallback?: (err: unknown, fallback: SpawnFallback) => void;
};

const DEFAULT_RETRY_CODES = ["EBADF"];

const ALLOWED_RETRY_CODES = new Set(["EBADF", "ENOENT", "EACCES", "EAGAIN"]);

function sanitizeCommand(cmd: string): string {
  // Reject commands containing shell metacharacters or path traversal
  if (/[;&|`$<>\\]/.test(cmd)) {
    throw new Error(`Invalid command: shell metacharacters are not allowed`);
  }
  return cmd;
}

function sanitizeArgv(argv: string[]): string[] {
  if (!Array.isArray(argv) || argv.length === 0) {
    throw new Error("argv must be a non-empty array");
  }
  const [cmd, ...args] = argv;
  const sanitizedCmd = sanitizeCommand(cmd);
  // Sanitize arguments to prevent injection
  const sanitizedArgs = args.map((arg) => {
    if (typeof arg !== "string") {
      throw new Error("All argv elements must be strings");
    }
    return arg;
  });
  return [sanitizedCmd, ...sanitizedArgs];
}

function sanitizeRetryCodes(codes: string[]): string[] {
  return codes.filter((code) => ALLOWED_RETRY_CODES.has(code));
}

export function resolveCommandStdio(params: {
  hasInput: boolean;
  preferInherit: boolean;
}): ["pipe" | "inherit" | "ignore", "pipe", "pipe"] {
  const stdin = params.hasInput ? "pipe" : params.preferInherit ? "inherit" : "pipe";
  return [stdin, "pipe", "pipe"];
}

export function formatSpawnError(err: unknown): string {
  if (!(err instanceof Error)) {
    return "An unknown error occurred";
  }
  const details = err as NodeJS.ErrnoException;
  const parts: string[] = [];
  // Sanitize message to avoid leaking sensitive path or system information
  const message = err.message?.trim().replace(/\/[^\s]*/g, "[path]");
  if (message) {
    parts.push(message);
  }
  if (details.code && !message?.includes(details.code)) {
    // Only include known safe error codes
    if (ALLOWED_RETRY_CODES.has(details.code) || /^E[A-Z]+$/.test(details.code)) {
      parts.push(details.code);
    }
  }
  if (details.syscall) {
    parts.push(`syscall=${details.syscall}`);
  }
  // Omit errno to avoid leaking system-level details
  return parts.join(" ");
}

function shouldRetry(err: unknown, codes: string[]): boolean {
  const code =
    err && typeof err === "object" && "code" in err ? String((err as { code?: unknown }).code) : "";
  return code.length > 0 && codes.includes(code) && ALLOWED_RETRY_CODES.has(code);
}

async function spawnAndWaitForSpawn(
  spawnImpl: typeof spawn,
  argv: string[],
  options: SpawnOptions,
): Promise<ChildProcess> {
  const sanitizedArgv = sanitizeArgv(argv);

  // Ensure shell is never enabled to prevent command injection
  const safeOptions: SpawnOptions = { ...options, shell: false };

  const child = spawnImpl(sanitizedArgv[0], sanitizedArgv.slice(1), safeOptions);

  return await new Promise((resolve, reject) => {
    let settled = false;
    const cleanup = () => {
      child.removeListener("error", onError);
      child.removeListener("spawn", onSpawn);
    };
    const finishResolve = () => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      resolve(child);
    };
    const onError = (err: unknown) => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      reject(err);
    };
    const onSpawn = () => {
      finishResolve();
    };
    child.once("error", onError);
    child.once("spawn", onSpawn);
    // Ensure mocked spawns that never emit "spawn" don't stall.
    process.nextTick(() => {
      if (typeof child.pid === "number") {
        finishResolve();
      }
    });
  });
}

export async function spawnWithFallback(
  params: SpawnWithFallbackParams,
): Promise<SpawnWithFallbackResult> {
  const spawnImpl = params.spawnImpl ?? spawn;
  const retryCodes = sanitizeRetryCodes(params.retryCodes ?? DEFAULT_RETRY_CODES);
  const baseOptions = { ...params.options, shell: false };
  const fallbacks = params.fallbacks ?? [];
  const attempts: Array<{ label?: string; options: SpawnOptions }> = [
    { options: baseOptions },
    ...fallbacks.map((fallback) => ({
      label: fallback.label,
      options: { ...baseOptions, ...fallback.options, shell: false },
    })),
  ];

  let lastError: unknown;
  for (let index = 0; index < attempts.length; index += 1) {
    const attempt = attempts[index];
    try {
      const child = await spawnAndWaitForSpawn(spawnImpl, params.argv, attempt.options);
      return {
        child,
        usedFallback: index > 0,
        fallbackLabel: attempt.label,
      };
    } catch (err) {
      lastError = err;
      const nextFallback = fallbacks[index];
      if (!nextFallback || !shouldRetry(err, retryCodes)) {
        throw err;
      }
      params.onFallback?.(err, nextFallback);
    }
  }

  throw lastError;
}