import { execFile, type ExecFileOptions } from "node:child_process";
import { promisify } from "node:util";
import { resolveSystemBin } from "../infra/resolve-system-bin.js";
import { normalizeLowercaseStringOrEmpty } from "../shared/string-coerce.js";
import {
  MEDIA_FFMPEG_MAX_BUFFER_BYTES,
  MEDIA_FFMPEG_TIMEOUT_MS,
  MEDIA_FFPROBE_TIMEOUT_MS,
} from "./ffmpeg-limits.js";

const execFileAsync = promisify(execFile);

export type MediaExecOptions = {
  timeoutMs?: number;
  maxBufferBytes?: number;
};

function resolveExecOptions(
  defaultTimeoutMs: number,
  options: MediaExecOptions | undefined,
): ExecFileOptions {
  return {
    timeout: options?.timeoutMs ?? defaultTimeoutMs,
    maxBuffer: options?.maxBufferBytes ?? MEDIA_FFMPEG_MAX_BUFFER_BYTES,
  };
}

function requireSystemBin(name: string): string {
  const resolved = resolveSystemBin(name, { trust: "standard" });
  if (!resolved) {
    const hint =
      process.platform === "darwin"
        ? "e.g. brew install ffmpeg"
        : "e.g. apt install ffmpeg / dnf install ffmpeg";
    throw new Error(
      `${name} not found in trusted system directories. ` +
        `Install it via your system package manager (${hint}).`,
    );
  }
  return resolved;
}

const ALLOWED_ARG_PATTERN = /^[a-zA-Z0-9_./:=,+\-@%\s]+$/;
const MAX_ARG_LENGTH = 4096;
const MAX_ARGS_COUNT = 64;

function sanitizeArgs(args: string[]): string[] {
  if (!Array.isArray(args)) {
    throw new Error("Arguments must be an array.");
  }
  if (args.length > MAX_ARGS_COUNT) {
    throw new Error(`Too many arguments: maximum allowed is ${MAX_ARGS_COUNT}.`);
  }
  return args.map((arg, index) => {
    if (typeof arg !== "string") {
      throw new Error(`Argument at index ${index} must be a string.`);
    }
    if (arg.length > MAX_ARG_LENGTH) {
      throw new Error(`Argument at index ${index} exceeds maximum length of ${MAX_ARG_LENGTH}.`);
    }
    if (!ALLOWED_ARG_PATTERN.test(arg)) {
      throw new Error(
        `Argument at index ${index} contains disallowed characters.`,
      );
    }
    return arg;
  });
}

export async function runFfprobe(args: string[], options?: MediaExecOptions): Promise<string> {
  const sanitized = sanitizeArgs(args);
  const { stdout } = await execFileAsync(
    requireSystemBin("ffprobe"),
    sanitized,
    resolveExecOptions(MEDIA_FFPROBE_TIMEOUT_MS, options),
  );
  return stdout.toString();
}

export async function runFfmpeg(args: string[], options?: MediaExecOptions): Promise<string> {
  const sanitized = sanitizeArgs(args);
  const { stdout } = await execFileAsync(
    requireSystemBin("ffmpeg"),
    sanitized,
    resolveExecOptions(MEDIA_FFMPEG_TIMEOUT_MS, options),
  );
  return stdout.toString();
}

export function parseFfprobeCsvFields(stdout: string, maxFields: number): string[] {
  return stdout
    .trim()
    .split(/[,\r\n]+/, maxFields)
    .map((field) => normalizeLowercaseStringOrEmpty(field));
}

export function parseFfprobeCodecAndSampleRate(stdout: string): {
  codec: string | null;
  sampleRateHz: number | null;
} {
  const [codecRaw, sampleRateRaw] = parseFfprobeCsvFields(stdout, 2);
  const codec = codecRaw ? codecRaw : null;
  const sampleRate = sampleRateRaw ? Number.parseInt(sampleRateRaw, 10) : Number.NaN;
  return {
    codec,
    sampleRateHz: Number.isFinite(sampleRate) ? sampleRate : null,
  };
}