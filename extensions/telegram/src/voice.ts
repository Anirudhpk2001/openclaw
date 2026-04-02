import { isTelegramVoiceCompatibleAudio } from "openclaw/plugin-sdk/media-runtime";

const MAX_CONTENT_TYPE_LENGTH = 256;
const MAX_FILE_NAME_LENGTH = 512;
const SAFE_CONTENT_TYPE_PATTERN = /^[a-zA-Z0-9!#$&\-^_.+\/]+$/;
const SAFE_FILE_NAME_PATTERN = /^[a-zA-Z0-9._\- ]+$/;

function sanitizeContentType(value?: string | null): string | null {
  if (value == null) return null;
  const trimmed = String(value).trim().slice(0, MAX_CONTENT_TYPE_LENGTH);
  if (!SAFE_CONTENT_TYPE_PATTERN.test(trimmed)) {
    return "application/octet-stream";
  }
  return trimmed;
}

function sanitizeFileName(value?: string | null): string | null {
  if (value == null) return null;
  const trimmed = String(value).trim().slice(0, MAX_FILE_NAME_LENGTH);
  if (!SAFE_FILE_NAME_PATTERN.test(trimmed)) {
    return "unknown";
  }
  return trimmed;
}

export function resolveTelegramVoiceDecision(opts: {
  wantsVoice: boolean;
  contentType?: string | null;
  fileName?: string | null;
}): { useVoice: boolean; reason?: string } {
  const sanitizedOpts = {
    wantsVoice: Boolean(opts.wantsVoice),
    contentType: sanitizeContentType(opts.contentType),
    fileName: sanitizeFileName(opts.fileName),
  };

  if (!sanitizedOpts.wantsVoice) {
    return { useVoice: false };
  }
  if (isTelegramVoiceCompatibleAudio(sanitizedOpts)) {
    return { useVoice: true };
  }
  const contentType = sanitizedOpts.contentType ?? "unknown";
  const fileName = sanitizedOpts.fileName ?? "unknown";
  return {
    useVoice: false,
    reason: `media is ${contentType} (${fileName})`,
  };
}

export function resolveTelegramVoiceSend(opts: {
  wantsVoice: boolean;
  contentType?: string | null;
  fileName?: string | null;
  logFallback?: (message: string) => void;
}): { useVoice: boolean } {
  const decision = resolveTelegramVoiceDecision(opts);
  if (decision.reason && opts.logFallback) {
    opts.logFallback(
      `Telegram voice requested but ${decision.reason}; sending as audio file instead.`,
    );
  }
  return { useVoice: decision.useVoice };
}