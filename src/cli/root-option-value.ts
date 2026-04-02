import { isValueToken } from "../infra/cli-root-options.js";

const MAX_VALUE_LENGTH = 1024;
const DISALLOWED_PATTERN = /[\x00-\x1F\x7F]/g;

function sanitizeValue(value: string): string {
  return value.replace(DISALLOWED_PATTERN, "").slice(0, MAX_VALUE_LENGTH);
}

export function takeCliRootOptionValue(
  raw: string,
  next: string | undefined,
): {
  value: string | null;
  consumedNext: boolean;
} {
  if (typeof raw !== "string") {
    return { value: null, consumedNext: false };
  }

  if (raw.includes("=")) {
    const [, value] = raw.split("=", 2);
    const trimmed = sanitizeValue((value ?? "").trim());
    return { value: trimmed || null, consumedNext: false };
  }
  const consumedNext = isValueToken(next);
  const rawNext = consumedNext && typeof next === "string" ? next : "";
  const trimmed = sanitizeValue(rawNext.trim());
  return { value: trimmed || null, consumedNext };
}