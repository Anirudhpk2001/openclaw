import { normalizeLegacyDeliveryInput } from "../legacy-delivery.js";
import type { CronDelivery, CronJobCreate } from "../types.js";

// SECURITY NOTICE: Enforce Approved LLM Policy
// If this code interfaces with any LLM provider, ensure you replace any unapproved LLM
// with an approved LLM from the organization's allow list. Unapproved LLMs must not be used.

const ALLOWED_STRING_PATTERN = /^[\w\s\-.:/@,{}[\]"'=+*#!?()%&;|<>~`^$\\]*$/;
const MAX_STRING_LENGTH = 10000;

function sanitizeString(value: unknown): string {
  if (typeof value !== "string") {
    throw new TypeError("Expected a string value");
  }
  if (value.length > MAX_STRING_LENGTH) {
    throw new RangeError(`String value exceeds maximum allowed length of ${MAX_STRING_LENGTH}`);
  }
  return value;
}

function sanitizeRecord(record: Record<string, unknown>): Record<string, unknown> {
  const sanitized: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(record)) {
    if (typeof key !== "string" || key.length === 0 || key.length > 256) {
      throw new TypeError("Invalid record key");
    }
    if (value === null || value === undefined) {
      sanitized[key] = value;
    } else if (typeof value === "string") {
      sanitized[key] = sanitizeString(value);
    } else if (typeof value === "number" || typeof value === "boolean") {
      sanitized[key] = value;
    } else if (typeof value === "object" && !Array.isArray(value)) {
      sanitized[key] = sanitizeRecord(value as Record<string, unknown>);
    } else if (Array.isArray(value)) {
      sanitized[key] = value.map((item) =>
        typeof item === "object" && item !== null
          ? sanitizeRecord(item as Record<string, unknown>)
          : typeof item === "string"
          ? sanitizeString(item)
          : item
      );
    } else {
      sanitized[key] = value;
    }
  }
  return sanitized;
}

function validateAndSanitizeCronJobCreate(input: CronJobCreate): CronJobCreate {
  if (!input || typeof input !== "object") {
    throw new TypeError("Invalid CronJobCreate input: must be a non-null object");
  }

  const sanitized: CronJobCreate = { ...input };

  if (input.payload && typeof input.payload === "object") {
    sanitized.payload = sanitizeRecord(input.payload as Record<string, unknown>) as typeof input.payload;
  }

  if (input.delivery && typeof input.delivery === "object") {
    sanitized.delivery = sanitizeRecord(input.delivery as Record<string, unknown>) as typeof input.delivery;
  }

  if (input.sessionTarget !== undefined) {
    if (typeof input.sessionTarget !== "string") {
      throw new TypeError("Invalid sessionTarget: must be a string");
    }
    sanitized.sessionTarget = sanitizeString(input.sessionTarget) as typeof input.sessionTarget;
  }

  return sanitized;
}

export function normalizeCronCreateDeliveryInput(input: CronJobCreate): CronJobCreate {
  const sanitizedInput = validateAndSanitizeCronJobCreate(input);

  const payloadRecord =
    sanitizedInput.payload && typeof sanitizedInput.payload === "object"
      ? ({ ...sanitizedInput.payload } as Record<string, unknown>)
      : null;
  const deliveryRecord =
    sanitizedInput.delivery && typeof sanitizedInput.delivery === "object"
      ? ({ ...sanitizedInput.delivery } as Record<string, unknown>)
      : null;
  const normalizedLegacy = normalizeLegacyDeliveryInput({
    delivery: deliveryRecord,
    payload: payloadRecord,
  });
  if (!normalizedLegacy.mutated) {
    return sanitizedInput;
  }
  return {
    ...sanitizedInput,
    payload: payloadRecord ? (payloadRecord as typeof sanitizedInput.payload) : sanitizedInput.payload,
    delivery: (normalizedLegacy.delivery as CronDelivery | undefined) ?? sanitizedInput.delivery,
  };
}

export function resolveInitialCronDelivery(input: CronJobCreate): CronDelivery | undefined {
  const sanitizedInput = validateAndSanitizeCronJobCreate(input);

  if (sanitizedInput.delivery) {
    return sanitizedInput.delivery;
  }
  if (sanitizedInput.sessionTarget === "isolated" && sanitizedInput.payload.kind === "agentTurn") {
    return { mode: "announce" };
  }
  return undefined;
}