import type { NodeListNode, PairedNode, PairingList, PendingRequest } from "./node-list-types.js";

const MAX_STRING_LENGTH = 1024;
const MAX_ARRAY_LENGTH = 1000;

function sanitizeString(value: unknown): string {
  if (typeof value !== "string") return "";
  return value.slice(0, MAX_STRING_LENGTH).replace(/[<>"'`]/g, "");
}

function sanitizeRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return {};
  const obj = value as Record<string, unknown>;
  const sanitized: Record<string, unknown> = {};
  for (const key of Object.keys(obj).slice(0, 100)) {
    const sanitizedKey = sanitizeString(key);
    if (sanitizedKey) {
      sanitized[sanitizedKey] = obj[key];
    }
  }
  return sanitized;
}

function asRecord(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? sanitizeRecord(value)
    : {};
}

function sanitizePendingRequest(value: unknown): PendingRequest {
  const obj = asRecord(value);
  const sanitized: Record<string, unknown> = {};
  for (const key of Object.keys(obj)) {
    const v = obj[key];
    sanitized[key] = typeof v === "string" ? sanitizeString(v) : v;
  }
  return sanitized as PendingRequest;
}

function sanitizePairedNode(value: unknown): PairedNode {
  const obj = asRecord(value);
  const sanitized: Record<string, unknown> = {};
  for (const key of Object.keys(obj)) {
    const v = obj[key];
    sanitized[key] = typeof v === "string" ? sanitizeString(v) : v;
  }
  return sanitized as PairedNode;
}

function sanitizeNodeListNode(value: unknown): NodeListNode {
  const obj = asRecord(value);
  const sanitized: Record<string, unknown> = {};
  for (const key of Object.keys(obj)) {
    const v = obj[key];
    sanitized[key] = typeof v === "string" ? sanitizeString(v) : v;
  }
  return sanitized as NodeListNode;
}

export function parsePairingList(value: unknown): PairingList {
  if (typeof value !== "object" || value === null) {
    return { pending: [], paired: [] };
  }
  const obj = asRecord(value);
  const rawPending = Array.isArray(obj.pending) ? obj.pending : [];
  const rawPaired = Array.isArray(obj.paired) ? obj.paired : [];
  const pending: PendingRequest[] = rawPending
    .slice(0, MAX_ARRAY_LENGTH)
    .map((item) => sanitizePendingRequest(item));
  const paired: PairedNode[] = rawPaired
    .slice(0, MAX_ARRAY_LENGTH)
    .map((item) => sanitizePairedNode(item));
  return { pending, paired };
}

export function parseNodeList(value: unknown): NodeListNode[] {
  if (typeof value !== "object" || value === null) {
    return [];
  }
  const obj = asRecord(value);
  if (!Array.isArray(obj.nodes)) return [];
  return obj.nodes
    .slice(0, MAX_ARRAY_LENGTH)
    .map((item) => sanitizeNodeListNode(item));
}