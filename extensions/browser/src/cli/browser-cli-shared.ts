import { callGatewayFromCli, type GatewayRpcOpts } from "./core-api.js";

export type BrowserParentOpts = GatewayRpcOpts & {
  json?: boolean;
  browserProfile?: string;
};

type BrowserRequestParams = {
  method: "GET" | "POST" | "DELETE";
  path: string;
  query?: Record<string, string | number | boolean | undefined>;
  body?: unknown;
};

const ALLOWED_METHODS = new Set<string>(["GET", "POST", "DELETE"]);
const MAX_PATH_LENGTH = 2048;
const MAX_QUERY_KEY_LENGTH = 256;
const MAX_QUERY_VALUE_LENGTH = 4096;
const MAX_PROFILE_LENGTH = 256;
const MAX_DIMENSION = 32767;
const MIN_DIMENSION = 1;
const MAX_TARGET_ID_LENGTH = 512;

function sanitizeString(value: string, maxLength: number): string {
  return value.slice(0, maxLength).replace(/[\x00-\x1f\x7f]/g, "");
}

function validateMethod(method: string): "GET" | "POST" | "DELETE" {
  if (!ALLOWED_METHODS.has(method)) {
    throw new Error(`Invalid HTTP method: ${method}`);
  }
  return method as "GET" | "POST" | "DELETE";
}

function validatePath(path: string): string {
  if (typeof path !== "string" || path.length === 0) {
    throw new Error("Path must be a non-empty string");
  }
  const sanitized = sanitizeString(path, MAX_PATH_LENGTH);
  if (!/^\/[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=%]*$/.test(sanitized)) {
    throw new Error("Path contains invalid characters");
  }
  return sanitized;
}

function normalizeQuery(query: BrowserRequestParams["query"]): Record<string, string> | undefined {
  if (!query) {
    return undefined;
  }
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined) {
      continue;
    }
    const sanitizedKey = sanitizeString(String(key), MAX_QUERY_KEY_LENGTH);
    const sanitizedValue = sanitizeString(String(value), MAX_QUERY_VALUE_LENGTH);
    if (sanitizedKey.length === 0) {
      continue;
    }
    out[sanitizedKey] = sanitizedValue;
  }
  return Object.keys(out).length ? out : undefined;
}

function validateDimension(value: number, name: string): number {
  if (!Number.isFinite(value) || !Number.isInteger(value)) {
    throw new Error(`${name} must be a finite integer`);
  }
  if (value < MIN_DIMENSION || value > MAX_DIMENSION) {
    throw new Error(`${name} must be between ${MIN_DIMENSION} and ${MAX_DIMENSION}`);
  }
  return value;
}

function validateProfile(profile: string | undefined): string | undefined {
  if (profile === undefined) {
    return undefined;
  }
  if (typeof profile !== "string") {
    throw new Error("Profile must be a string");
  }
  const sanitized = sanitizeString(profile, MAX_PROFILE_LENGTH);
  if (!/^[a-zA-Z0-9\-_.]+$/.test(sanitized)) {
    throw new Error("Profile contains invalid characters");
  }
  return sanitized;
}

export async function callBrowserRequest<T>(
  opts: BrowserParentOpts,
  params: BrowserRequestParams,
  extra?: { timeoutMs?: number; progress?: boolean },
): Promise<T> {
  const validatedMethod = validateMethod(params.method);
  const validatedPath = validatePath(params.path);

  const resolvedTimeoutMs =
    typeof extra?.timeoutMs === "number" && Number.isFinite(extra.timeoutMs)
      ? Math.max(1, Math.floor(extra.timeoutMs))
      : typeof opts.timeout === "string"
        ? Number.parseInt(opts.timeout, 10)
        : undefined;
  const resolvedTimeout =
    typeof resolvedTimeoutMs === "number" && Number.isFinite(resolvedTimeoutMs)
      ? resolvedTimeoutMs
      : undefined;
  const timeout = typeof resolvedTimeout === "number" ? String(resolvedTimeout) : opts.timeout;
  const payload = await callGatewayFromCli(
    "browser.request",
    { ...opts, timeout },
    {
      method: validatedMethod,
      path: validatedPath,
      query: normalizeQuery(params.query),
      body: params.body,
      timeoutMs: resolvedTimeout,
    },
    { progress: extra?.progress },
  );
  if (payload === undefined) {
    throw new Error("Unexpected browser.request response");
  }
  return payload as T;
}

export async function callBrowserResize(
  opts: BrowserParentOpts,
  params: { profile?: string; width: number; height: number; targetId?: string },
  extra?: { timeoutMs?: number },
): Promise<unknown> {
  const validatedProfile = validateProfile(params.profile);
  const validatedWidth = validateDimension(params.width, "width");
  const validatedHeight = validateDimension(params.height, "height");
  const sanitizedTargetId =
    params.targetId?.trim()
      ? sanitizeString(params.targetId.trim(), MAX_TARGET_ID_LENGTH)
      : undefined;

  return callBrowserRequest(
    opts,
    {
      method: "POST",
      path: "/act",
      query: validatedProfile ? { profile: validatedProfile } : undefined,
      body: {
        kind: "resize",
        width: validatedWidth,
        height: validatedHeight,
        targetId: sanitizedTargetId || undefined,
      },
    },
    extra,
  );
}