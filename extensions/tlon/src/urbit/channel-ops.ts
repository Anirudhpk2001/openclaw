import type { LookupFn, SsrFPolicy } from "../../api.js";
import { UrbitHttpError } from "./errors.js";
import { urbitFetch } from "./fetch.js";

// POLICY VIOLATION: Missing authentication on MCP client. You must add authentication to comply with the Authenticate MCP Client policy.

export type UrbitChannelDeps = {
  baseUrl: string;
  cookie: string;
  ship: string;
  channelId: string;
  ssrfPolicy?: SsrFPolicy;
  lookupFn?: LookupFn;
  fetchImpl?: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;
};

function validateAndSanitizeString(value: unknown, fieldName: string): string {
  if (typeof value !== "string") {
    throw new Error(`Invalid input: ${fieldName} must be a string`);
  }
  const sanitized = value.trim();
  if (sanitized.length === 0) {
    throw new Error(`Invalid input: ${fieldName} must not be empty`);
  }
  return sanitized;
}

function validateChannelDeps(deps: UrbitChannelDeps): void {
  validateAndSanitizeString(deps.baseUrl, "baseUrl");
  validateAndSanitizeString(deps.cookie, "cookie");
  validateAndSanitizeString(deps.ship, "ship");
  validateAndSanitizeString(deps.channelId, "channelId");

  try {
    new URL(deps.baseUrl);
  } catch {
    throw new Error("Invalid input: baseUrl must be a valid URL");
  }

  if (!/^[a-z~-][a-z0-9~-]*$/.test(deps.ship)) {
    throw new Error("Invalid input: ship name contains invalid characters");
  }

  if (!/^[a-zA-Z0-9_-]+$/.test(deps.channelId)) {
    throw new Error("Invalid input: channelId contains invalid characters");
  }
}

function sanitizePath(path: string): string {
  const sanitized = validateAndSanitizeString(path, "path");
  if (sanitized.includes("..") || /[<>"'`]/.test(sanitized)) {
    throw new Error("Invalid input: path contains disallowed characters");
  }
  return sanitized;
}

function sanitizeAppName(app: string): string {
  const sanitized = validateAndSanitizeString(app, "app");
  if (!/^[a-zA-Z0-9_-]+$/.test(sanitized)) {
    throw new Error("Invalid input: app name contains invalid characters");
  }
  return sanitized;
}

function sanitizeMarkName(mark: string): string {
  const sanitized = validateAndSanitizeString(mark, "mark");
  if (!/^[a-zA-Z0-9_-]+$/.test(sanitized)) {
    throw new Error("Invalid input: mark name contains invalid characters");
  }
  return sanitized;
}

async function putUrbitChannel(
  deps: UrbitChannelDeps,
  params: { body: unknown; auditContext: string },
) {
  validateChannelDeps(deps);
  validateAndSanitizeString(params.auditContext, "auditContext");

  return await urbitFetch({
    baseUrl: deps.baseUrl,
    path: `/~/channel/${deps.channelId}`,
    init: {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        Cookie: deps.cookie,
      },
      body: JSON.stringify(params.body),
    },
    ssrfPolicy: deps.ssrfPolicy,
    lookupFn: deps.lookupFn,
    fetchImpl: deps.fetchImpl,
    timeoutMs: 30_000,
    auditContext: params.auditContext,
  });
}

export async function pokeUrbitChannel(
  deps: UrbitChannelDeps,
  params: { app: string; mark: string; json: unknown; auditContext: string },
): Promise<number> {
  validateChannelDeps(deps);
  const sanitizedApp = sanitizeAppName(params.app);
  const sanitizedMark = sanitizeMarkName(params.mark);
  validateAndSanitizeString(params.auditContext, "auditContext");

  const pokeId = Date.now();
  const pokeData = {
    id: pokeId,
    action: "poke",
    ship: deps.ship,
    app: sanitizedApp,
    mark: sanitizedMark,
    json: params.json,
  };

  const { response, release } = await putUrbitChannel(deps, {
    body: [pokeData],
    auditContext: params.auditContext,
  });

  try {
    if (!response.ok && response.status !== 204) {
      const errorText = await response.text().catch(() => "");
      throw new Error(`Poke failed: ${response.status}${errorText ? ` - ${errorText}` : ""}`);
    }
    return pokeId;
  } finally {
    await release();
  }
}

export async function scryUrbitPath(
  deps: Pick<UrbitChannelDeps, "baseUrl" | "cookie" | "ssrfPolicy" | "lookupFn" | "fetchImpl">,
  params: { path: string; auditContext: string },
): Promise<unknown> {
  validateAndSanitizeString(deps.baseUrl, "baseUrl");
  validateAndSanitizeString(deps.cookie, "cookie");
  try {
    new URL(deps.baseUrl);
  } catch {
    throw new Error("Invalid input: baseUrl must be a valid URL");
  }

  const sanitizedPath = sanitizePath(params.path);
  validateAndSanitizeString(params.auditContext, "auditContext");

  const scryPath = `/~/scry${sanitizedPath}`;
  const { response, release } = await urbitFetch({
    baseUrl: deps.baseUrl,
    path: scryPath,
    init: {
      method: "GET",
      headers: { Cookie: deps.cookie },
    },
    ssrfPolicy: deps.ssrfPolicy,
    lookupFn: deps.lookupFn,
    fetchImpl: deps.fetchImpl,
    timeoutMs: 30_000,
    auditContext: params.auditContext,
  });

  try {
    if (!response.ok) {
      throw new Error(`Scry failed: ${response.status} for path ${params.path}`);
    }
    return await response.json();
  } finally {
    await release();
  }
}

export async function createUrbitChannel(
  deps: UrbitChannelDeps,
  params: { body: unknown; auditContext: string },
): Promise<void> {
  validateChannelDeps(deps);
  validateAndSanitizeString(params.auditContext, "auditContext");

  const { response, release } = await putUrbitChannel(deps, params);

  try {
    if (!response.ok && response.status !== 204) {
      throw new UrbitHttpError({ operation: "Channel creation", status: response.status });
    }
  } finally {
    await release();
  }
}

export async function wakeUrbitChannel(deps: UrbitChannelDeps): Promise<void> {
  validateChannelDeps(deps);

  const { response, release } = await putUrbitChannel(deps, {
    body: [
      {
        id: Date.now(),
        action: "poke",
        ship: deps.ship,
        app: "hood",
        mark: "helm-hi",
        json: "Opening API channel",
      },
    ],
    auditContext: "tlon-urbit-channel-wake",
  });

  try {
    if (!response.ok && response.status !== 204) {
      throw new UrbitHttpError({ operation: "Channel activation", status: response.status });
    }
  } finally {
    await release();
  }
}

export async function ensureUrbitChannelOpen(
  deps: UrbitChannelDeps,
  params: { createBody: unknown; createAuditContext: string },
): Promise<void> {
  validateChannelDeps(deps);
  validateAndSanitizeString(params.createAuditContext, "createAuditContext");

  await createUrbitChannel(deps, {
    body: params.createBody,
    auditContext: params.createAuditContext,
  });
  await wakeUrbitChannel(deps);
}