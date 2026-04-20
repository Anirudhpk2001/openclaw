import type { SessionEntry } from "../../config/sessions/types.js";
import { setAbortMemory } from "./abort-primitives.js";
import path from "path";

let sessionStoreRuntimePromise: Promise<
  typeof import("../../config/sessions/store.runtime.js")
> | null = null;

function loadSessionStoreRuntime() {
  sessionStoreRuntimePromise ??= import("../../config/sessions/store.runtime.js");
  return sessionStoreRuntimePromise;
}

function sanitizeForOutput(value: string): string {
  return value.replace(/[<>&"'`]/g, (char) => {
    const escapeMap: Record<string, string> = {
      "<": "&lt;",
      ">": "&gt;",
      "&": "&amp;",
      '"': "&quot;",
      "'": "&#x27;",
      "`": "&#x60;",
    };
    return escapeMap[char] ?? char;
  });
}

function validateStorePath(storePath: string): string {
  const normalized = path.normalize(storePath);
  if (normalized.includes("..")) {
    throw new Error("Invalid store path: path traversal detected");
  }
  return normalized;
}

function validateSessionKey(sessionKey: string): string {
  if (!/^[\w\-.:@]+$/.test(sessionKey)) {
    throw new Error("Invalid session key: contains disallowed characters");
  }
  return sessionKey;
}

export async function applySessionHints(params: {
  baseBody: string;
  abortedLastRun: boolean;
  sessionEntry?: SessionEntry;
  sessionStore?: Record<string, SessionEntry>;
  sessionKey?: string;
  storePath?: string;
  abortKey?: string;
}): Promise<string> {
  let prefixedBodyBase = params.baseBody;
  const abortedHint = params.abortedLastRun
    ? "Note: The previous agent run was aborted by the user. Resume carefully or ask for clarification."
    : "";
  if (abortedHint) {
    prefixedBodyBase = `${abortedHint}\n\n${prefixedBodyBase}`;
    if (params.sessionEntry && params.sessionStore && params.sessionKey) {
      const validatedSessionKey = validateSessionKey(params.sessionKey);
      params.sessionEntry.abortedLastRun = false;
      params.sessionEntry.updatedAt = Date.now();
      params.sessionStore[validatedSessionKey] = params.sessionEntry;
      if (params.storePath) {
        const validatedStorePath = validateStorePath(params.storePath);
        const { updateSessionStore } = await loadSessionStoreRuntime();
        await updateSessionStore(validatedStorePath, (store) => {
          const entry = store[validatedSessionKey] ?? params.sessionEntry;
          if (!entry) {
            return;
          }
          store[validatedSessionKey] = {
            ...entry,
            abortedLastRun: false,
            updatedAt: Date.now(),
          };
        });
      }
    } else if (params.abortKey) {
      const validatedAbortKey = validateSessionKey(params.abortKey);
      setAbortMemory(validatedAbortKey, false);
    }
  }

  return prefixedBodyBase;
}