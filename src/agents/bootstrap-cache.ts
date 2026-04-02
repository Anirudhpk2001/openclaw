import { loadWorkspaceBootstrapFiles, type WorkspaceBootstrapFile } from "./workspace.js";
import path from "path";

const cache = new Map<string, WorkspaceBootstrapFile[]>();

function sanitizeSessionKey(sessionKey: string): string {
  if (typeof sessionKey !== "string") {
    throw new Error("Invalid sessionKey: must be a string");
  }
  const sanitized = sessionKey.replace(/[^a-zA-Z0-9_\-]/g, "");
  if (sanitized.length === 0) {
    throw new Error("Invalid sessionKey: must contain at least one valid character");
  }
  if (sanitized.length > 256) {
    throw new Error("Invalid sessionKey: exceeds maximum length");
  }
  return sanitized;
}

function sanitizeWorkspaceDir(workspaceDir: string): string {
  if (typeof workspaceDir !== "string") {
    throw new Error("Invalid workspaceDir: must be a string");
  }
  const normalized = path.normalize(workspaceDir);
  if (normalized.includes("..")) {
    throw new Error("Invalid workspaceDir: path traversal detected");
  }
  if (normalized.length === 0) {
    throw new Error("Invalid workspaceDir: must not be empty");
  }
  return normalized;
}

export async function getOrLoadBootstrapFiles(params: {
  workspaceDir: string;
  sessionKey: string;
}): Promise<WorkspaceBootstrapFile[]> {
  const sessionKey = sanitizeSessionKey(params.sessionKey);
  const workspaceDir = sanitizeWorkspaceDir(params.workspaceDir);

  const existing = cache.get(sessionKey);
  if (existing) {
    return existing;
  }

  const files = await loadWorkspaceBootstrapFiles(workspaceDir);
  cache.set(sessionKey, files);
  return files;
}

export function clearBootstrapSnapshot(sessionKey: string): void {
  const sanitized = sanitizeSessionKey(sessionKey);
  cache.delete(sanitized);
}

export function clearBootstrapSnapshotOnSessionRollover(params: {
  sessionKey?: string;
  previousSessionId?: string;
}): void {
  if (!params.sessionKey || !params.previousSessionId) {
    return;
  }

  clearBootstrapSnapshot(params.sessionKey);
}

export function clearAllBootstrapSnapshots(): void {
  cache.clear();
}