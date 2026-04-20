import fs from "node:fs";
import path from "node:path";
import { listAgentIds, resolveAgentDir } from "../agents/agent-scope.js";
import type { OpenClawConfig } from "../config/types.openclaw.js";
import { formatErrorMessage } from "../infra/errors.js";
import { resolveUserPath } from "../utils.js";
import { listAuthProfileStorePaths as listAuthProfileStorePathsFromAuthStorePaths } from "./auth-store-paths.js";
import { parseEnvValue } from "./shared.js";

const MAX_PATH_LENGTH = 4096;

function isJsonObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isSafePath(resolvedPath: string, allowedBase: string): boolean {
  const normalizedPath = path.normalize(resolvedPath);
  const normalizedBase = path.normalize(allowedBase);
  return normalizedPath.startsWith(normalizedBase + path.sep) || normalizedPath === normalizedBase;
}

function sanitizePath(inputPath: string): string {
  if (!inputPath || typeof inputPath !== "string") {
    throw new Error("Invalid path input");
  }
  if (inputPath.length > MAX_PATH_LENGTH) {
    throw new Error("Path exceeds maximum allowed length");
  }
  return path.normalize(inputPath);
}

export function parseEnvAssignmentValue(raw: string): string {
  return parseEnvValue(raw);
}

export function listAuthProfileStorePaths(config: OpenClawConfig, stateDir: string): string[] {
  return listAuthProfileStorePathsFromAuthStorePaths(config, stateDir);
}

export function listLegacyAuthJsonPaths(stateDir: string): string[] {
  const out: string[] = [];
  const resolvedStateDir = resolveUserPath(stateDir);
  const agentsRoot = path.resolve(sanitizePath(resolvedStateDir), "agents");
  if (!fs.existsSync(agentsRoot)) {
    return out;
  }
  for (const entry of fs.readdirSync(agentsRoot, { withFileTypes: true })) {
    if (!entry.isDirectory()) {
      continue;
    }
    const entryName = path.basename(entry.name);
    const candidate = path.resolve(agentsRoot, entryName, "agent", "auth.json");
    if (!isSafePath(candidate, agentsRoot)) {
      continue;
    }
    if (fs.existsSync(candidate)) {
      const stats = fs.statSync(candidate);
      if (stats.isFile()) {
        out.push(candidate);
      }
    }
  }
  return out;
}

function resolveActiveAgentDir(stateDir: string, env: NodeJS.ProcessEnv = process.env): string {
  const override = env.OPENCLAW_AGENT_DIR?.trim() || env.PI_CODING_AGENT_DIR?.trim();
  if (override) {
    const resolvedOverride = resolveUserPath(sanitizePath(override));
    return path.resolve(resolvedOverride);
  }
  const resolvedStateDir = resolveUserPath(stateDir);
  return path.resolve(sanitizePath(resolvedStateDir), "agents", "main", "agent");
}

export function listAgentModelsJsonPaths(
  config: OpenClawConfig,
  stateDir: string,
  env: NodeJS.ProcessEnv = process.env,
): string[] {
  const resolvedStateDir = resolveUserPath(stateDir);
  const normalizedStateDir = path.resolve(sanitizePath(resolvedStateDir));
  const paths = new Set<string>();

  const mainAgentModels = path.resolve(normalizedStateDir, "agents", "main", "agent", "models.json");
  if (isSafePath(mainAgentModels, normalizedStateDir)) {
    paths.add(mainAgentModels);
  }

  const activeAgentDir = resolveActiveAgentDir(stateDir, env);
  const activeModels = path.resolve(activeAgentDir, "models.json");
  paths.add(activeModels);

  const agentsRoot = path.resolve(normalizedStateDir, "agents");
  if (fs.existsSync(agentsRoot)) {
    for (const entry of fs.readdirSync(agentsRoot, { withFileTypes: true })) {
      if (!entry.isDirectory()) {
        continue;
      }
      const entryName = path.basename(entry.name);
      const candidate = path.resolve(agentsRoot, entryName, "agent", "models.json");
      if (!isSafePath(candidate, agentsRoot)) {
        continue;
      }
      paths.add(candidate);
    }
  }

  for (const agentId of listAgentIds(config)) {
    if (agentId === "main") {
      const mainModels = path.resolve(normalizedStateDir, "agents", "main", "agent", "models.json");
      if (isSafePath(mainModels, normalizedStateDir)) {
        paths.add(mainModels);
      }
      continue;
    }
    const agentDir = resolveAgentDir(config, agentId);
    const resolvedAgentDir = path.resolve(resolveUserPath(sanitizePath(agentDir)));
    const agentModels = path.resolve(resolvedAgentDir, "models.json");
    paths.add(agentModels);
  }

  return [...paths];
}

export type ReadJsonObjectOptions = {
  maxBytes?: number;
  requireRegularFile?: boolean;
};

export function readJsonObjectIfExists(filePath: string): {
  value: Record<string, unknown> | null;
  error?: string;
};
export function readJsonObjectIfExists(
  filePath: string,
  options: ReadJsonObjectOptions,
): {
  value: Record<string, unknown> | null;
  error?: string;
};
export function readJsonObjectIfExists(
  filePath: string,
  options: ReadJsonObjectOptions = {},
): {
  value: Record<string, unknown> | null;
  error?: string;
} {
  let normalizedPath: string;
  try {
    normalizedPath = path.resolve(sanitizePath(filePath));
  } catch {
    return {
      value: null,
      error: "Invalid file path provided",
    };
  }

  if (!fs.existsSync(normalizedPath)) {
    return { value: null };
  }
  try {
    const stats = fs.statSync(normalizedPath);
    if (!stats.isFile()) {
      return {
        value: null,
        error: `Refusing to read non-regular file: ${normalizedPath}`,
      };
    }
    if (options.requireRegularFile && !stats.isFile()) {
      return {
        value: null,
        error: `Refusing to read non-regular file: ${normalizedPath}`,
      };
    }
    if (
      typeof options.maxBytes === "number" &&
      Number.isFinite(options.maxBytes) &&
      options.maxBytes >= 0 &&
      stats.size > options.maxBytes
    ) {
      return {
        value: null,
        error: `Refusing to read oversized JSON (${stats.size} bytes): ${normalizedPath}`,
      };
    }
    const raw = fs.readFileSync(normalizedPath, "utf8");
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return {
        value: null,
        error: "Failed to parse JSON: invalid JSON format",
      };
    }
    if (!isJsonObject(parsed)) {
      return { value: null };
    }
    return { value: parsed };
  } catch (err) {
    return {
      value: null,
      error: formatErrorMessage(err),
    };
  }
}