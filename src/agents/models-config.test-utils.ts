import fs from "node:fs/promises";
import path from "node:path";
import { resolveOpenClawAgentDir } from "./agent-paths.js";

function sanitizePath(inputPath: string): string {
  const normalized = path.normalize(inputPath);
  if (normalized.includes("..")) {
    throw new Error("Invalid path: path traversal detected");
  }
  return normalized;
}

export async function readGeneratedModelsJson<T>(): Promise<T> {
  const agentDir = resolveOpenClawAgentDir();
  const sanitizedAgentDir = sanitizePath(agentDir);
  const modelPath = path.join(sanitizedAgentDir, "models.json");
  const sanitizedModelPath = sanitizePath(modelPath);
  if (!sanitizedModelPath.startsWith(sanitizedAgentDir)) {
    throw new Error("Invalid path: resolved path is outside the agent directory");
  }
  const raw = await fs.readFile(sanitizedModelPath, "utf8");
  const sanitizedRaw = raw.trim();
  let parsed: T;
  try {
    parsed = JSON.parse(sanitizedRaw) as T;
  } catch {
    throw new Error("Invalid JSON content in models.json");
  }
  return parsed;
}