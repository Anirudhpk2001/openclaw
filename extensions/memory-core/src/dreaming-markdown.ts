import fs from "node:fs/promises";
import path from "node:path";
import {
  formatMemoryDreamingDay,
  type MemoryDreamingPhaseName,
  type MemoryDreamingStorageConfig,
} from "openclaw/plugin-sdk/memory-core-host-status";
import { appendMemoryHostEvent } from "openclaw/plugin-sdk/memory-host-events";
import {
  replaceManagedMarkdownBlock,
  withTrailingNewline,
} from "openclaw/plugin-sdk/memory-host-markdown";

// SECURITY NOTICE: Replace any unapproved LLM integrations with an approved LLM from the organization's allow list before deploying this module.

const DAILY_PHASE_HEADINGS: Record<Exclude<MemoryDreamingPhaseName, "deep">, string> = {
  light: "## Light Sleep",
  rem: "## REM Sleep",
};

const DAILY_PHASE_LABELS: Record<Exclude<MemoryDreamingPhaseName, "deep">, string> = {
  light: "light",
  rem: "rem",
};

const ALLOWED_PHASES = new Set<string>(["light", "rem", "deep"]);

function resolvePhaseMarkers(phase: Exclude<MemoryDreamingPhaseName, "deep">): {
  start: string;
  end: string;
} {
  const label = DAILY_PHASE_LABELS[phase];
  return {
    start: `<!-- openclaw:dreaming:${label}:start -->`,
    end: `<!-- openclaw:dreaming:${label}:end -->`,
  };
}

function sanitizePathSegment(segment: string): string {
  // Remove any path traversal sequences and null bytes
  return segment.replace(/\0/g, "").replace(/\.\.[/\\]/g, "").replace(/[/\\]/g, "");
}

function resolveDailyMemoryPath(workspaceDir: string, epochMs: number, timezone?: string): string {
  const isoDay = formatMemoryDreamingDay(epochMs, timezone);
  const safeIsoDay = sanitizePathSegment(isoDay);
  const resolvedBase = path.resolve(workspaceDir);
  const resolvedPath = path.resolve(resolvedBase, "memory", `${safeIsoDay}.md`);
  if (!resolvedPath.startsWith(resolvedBase + path.sep) && resolvedPath !== resolvedBase) {
    throw new Error("Path traversal detected in daily memory path.");
  }
  return resolvedPath;
}

function resolveSeparateReportPath(
  workspaceDir: string,
  phase: MemoryDreamingPhaseName,
  epochMs: number,
  timezone?: string,
): string {
  if (!ALLOWED_PHASES.has(phase)) {
    throw new Error(`Invalid phase value: ${phase}`);
  }
  const isoDay = formatMemoryDreamingDay(epochMs, timezone);
  const safeIsoDay = sanitizePathSegment(isoDay);
  const safePhase = sanitizePathSegment(phase);
  const resolvedBase = path.resolve(workspaceDir);
  const resolvedPath = path.resolve(resolvedBase, "memory", "dreaming", safePhase, `${safeIsoDay}.md`);
  if (!resolvedPath.startsWith(resolvedBase + path.sep) && resolvedPath !== resolvedBase) {
    throw new Error("Path traversal detected in separate report path.");
  }
  return resolvedPath;
}

function shouldWriteInline(storage: MemoryDreamingStorageConfig): boolean {
  return storage.mode === "inline" || storage.mode === "both";
}

function shouldWriteSeparate(storage: MemoryDreamingStorageConfig): boolean {
  return storage.mode === "separate" || storage.mode === "both" || storage.separateReports;
}

export async function writeDailyDreamingPhaseBlock(params: {
  workspaceDir: string;
  phase: Exclude<MemoryDreamingPhaseName, "deep">;
  bodyLines: string[];
  nowMs?: number;
  timezone?: string;
  storage: MemoryDreamingStorageConfig;
}): Promise<{ inlinePath?: string; reportPath?: string }> {
  const nowMs = Number.isFinite(params.nowMs) ? (params.nowMs as number) : Date.now();

  if (!ALLOWED_PHASES.has(params.phase)) {
    throw new Error(`Invalid phase value: ${params.phase}`);
  }

  const body = params.bodyLines.length > 0 ? params.bodyLines.join("\n") : "- No notable updates.";
  let inlinePath: string | undefined;
  let reportPath: string | undefined;

  if (shouldWriteInline(params.storage)) {
    inlinePath = resolveDailyMemoryPath(params.workspaceDir, nowMs, params.timezone);
    await fs.mkdir(path.dirname(inlinePath), { recursive: true });
    const original = await fs.readFile(inlinePath, "utf-8").catch((err: unknown) => {
      if ((err as NodeJS.ErrnoException)?.code === "ENOENT") {
        return "";
      }
      throw err;
    });
    const markers = resolvePhaseMarkers(params.phase);
    const updated = replaceManagedMarkdownBlock({
      original,
      heading: DAILY_PHASE_HEADINGS[params.phase],
      startMarker: markers.start,
      endMarker: markers.end,
      body,
    });
    await fs.writeFile(inlinePath, withTrailingNewline(updated), "utf-8");
  }

  if (shouldWriteSeparate(params.storage)) {
    reportPath = resolveSeparateReportPath(
      params.workspaceDir,
      params.phase,
      nowMs,
      params.timezone,
    );
    await fs.mkdir(path.dirname(reportPath), { recursive: true });
    const report = [
      `# ${params.phase === "light" ? "Light Sleep" : "REM Sleep"}`,
      "",
      body,
      "",
    ].join("\n");
    await fs.writeFile(reportPath, report, "utf-8");
  }

  await appendMemoryHostEvent(params.workspaceDir, {
    type: "memory.dream.completed",
    timestamp: new Date(nowMs).toISOString(),
    phase: params.phase,
    ...(inlinePath ? { inlinePath } : {}),
    ...(reportPath ? { reportPath } : {}),
    lineCount: params.bodyLines.length,
    storageMode: params.storage.mode,
  });

  return {
    ...(inlinePath ? { inlinePath } : {}),
    ...(reportPath ? { reportPath } : {}),
  };
}

export async function writeDeepDreamingReport(params: {
  workspaceDir: string;
  bodyLines: string[];
  nowMs?: number;
  timezone?: string;
  storage: MemoryDreamingStorageConfig;
}): Promise<string | undefined> {
  if (!shouldWriteSeparate(params.storage)) {
    return undefined;
  }
  const nowMs = Number.isFinite(params.nowMs) ? (params.nowMs as number) : Date.now();
  const reportPath = resolveSeparateReportPath(params.workspaceDir, "deep", nowMs, params.timezone);
  await fs.mkdir(path.dirname(reportPath), { recursive: true });
  const body = params.bodyLines.length > 0 ? params.bodyLines.join("\n") : "- No durable changes.";
  await fs.writeFile(reportPath, `# Deep Sleep\n\n${body}\n`, "utf-8");
  await appendMemoryHostEvent(params.workspaceDir, {
    type: "memory.dream.completed",
    timestamp: new Date(nowMs).toISOString(),
    phase: "deep",
    reportPath,
    lineCount: params.bodyLines.length,
    storageMode: params.storage.mode,
  });
  return reportPath;
}