import type { Command } from "commander";
import { runCommandWithRuntime } from "../core-api.js";
import { callBrowserRequest, type BrowserParentOpts } from "./browser-cli-shared.js";
import { danger, defaultRuntime, shortenHomePath } from "./core-api.js";

function runBrowserObserve(action: () => Promise<void>) {
  return runCommandWithRuntime(defaultRuntime, action, (err) => {
    defaultRuntime.error(danger(String(err as unknown)));
    defaultRuntime.exit(1);
  });
}

const ALLOWED_CONSOLE_LEVELS = new Set(["error", "warn", "info"]);

function sanitizeString(value: unknown, maxLength = 1024): string | undefined {
  if (value === undefined || value === null) return undefined;
  const str = String(value).trim();
  if (str.length === 0) return undefined;
  return str.slice(0, maxLength);
}

function sanitizeLevel(level: unknown): string | undefined {
  const sanitized = sanitizeString(level);
  if (!sanitized) return undefined;
  if (!ALLOWED_CONSOLE_LEVELS.has(sanitized)) return undefined;
  return sanitized;
}

function sanitizeTargetId(targetId: unknown): string | undefined {
  const sanitized = sanitizeString(targetId, 256);
  if (!sanitized) return undefined;
  // Only allow alphanumeric, hyphens, underscores, and dots
  if (!/^[a-zA-Z0-9\-_.]+$/.test(sanitized)) return undefined;
  return sanitized;
}

function sanitizeUrl(url: unknown): string {
  const sanitized = sanitizeString(url, 2048);
  if (!sanitized) throw new Error("Invalid or empty URL provided");
  // Basic URL/glob validation: allow printable ASCII, reject control chars
  if (/[\x00-\x1f\x7f]/.test(sanitized)) throw new Error("URL contains invalid characters");
  return sanitized;
}

function sanitizePositiveInteger(value: unknown): number | undefined {
  const num = Number(value);
  if (!Number.isFinite(num) || num <= 0 || !Number.isInteger(num)) return undefined;
  return num;
}

export function registerBrowserActionObserveCommands(
  browser: Command,
  parentOpts: (cmd: Command) => BrowserParentOpts,
) {
  browser
    .command("console")
    .description("Get recent console messages")
    .option("--level <level>", "Filter by level (error, warn, info)")
    .option("--target-id <id>", "CDP target id (or unique prefix)")
    .action(async (opts, cmd) => {
      const parent = parentOpts(cmd);
      const profile = parent?.browserProfile;
      await runBrowserObserve(async () => {
        const level = sanitizeLevel(opts.level);
        const targetId = sanitizeTargetId(opts.targetId);
        const result = await callBrowserRequest<{ messages: unknown[] }>(
          parent,
          {
            method: "GET",
            path: "/console",
            query: {
              level,
              targetId,
              profile,
            },
          },
          { timeoutMs: 20000 },
        );
        if (parent?.json) {
          defaultRuntime.writeJson(result);
          return;
        }
        defaultRuntime.writeJson(result.messages);
      });
    });

  browser
    .command("pdf")
    .description("Save page as PDF")
    .option("--target-id <id>", "CDP target id (or unique prefix)")
    .action(async (opts, cmd) => {
      const parent = parentOpts(cmd);
      const profile = parent?.browserProfile;
      await runBrowserObserve(async () => {
        const targetId = sanitizeTargetId(opts.targetId);
        const result = await callBrowserRequest<{ path: string }>(
          parent,
          {
            method: "POST",
            path: "/pdf",
            query: profile ? { profile } : undefined,
            body: { targetId },
          },
          { timeoutMs: 20000 },
        );
        if (parent?.json) {
          defaultRuntime.writeJson(result);
          return;
        }
        defaultRuntime.log(`PDF: ${shortenHomePath(result.path)}`);
      });
    });

  browser
    .command("responsebody")
    .description("Wait for a network response and return its body")
    .argument("<url>", "URL (exact, substring, or glob like **/api)")
    .option("--target-id <id>", "CDP target id (or unique prefix)")
    .option(
      "--timeout-ms <ms>",
      "How long to wait for the response (default: 20000)",
      (v: string) => Number(v),
    )
    .option("--max-chars <n>", "Max body chars to return (default: 200000)", (v: string) =>
      Number(v),
    )
    .action(async (url: string, opts, cmd) => {
      const parent = parentOpts(cmd);
      const profile = parent?.browserProfile;
      await runBrowserObserve(async () => {
        const sanitizedUrl = sanitizeUrl(url);
        const timeoutMs = sanitizePositiveInteger(opts.timeoutMs);
        const maxChars = sanitizePositiveInteger(opts.maxChars);
        const targetId = sanitizeTargetId(opts.targetId);
        const result = await callBrowserRequest<{ response: { body: string } }>(
          parent,
          {
            method: "POST",
            path: "/response/body",
            query: profile ? { profile } : undefined,
            body: {
              url: sanitizedUrl,
              targetId,
              timeoutMs,
              maxChars,
            },
          },
          { timeoutMs: timeoutMs ?? 20000 },
        );
        if (parent?.json) {
          defaultRuntime.writeJson(result);
          return;
        }
        defaultRuntime.log(result.response.body);
      });
    });
}