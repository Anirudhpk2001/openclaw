import type { Command } from "commander";
import { runBrowserResizeWithOutput } from "../browser-cli-resize.js";
import { callBrowserRequest, type BrowserParentOpts } from "../browser-cli-shared.js";
import { danger, defaultRuntime } from "../core-api.js";
import { requireRef, resolveBrowserActionContext } from "./shared.js";

const ALLOWED_URL_PROTOCOLS = ["http:", "https:"];
const MAX_URL_LENGTH = 2048;
const MAX_TARGET_ID_LENGTH = 128;
const TARGET_ID_PATTERN = /^[a-zA-Z0-9_\-]+$/;
const MAX_DIMENSION = 65535;
const MIN_DIMENSION = 1;

function sanitizeUrl(url: string): string {
  if (typeof url !== "string") {
    throw new Error("URL must be a string");
  }
  const trimmed = url.trim();
  if (trimmed.length === 0) {
    throw new Error("URL must not be empty");
  }
  if (trimmed.length > MAX_URL_LENGTH) {
    throw new Error(`URL must not exceed ${MAX_URL_LENGTH} characters`);
  }
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new Error("URL is not valid");
  }
  if (!ALLOWED_URL_PROTOCOLS.includes(parsed.protocol)) {
    throw new Error(`URL protocol must be one of: ${ALLOWED_URL_PROTOCOLS.join(", ")}`);
  }
  return parsed.toString();
}

function sanitizeTargetId(targetId: string | undefined): string | undefined {
  if (targetId === undefined || targetId === null) {
    return undefined;
  }
  const trimmed = String(targetId).trim();
  if (trimmed.length === 0) {
    return undefined;
  }
  if (trimmed.length > MAX_TARGET_ID_LENGTH) {
    throw new Error(`Target ID must not exceed ${MAX_TARGET_ID_LENGTH} characters`);
  }
  if (!TARGET_ID_PATTERN.test(trimmed)) {
    throw new Error("Target ID contains invalid characters");
  }
  return trimmed;
}

function sanitizeDimension(value: number, name: string): number {
  const num = Number(value);
  if (!Number.isFinite(num) || !Number.isInteger(num)) {
    throw new Error(`${name} must be a finite integer`);
  }
  if (num < MIN_DIMENSION || num > MAX_DIMENSION) {
    throw new Error(`${name} must be between ${MIN_DIMENSION} and ${MAX_DIMENSION}`);
  }
  return num;
}

export function registerBrowserNavigationCommands(
  browser: Command,
  parentOpts: (cmd: Command) => BrowserParentOpts,
) {
  browser
    .command("navigate")
    .description("Navigate the current tab to a URL")
    .argument("<url>", "URL to navigate to")
    .option("--target-id <id>", "CDP target id (or unique prefix)")
    .action(async (url: string, opts, cmd) => {
      const { parent, profile } = resolveBrowserActionContext(cmd, parentOpts);
      try {
        const sanitizedUrl = sanitizeUrl(url);
        const sanitizedTargetId = sanitizeTargetId(opts.targetId);
        const result = await callBrowserRequest<{ url?: string }>(
          parent,
          {
            method: "POST",
            path: "/navigate",
            query: profile ? { profile } : undefined,
            body: {
              url: sanitizedUrl,
              targetId: sanitizedTargetId,
            },
          },
          { timeoutMs: 20000 },
        );
        if (parent?.json) {
          defaultRuntime.writeJson(result);
          return;
        }
        defaultRuntime.log(`navigated to ${result.url ?? sanitizedUrl}`);
      } catch (err) {
        defaultRuntime.error(danger(String(err)));
        defaultRuntime.exit(1);
      }
    });

  browser
    .command("resize")
    .description("Resize the viewport")
    .argument("<width>", "Viewport width", (v: string) => Number(v))
    .argument("<height>", "Viewport height", (v: string) => Number(v))
    .option("--target-id <id>", "CDP target id (or unique prefix)")
    .action(async (width: number, height: number, opts, cmd) => {
      const { parent, profile } = resolveBrowserActionContext(cmd, parentOpts);
      try {
        const sanitizedWidth = sanitizeDimension(width, "width");
        const sanitizedHeight = sanitizeDimension(height, "height");
        const sanitizedTargetId = sanitizeTargetId(opts.targetId);
        await runBrowserResizeWithOutput({
          parent,
          profile,
          width: sanitizedWidth,
          height: sanitizedHeight,
          targetId: sanitizedTargetId,
          timeoutMs: 20000,
          successMessage: `resized to ${sanitizedWidth}x${sanitizedHeight}`,
        });
      } catch (err) {
        defaultRuntime.error(danger(String(err)));
        defaultRuntime.exit(1);
      }
    });

  // Keep `requireRef` reachable; shared utilities are intended for other modules too.
  void requireRef;
}