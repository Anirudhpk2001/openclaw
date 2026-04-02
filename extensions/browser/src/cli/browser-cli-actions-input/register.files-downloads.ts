import type { Command } from "commander";
import { callBrowserRequest, type BrowserParentOpts } from "../browser-cli-shared.js";
import {
  danger,
  DEFAULT_UPLOAD_DIR,
  defaultRuntime,
  resolveExistingPathsWithinRoot,
  shortenHomePath,
} from "../core-api.js";
import { resolveBrowserActionContext } from "./shared.js";
import * as fs from "fs";
import * as path from "path";

// ── Suspicious content patterns ──────────────────────────────────────────────
const SUSPICIOUS_PATTERNS: RegExp[] = [
  // explicit command list (including required ones)
  /\b(alias|curl|rm|echo|dd|git|tar|chmod|chown|fsck|ripgrep|rg)\b/gi,
  // shell / system executables
  /\b(bash|sh|zsh|fish|ksh|csh|tcsh|dash|powershell|pwsh|cmd|wscript|cscript)\b/gi,
  // common system binaries
  /\b(wget|nc|netcat|ncat|socat|ssh|scp|sftp|ftp|telnet|nmap|ping|traceroute|iptables|ufw|crontab|at|systemctl|service|kill|pkill|killall|ps|top|htop|sudo|su|passwd|useradd|userdel|usermod|groupadd|groupdel|chpasswd|visudo|mount|umount|fdisk|mkfs|parted|lsblk|blkid|df|du|find|locate|which|whereis|xargs|awk|sed|grep|cut|sort|uniq|head|tail|cat|tee|tr|wc|diff|patch|cp|mv|ln|mkdir|rmdir|touch|chmod|chown|chgrp|stat|file|strings|hexdump|xxd|od|base64|openssl|gpg|python|python3|perl|ruby|php|node|nodejs|java|javac|gcc|g\+\+|make|cmake|go|rust|cargo|pip|npm|yarn|apt|apt-get|yum|dnf|brew|snap|dpkg|rpm|pacman)\b/gi,
  // base64-encoded content (heuristic: long base64 strings)
  /(?:[A-Za-z0-9+/]{40,}={0,2})/g,
  // leetspeak variants of dangerous words (e.g. 3ch0, r00t, sh3ll)
  /\b(3ch0|r00t|sh3ll|b4sh|cur1|w3get|t4r|ch0wn|ch0mod|3x3c|3xec|exec|eval)\b/gi,
  // shell metacharacters / command injection sequences
  /(\$\(|\`|&&|\|\||;[\s]*\w+|>\s*\/dev\/|<\s*\/dev\/|2>&1)/g,
];

const SINGAPORE_PII_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  // NRIC / FIN (S/T/F/G followed by 7 digits and a letter)
  { pattern: /\b[STFG]\d{7}[A-Z]\b/gi, label: "NRIC/FIN" },
  // Passport numbers (generic)
  { pattern: /\b[A-Z]{1,2}\d{6,9}\b/g, label: "Passport" },
  // Singapore phone numbers
  { pattern: /\b(?:\+65[\s-]?)?[689]\d{3}[\s-]?\d{4}\b/g, label: "SG Phone" },
  // Email addresses
  { pattern: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g, label: "Email" },
  // Credit / debit card numbers (13-19 digits, optionally space/dash separated)
  { pattern: /\b(?:\d[ -]?){13,19}\b/g, label: "Card Number" },
  // Bank account numbers (8-20 digits)
  { pattern: /\b\d{8,20}\b/g, label: "Bank Account" },
  // CPF account (same format as NRIC but kept explicit)
  { pattern: /\b[STFG]\d{7}[A-Z]\b/gi, label: "CPF" },
  // IP addresses
  { pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, label: "IP Address" },
  // MAC addresses
  { pattern: /\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b/g, label: "MAC Address" },
  // GPS coordinates
  { pattern: /\b-?\d{1,3}\.\d{4,},\s*-?\d{1,3}\.\d{4,}\b/g, label: "GPS" },
  // Singapore postal codes
  { pattern: /\bSingapore\s+\d{6}\b/gi, label: "SG Address" },
  // Dates of birth (common formats)
  { pattern: /\b\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}\b/g, label: "DOB" },
  // Authentication tokens / session IDs (long hex strings)
  { pattern: /\b[0-9a-fA-F]{32,}\b/g, label: "Token" },
  // SingPass / MyInfo identifiers (heuristic)
  { pattern: /\b(singpass|myinfo)[\s_\-]?id[\s:=]+\S+/gi, label: "SingPass/MyInfo ID" },
  // Full name heuristic (Title + words)
  { pattern: /\b(Mr|Mrs|Ms|Dr|Prof)\.?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+/g, label: "Full Name" },
];

const GENERAL_PII_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  // SSN
  { pattern: /\b\d{3}-\d{2}-\d{4}\b/g, label: "SSN" },
  // Passport (generic)
  { pattern: /\b[A-Z]{1,2}\d{6,9}\b/g, label: "Passport" },
  // Driver's license (US style)
  { pattern: /\b[A-Z]{1,2}\d{6,8}\b/g, label: "DL" },
  // TIN / EIN
  { pattern: /\b\d{2}-\d{7}\b/g, label: "TIN" },
  // Credit card
  { pattern: /\b(?:\d[ -]?){13,19}\b/g, label: "Credit Card" },
  // Financial account
  { pattern: /\b\d{8,20}\b/g, label: "Financial Account" },
  // Email
  { pattern: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g, label: "Email" },
  // Phone
  { pattern: /\b(?:\+?1[\s.\-]?)?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}\b/g, label: "Phone" },
  // IP address
  { pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, label: "IP Address" },
  // MAC address
  { pattern: /\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b/g, label: "MAC Address" },
  // GPS / fine location
  { pattern: /\b-?\d{1,3}\.\d{4,},\s*-?\d{1,3}\.\d{4,}\b/g, label: "GPS" },
  // Year of birth (standalone 4-digit year in context)
  { pattern: /\b(19|20)\d{2}\b/g, label: "Year of Birth" },
  // VIN
  { pattern: /\b[A-HJ-NPR-Z0-9]{17}\b/g, label: "VIN" },
  // Auth tokens (long hex)
  { pattern: /\b[0-9a-fA-F]{32,}\b/g, label: "Token" },
];

function sanitizeInput(value: string): string {
  if (typeof value !== "string") return value;
  // Remove null bytes
  let sanitized = value.replace(/\0/g, "");
  // Trim leading/trailing whitespace
  sanitized = sanitized.trim();
  // Remove control characters except newline/tab
  sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
  return sanitized;
}

function sanitizeObject(obj: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj)) {
    if (typeof value === "string") {
      result[key] = sanitizeInput(value);
    } else if (Array.isArray(value)) {
      result[key] = value.map((v) => (typeof v === "string" ? sanitizeInput(v) : v));
    } else {
      result[key] = value;
    }
  }
  return result;
}

function removeSuspiciousContent(content: string): string {
  let sanitized = content;
  for (const pattern of SUSPICIOUS_PATTERNS) {
    sanitized = sanitized.replace(pattern, "<suspicious_content_removed>");
  }
  return sanitized;
}

function redactSingaporePII(content: string): string {
  let redacted = content;
  for (const { pattern } of SINGAPORE_PII_PATTERNS) {
    redacted = redacted.replace(pattern, "REDACTED");
  }
  return redacted;
}

function redactGeneralPII(content: string): string {
  let redacted = content;
  for (const { pattern } of GENERAL_PII_PATTERNS) {
    redacted = redacted.replace(pattern, "REDACTED");
  }
  return redacted;
}

async function processUploadedFileContent(filePath: string): Promise<void> {
  try {
    const raw = fs.readFileSync(filePath, "utf8");
    let processed = raw;
    // 1. Remove suspicious / executable content
    processed = removeSuspiciousContent(processed);
    // 2. Redact Singapore PII
    processed = redactSingaporePII(processed);
    // 3. Redact general PII
    processed = redactGeneralPII(processed);
    if (processed !== raw) {
      fs.writeFileSync(filePath, processed, "utf8");
    }
  } catch {
    // Binary files or unreadable files are skipped silently
  }
}

async function normalizeUploadPaths(paths: string[]): Promise<string[]> {
  const result = await resolveExistingPathsWithinRoot({
    rootDir: DEFAULT_UPLOAD_DIR,
    requestedPaths: paths,
    scopeLabel: `uploads directory (${DEFAULT_UPLOAD_DIR})`,
  });
  if (!result.ok) {
    throw new Error(result.error);
  }
  // Process each uploaded file for suspicious content and PII
  for (const filePath of result.paths) {
    await processUploadedFileContent(filePath);
  }
  return result.paths;
}

async function runBrowserPostAction<T>(params: {
  parent: BrowserParentOpts;
  profile: string | undefined;
  path: string;
  body: Record<string, unknown>;
  timeoutMs: number;
  describeSuccess: (result: T) => string;
}): Promise<void> {
  try {
    const sanitizedBody = sanitizeObject(params.body);
    const result = await callBrowserRequest<T>(
      params.parent,
      {
        method: "POST",
        path: params.path,
        query: params.profile ? { profile: params.profile } : undefined,
        body: sanitizedBody,
      },
      { timeoutMs: params.timeoutMs },
    );
    if (params.parent?.json) {
      defaultRuntime.writeJson(result);
      return;
    }
    defaultRuntime.log(params.describeSuccess(result));
  } catch (err) {
    defaultRuntime.error(danger(String(err)));
    defaultRuntime.exit(1);
  }
}

export function registerBrowserFilesAndDownloadsCommands(
  browser: Command,
  parentOpts: (cmd: Command) => BrowserParentOpts,
) {
  const resolveTimeoutAndTarget = (opts: { timeoutMs?: unknown; targetId?: unknown }) => {
    const timeoutMs = Number.isFinite(opts.timeoutMs) ? Number(opts.timeoutMs) : undefined;
    const targetId =
      typeof opts.targetId === "string"
        ? sanitizeInput(opts.targetId.trim() || "")  || undefined
        : undefined;
    return { timeoutMs, targetId };
  };

  const runDownloadCommand = async (
    cmd: Command,
    opts: { timeoutMs?: unknown; targetId?: unknown },
    request: { path: string; body: Record<string, unknown> },
  ) => {
    const { parent, profile } = resolveBrowserActionContext(cmd, parentOpts);
    const { timeoutMs, targetId } = resolveTimeoutAndTarget(opts);
    await runBrowserPostAction<{ download: { path: string } }>({
      parent,
      profile,
      path: request.path,
      body: sanitizeObject({
        ...request.body,
        targetId,
        timeoutMs,
      }),
      timeoutMs: timeoutMs ?? 20000,
      describeSuccess: (result) => `downloaded: ${shortenHomePath(result.download.path)}`,
    });
  };

  browser
    .command("upload")
    .description("Arm file upload for the next file chooser")
    .argument(
      "<paths...>",
      "File paths to upload (must be within OpenClaw temp uploads dir, e.g. /tmp/openclaw/uploads/file.pdf)",
    )
    .option("--ref <ref>", "Ref id from snapshot to click after arming")
    .option("--input-ref <ref>", "Ref id for <input type=file> to set directly")
    .option("--element <selector>", "CSS selector for <input type=file>")
    .option("--target-id <id>", "CDP target id (or unique prefix)")
    .option(
      "--timeout-ms <ms>",
      "How long to wait for the next file chooser (default: 120000)",
      (v: string) => Number(v),
    )
    .action(async (paths: string[], opts, cmd) => {
      const { parent, profile } = resolveBrowserActionContext(cmd, parentOpts);
      const normalizedPaths = await normalizeUploadPaths(paths);
      const { timeoutMs, targetId } = resolveTimeoutAndTarget(opts);
      await runBrowserPostAction({
        parent,
        profile,
        path: "/hooks/file-chooser",
        body: sanitizeObject({
          paths: normalizedPaths,
          ref: opts.ref?.trim() || undefined,
          inputRef: opts.inputRef?.trim() || undefined,
          element: opts.element?.trim() || undefined,
          targetId,
          timeoutMs,
        }),
        timeoutMs: timeoutMs ?? 20000,
        describeSuccess: () => `upload armed for ${paths.length} file(s)`,
      });
    });

  browser
    .command("waitfordownload")
    .description("Wait for the next download (and save it)")
    .argument(
      "[path]",
      "Save path within openclaw temp downloads dir (default: /tmp/openclaw/downloads/...; fallback: os.tmpdir()/openclaw/downloads/...)",
    )
    .option("--target-id <id>", "CDP target id (or unique prefix)")
    .option(
      "--timeout-ms <ms>",
      "How long to wait for the next download (default: 120000)",
      (v: string) => Number(v),
    )
    .action(async (outPath: string | undefined, opts, cmd) => {
      await runDownloadCommand(cmd, opts, {
        path: "/wait/download",
        body: sanitizeObject({
          path: outPath?.trim() || undefined,
        }),
      });
    });

  browser
    .command("download")
    .description("Click a ref and save the resulting download")
    .argument("<ref>", "Ref id from snapshot to click")
    .argument(
      "<path>",
      "Save path within openclaw temp downloads dir (e.g. report.pdf or /tmp/openclaw/downloads/report.pdf)",
    )
    .option("--target-id <id>", "CDP target id (or unique prefix)")
    .option(
      "--timeout-ms <ms>",
      "How long to wait for the download to start (default: 120000)",
      (v: string) => Number(v),
    )
    .action(async (ref: string, outPath: string, opts, cmd) => {
      await runDownloadCommand(cmd, opts, {
        path: "/download",
        body: sanitizeObject({
          ref,
          path: outPath,
        }),
      });
    });

  browser
    .command("dialog")
    .description("Arm the next modal dialog (alert/confirm/prompt)")
    .option("--accept", "Accept the dialog", false)
    .option("--dismiss", "Dismiss the dialog", false)
    .option("--prompt <text>", "Prompt response text")
    .option("--target-id <id>", "CDP target id (or unique prefix)")
    .option(
      "--timeout-ms <ms>",
      "How long to wait for the next dialog (default: 120000)",
      (v: string) => Number(v),
    )
    .action(async (opts, cmd) => {
      const { parent, profile } = resolveBrowserActionContext(cmd, parentOpts);
      const accept = opts.accept ? true : opts.dismiss ? false : undefined;
      if (accept === undefined) {
        defaultRuntime.error(danger("Specify --accept or --dismiss"));
        defaultRuntime.exit(1);
        return;
      }
      const { timeoutMs, targetId } = resolveTimeoutAndTarget(opts);
      await runBrowserPostAction({
        parent,
        profile,
        path: "/hooks/dialog",
        body: sanitizeObject({
          accept,
          promptText: opts.prompt?.trim() || undefined,
          targetId,
          timeoutMs,
        }),
        timeoutMs: timeoutMs ?? 20000,
        describeSuccess: () => "dialog armed",
      });
    });
}