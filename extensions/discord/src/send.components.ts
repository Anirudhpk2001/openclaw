import {
  serializePayload,
  type MessagePayloadFile,
  type MessagePayloadObject,
  type RequestClient,
} from "@buape/carbon";
import { ChannelType, Routes } from "discord-api-types/v10";
import { loadConfig, type OpenClawConfig } from "openclaw/plugin-sdk/config-runtime";
import { recordChannelActivity } from "openclaw/plugin-sdk/infra-runtime";
import { resolveDiscordAccount } from "./accounts.js";
import { registerDiscordComponentEntries } from "./components-registry.js";
import {
  buildDiscordComponentMessage,
  buildDiscordComponentMessageFlags,
  resolveDiscordComponentAttachmentName,
  type DiscordComponentBuildResult,
  type DiscordComponentMessageSpec,
} from "./components.js";
import { parseAndResolveRecipient } from "./recipient-resolution.js";
import { loadOutboundMediaFromUrl } from "./runtime-api.js";
import { sendMessageDiscord } from "./send.outbound.js";
import {
  buildDiscordSendError,
  createDiscordClient,
  resolveChannelId,
  resolveDiscordChannelType,
  toDiscordFileBlob,
  stripUndefinedFields,
  SUPPRESS_NOTIFICATIONS_FLAG,
} from "./send.shared.js";
import type { DiscordSendResult } from "./send.types.js";

const DISCORD_FORUM_LIKE_TYPES = new Set<number>([ChannelType.GuildForum, ChannelType.GuildMedia]);

// ---------------------------------------------------------------------------
// Security: suspicious content patterns (shell commands, binaries, base64
// encoded commands, leetspeak variants, etc.)
// ---------------------------------------------------------------------------
const SUSPICIOUS_PATTERNS: RegExp[] = [
  // explicit command list (including policy-required commands)
  /\b(alias|curl|rm|echo|dd|git|tar|chmod|chown|fsck|ripgrep|rg)\b/gi,
  // shell / OS commands
  /\b(bash|sh|zsh|fish|ksh|csh|tcsh|dash|powershell|pwsh|cmd|command\.com)\b/gi,
  /\b(wget|nc|netcat|ncat|socat|telnet|ssh|scp|sftp|ftp|rsync)\b/gi,
  /\b(python|python3|perl|ruby|php|node|nodejs|lua|awk|sed|grep|find|xargs|tee|cat|less|more|head|tail|cut|sort|uniq|wc|tr|diff|patch)\b/gi,
  /\b(exec|eval|system|popen|subprocess|spawn|fork|execve|execvp|execl|execlp)\b/gi,
  /\b(sudo|su|doas|pkexec|runas)\b/gi,
  /\b(crontab|at|batch|nohup|screen|tmux|disown)\b/gi,
  /\b(mount|umount|fdisk|mkfs|dd|lsblk|blkid|parted)\b/gi,
  /\b(iptables|ip6tables|nftables|ufw|firewall-cmd|netstat|ss|ifconfig|ip\s+addr)\b/gi,
  /\b(kill|killall|pkill|reboot|shutdown|halt|poweroff|init)\b/gi,
  /\b(useradd|userdel|usermod|groupadd|groupdel|passwd|chpasswd)\b/gi,
  /\b(export|source|\.\/|\.\.\/)\b/gi,
  // shell metacharacters / injection patterns
  /[`$]\s*\(/g,
  /\$\{[^}]*\}/g,
  /;\s*(rm|curl|wget|bash|sh|python|perl|ruby|exec)/gi,
  /\|\s*(bash|sh|python|perl|ruby|exec|eval)/gi,
  // base64 encoded commands (base64 strings that decode to suspicious content)
  /(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/g,
  // leetspeak variants of dangerous commands
  /\b(3ch0|3x3c|3v4l|5h3ll|b45h|cur1|r00t|5udo|ch0wn|ch4ng3)\b/gi,
  // executable / binary extensions
  /\b\w+\.(exe|bat|cmd|sh|ps1|vbs|js|jar|py|rb|pl|php|elf|bin|run|app|dmg|msi|deb|rpm)\b/gi,
];

function sanitizeSuspiciousContent(content: string): string {
  let sanitized = content;
  for (const pattern of SUSPICIOUS_PATTERNS) {
    sanitized = sanitized.replace(pattern, "<suspicious_content_removed>");
  }
  return sanitized;
}

// ---------------------------------------------------------------------------
// Security: PII redaction patterns (Singapore + global zero-tolerance PII)
// ---------------------------------------------------------------------------
const PII_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  // Singapore NRIC / FIN (S/T/F/G followed by 7 digits and a letter)
  { pattern: /\b[STFG]\d{7}[A-Z]\b/gi, label: "NRIC/FIN" },
  // Passport numbers (generic: 1-2 letters + 6-9 digits)
  { pattern: /\b[A-Z]{1,2}\d{6,9}\b/g, label: "Passport" },
  // Singapore Work Permit / Student Pass (alphanumeric IDs)
  { pattern: /\b(WP|EP|SP|DP|LTVP|PEP|EntrePass)\s*[A-Z0-9]{6,12}\b/gi, label: "WorkPermit/Pass" },
  // Date of birth patterns
  { pattern: /\b(0?[1-9]|[12]\d|3[01])[\/\-](0?[1-9]|1[0-2])[\/\-](19|20)\d{2}\b/g, label: "DOB" },
  { pattern: /\b(19|20)\d{2}[\/\-](0?[1-9]|1[0-2])[\/\-](0?[1-9]|[12]\d|3[01])\b/g, label: "DOB" },
  // Personal phone numbers (Singapore +65 and generic)
  { pattern: /(\+65[\s\-]?)?(6|8|9)\d{7}\b/g, label: "PhoneNumber" },
  { pattern: /(\+?1[\s\-]?)?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4}\b/g, label: "PhoneNumber" },
  // Email addresses
  { pattern: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g, label: "Email" },
  // Credit / debit card numbers (13-19 digits, optionally separated)
  { pattern: /\b(?:\d[ \-]?){13,19}\b/g, label: "CardNumber" },
  // Bank account numbers (generic 8-20 digit sequences)
  { pattern: /\b\d{8,20}\b/g, label: "BankAccount" },
  // CPF account numbers (Singapore, 13 digits)
  { pattern: /\b\d{3}-\d{5}-\d{5}\b/g, label: "CPF" },
  // Social Security Numbers (US)
  { pattern: /\b\d{3}-\d{2}-\d{4}\b/g, label: "SSN" },
  // IP addresses (v4)
  { pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, label: "IPAddress" },
  // MAC addresses
  { pattern: /\b([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b/g, label: "MACAddress" },
  // GPS coordinates
  { pattern: /\b[-+]?([1-8]?\d(\.\d+)?|90(\.0+)?),\s*[-+]?(180(\.0+)?|((1[0-7]\d)|([1-9]?\d))(\.\d+)?)\b/g, label: "GPSCoordinates" },
  // SingPass / MyInfo identifiers (treat as NRIC pattern above, plus generic token)
  { pattern: /\b(singpass|myinfo)[\s_\-]?id[\s:=]+\S+/gi, label: "SingPassID" },
  // Authentication tokens / session identifiers (Bearer tokens, JWT)
  { pattern: /Bearer\s+[A-Za-z0-9\-._~+/]+=*/g, label: "AuthToken" },
  { pattern: /\beyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b/g, label: "JWT" },
  // Vehicle Identification Numbers (VIN)
  { pattern: /\b[A-HJ-NPR-Z0-9]{17}\b/g, label: "VIN" },
  // Driver's license (generic alphanumeric 6-15 chars — keep after more specific patterns)
  { pattern: /\b(DL|DLN|License No\.?|Licence No\.?)[\s:=]*[A-Z0-9]{6,15}\b/gi, label: "DriversLicense" },
  // Tax Identification Numbers
  { pattern: /\b(TIN|Tax ID|Taxpayer ID)[\s:=]*[A-Z0-9\-]{6,15}\b/gi, label: "TaxID" },
  // Employee / Student / School IDs
  { pattern: /\b(Employee ID|Emp ID|Staff ID|Student ID|School ID)[\s:=]*[A-Z0-9\-]{4,15}\b/gi, label: "EmployeeStudentID" },
  // Residential / mailing address (heuristic: number + street keyword)
  { pattern: /\b\d{1,5}\s+\w+\s+(Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Place|Pl|Way|Terrace|Ter|Close|Crescent|Cres)\b/gi, label: "Address" },
  // Full name heuristic (Title + two capitalised words)
  { pattern: /\b(Mr|Mrs|Ms|Miss|Dr|Prof)\.?\s+[A-Z][a-z]+\s+[A-Z][a-z]+\b/g, label: "FullName" },
  // IMEI (15 digits)
  { pattern: /\b\d{15}\b/g, label: "IMEI" },
];

function redactPII(content: string): string {
  let redacted = content;
  for (const { pattern } of PII_PATTERNS) {
    redacted = redacted.replace(pattern, "REDACTED");
  }
  return redacted;
}

// ---------------------------------------------------------------------------
// Combined file content sanitisation (suspicious content + PII)
// ---------------------------------------------------------------------------
function sanitizeFileContent(buffer: Buffer): Buffer {
  try {
    const text = buffer.toString("utf8");
    // Only process text-like buffers (skip binary blobs that are not valid UTF-8 text)
    // A simple heuristic: if the decoded string contains many replacement chars it is binary
    const nullCount = (text.match(/\0/g) ?? []).length;
    if (nullCount > text.length * 0.01) {
      // Likely binary — do not attempt text-based sanitisation
      return buffer;
    }
    const afterSuspicious = sanitizeSuspiciousContent(text);
    const afterPII = redactPII(afterSuspicious);
    return Buffer.from(afterPII, "utf8");
  } catch {
    return buffer;
  }
}

function extractComponentAttachmentNames(spec: DiscordComponentMessageSpec): string[] {
  const names: string[] = [];
  for (const block of spec.blocks ?? []) {
    if (block.type === "file") {
      names.push(resolveDiscordComponentAttachmentName(block.file));
    }
  }
  return names;
}

function hasComponentAttachmentBlock(spec: DiscordComponentMessageSpec): boolean {
  return (spec.blocks ?? []).some((block) => block.type === "file");
}

function withImplicitComponentAttachmentBlock(
  spec: DiscordComponentMessageSpec,
  attachmentName: string | undefined,
): DiscordComponentMessageSpec {
  if (!attachmentName || hasComponentAttachmentBlock(spec)) {
    return spec;
  }
  // Discord File components must point at the uploaded attachment name. Add the
  // matching file block automatically so callers do not have to duplicate it.
  return {
    ...spec,
    blocks: [
      ...(spec.blocks ?? []),
      {
        type: "file",
        file: `attachment://${attachmentName}`,
      },
    ],
  };
}

function hasClassicOnlyBlocks(spec: DiscordComponentMessageSpec): boolean {
  return (spec.blocks ?? []).every((block) => block.type === "text" || block.type === "file");
}

function hasUnsupportedClassicFeatures(spec: DiscordComponentMessageSpec): boolean {
  return Boolean(spec.modal || spec.container);
}

function hasAtMostOneNonSpoilerFile(spec: DiscordComponentMessageSpec): boolean {
  let fileBlockCount = 0;
  for (const block of spec.blocks ?? []) {
    if (block.type !== "file") {
      continue;
    }
    fileBlockCount += 1;
    if (block.spoiler) {
      return false;
    }
  }
  return fileBlockCount <= 1;
}

type ClassicDiscordMessageDecision =
  | {
      mode: "classic";
      reason: "plain-text-single-file";
    }
  | {
      mode: "components";
      reason: "unsupported-feature" | "unsupported-block" | "multiple-or-spoiler-files";
    };

/**
 * Keep the downgrade rules explicit because this path is only safe when the
 * spec means exactly what a plain Discord message can represent.
 */
function getClassicDiscordMessageDecision(
  spec: DiscordComponentMessageSpec,
): ClassicDiscordMessageDecision {
  if (hasUnsupportedClassicFeatures(spec)) {
    return { mode: "components", reason: "unsupported-feature" };
  }
  if (!hasClassicOnlyBlocks(spec)) {
    return { mode: "components", reason: "unsupported-block" };
  }
  if (!hasAtMostOneNonSpoilerFile(spec)) {
    return { mode: "components", reason: "multiple-or-spoiler-files" };
  }
  return { mode: "classic", reason: "plain-text-single-file" };
}

function collapseClassicComponentText(spec: DiscordComponentMessageSpec): string {
  const parts: string[] = [];
  const addPart = (value: string | undefined) => {
    if (typeof value !== "string") {
      return;
    }
    const trimmed = value.trim();
    if (!trimmed || parts.includes(trimmed)) {
      return;
    }
    parts.push(trimmed);
  };

  addPart(spec.text);
  for (const block of spec.blocks ?? []) {
    if (block.type === "text") {
      addPart(block.text);
    }
  }
  return parts.join("\n\n");
}

type DiscordComponentSendOpts = {
  cfg?: OpenClawConfig;
  accountId?: string;
  token?: string;
  rest?: RequestClient;
  silent?: boolean;
  replyTo?: string;
  sessionKey?: string;
  agentId?: string;
  mediaUrl?: string;
  mediaAccess?: {
    localRoots?: readonly string[];
    readFile?: (filePath: string) => Promise<Buffer>;
  };
  mediaLocalRoots?: readonly string[];
  mediaReadFile?: (filePath: string) => Promise<Buffer>;
  filename?: string;
};

export function registerBuiltDiscordComponentMessage(params: {
  buildResult: DiscordComponentBuildResult;
  messageId: string;
}): void {
  registerDiscordComponentEntries({
    entries: params.buildResult.entries,
    modals: params.buildResult.modals,
    messageId: params.messageId,
  });
}

async function buildDiscordComponentPayload(params: {
  spec: DiscordComponentMessageSpec;
  opts: DiscordComponentSendOpts;
  accountId: string;
}): Promise<{
  body: ReturnType<typeof stripUndefinedFields>;
  buildResult: ReturnType<typeof buildDiscordComponentMessage>;
}> {
  const messageReference = params.opts.replyTo
    ? { message_id: params.opts.replyTo, fail_if_not_exists: false }
    : undefined;

  let spec = params.spec;
  let resolvedFileName: string | undefined;
  let files: MessagePayloadFile[] | undefined;
  if (params.opts.mediaUrl) {
    const media = await loadOutboundMediaFromUrl(params.opts.mediaUrl, {
      mediaAccess: params.opts.mediaAccess,
      mediaLocalRoots: params.opts.mediaLocalRoots,
      mediaReadFile: params.opts.mediaReadFile,
    });
    const filenameOverride = params.opts.filename?.trim();
    // Security: sanitize the filename to prevent path traversal
    const rawFileName = filenameOverride || media.fileName || "upload";
    resolvedFileName = rawFileName.replace(/[^a-zA-Z0-9._\-]/g, "_").replace(/\.{2,}/g, "_");
    spec = withImplicitComponentAttachmentBlock(spec, resolvedFileName);
    // Security: sanitize file content for suspicious commands and PII before upload
    const sanitizedBuffer = sanitizeFileContent(media.buffer);
    const fileData = toDiscordFileBlob(sanitizedBuffer);
    files = [{ data: fileData, name: resolvedFileName }];
  }

  const attachmentNames = extractComponentAttachmentNames(spec);
  const uniqueAttachmentNames = [...new Set(attachmentNames)];
  if (uniqueAttachmentNames.length > 1) {
    throw new Error(
      "Discord component attachments currently support a single file. Use media-gallery for multiple files.",
    );
  }
  const expectedAttachmentName = uniqueAttachmentNames[0];
  if (expectedAttachmentName && resolvedFileName && expectedAttachmentName !== resolvedFileName) {
    throw new Error(
      `Component file block expects attachment "${expectedAttachmentName}", but the uploaded file is "${resolvedFileName}". Update components.blocks[].file or provide a matching filename.`,
    );
  }
  if (!params.opts.mediaUrl && expectedAttachmentName) {
    throw new Error(
      "Discord component file blocks require a media attachment (media/path/filePath).",
    );
  }

  const buildResult = buildDiscordComponentMessage({
    spec,
    sessionKey: params.opts.sessionKey,
    agentId: params.opts.agentId,
    accountId: params.accountId,
  });
  const flags = buildDiscordComponentMessageFlags(buildResult.components);
  const finalFlags = params.opts.silent
    ? (flags ?? 0) | SUPPRESS_NOTIFICATIONS_FLAG
    : (flags ?? undefined);

  const payload: MessagePayloadObject = {
    components: buildResult.components,
    ...(finalFlags ? { flags: finalFlags } : {}),
    ...(files ? { files } : {}),
  };
  const body = stripUndefinedFields({
    ...serializePayload(payload),
    ...(messageReference ? { message_reference: messageReference } : {}),
  });

  return { body, buildResult };
}

export async function sendDiscordComponentMessage(
  to: string,
  spec: DiscordComponentMessageSpec,
  opts: DiscordComponentSendOpts = {},
): Promise<DiscordSendResult> {
  const classicDecision = getClassicDiscordMessageDecision(spec);
  if (opts.mediaUrl && classicDecision.mode === "classic") {
    return await sendMessageDiscord(to, collapseClassicComponentText(spec), {
      cfg: opts.cfg,
      accountId: opts.accountId,
      token: opts.token,
      rest: opts.rest,
      mediaUrl: opts.mediaUrl,
      filename: opts.filename,
      mediaLocalRoots: opts.mediaLocalRoots,
      mediaReadFile: opts.mediaReadFile,
      mediaAccess: opts.mediaAccess,
      replyTo: opts.replyTo,
      silent: opts.silent,
    });
  }

  const cfg = opts.cfg ?? loadConfig();
  const accountInfo = resolveDiscordAccount({ cfg, accountId: opts.accountId });
  const { token, rest, request } = createDiscordClient(opts, cfg);
  const recipient = await parseAndResolveRecipient(to, opts.accountId, cfg);
  const { channelId } = await resolveChannelId(rest, recipient, request);

  const channelType = await resolveDiscordChannelType(rest, channelId);

  if (channelType && DISCORD_FORUM_LIKE_TYPES.has(channelType)) {
    throw new Error("Discord components are not supported in forum-style channels");
  }

  const { body, buildResult } = await buildDiscordComponentPayload({
    spec,
    opts,
    accountId: accountInfo.accountId,
  });

  let result: { id: string; channel_id: string };
  try {
    result = (await request(
      () =>
        rest.post(Routes.channelMessages(channelId), {
          body,
        }) as Promise<{ id: string; channel_id: string }>,
      "components",
    )) as { id: string; channel_id: string };
  } catch (err) {
    throw await buildDiscordSendError(err, {
      channelId,
      rest,
      token,
      hasMedia: Boolean(opts.mediaUrl),
    });
  }

  registerBuiltDiscordComponentMessage({
    buildResult,
    messageId: result.id,
  });

  recordChannelActivity({
    channel: "discord",
    accountId: accountInfo.accountId,
    direction: "outbound",
  });

  return {
    messageId: result.id ?? "unknown",
    channelId: result.channel_id ?? channelId,
  };
}

export async function editDiscordComponentMessage(
  to: string,
  messageId: string,
  spec: DiscordComponentMessageSpec,
  opts: DiscordComponentSendOpts = {},
): Promise<DiscordSendResult> {
  const cfg = opts.cfg ?? loadConfig();
  const accountInfo = resolveDiscordAccount({ cfg, accountId: opts.accountId });
  const { token, rest, request } = createDiscordClient(opts, cfg);
  const recipient = await parseAndResolveRecipient(to, opts.accountId, cfg);
  const { channelId } = await resolveChannelId(rest, recipient, request);
  const { body, buildResult } = await buildDiscordComponentPayload({
    spec,
    opts,
    accountId: accountInfo.accountId,
  });

  let result: { id: string; channel_id: string };
  try {
    result = (await request(
      () =>
        rest.patch(Routes.channelMessage(channelId, messageId), {
          body,
        }) as Promise<{ id: string; channel_id: string }>,
      "components",
    )) as { id: string; channel_id: string };
  } catch (err) {
    throw await buildDiscordSendError(err, {
      channelId,
      rest,
      token,
      hasMedia: Boolean(opts.mediaUrl),
    });
  }

  registerBuiltDiscordComponentMessage({
    buildResult,
    messageId: result.id ?? messageId,
  });

  recordChannelActivity({
    channel: "discord",
    accountId: accountInfo.accountId,
    direction: "outbound",
  });

  return {
    messageId: result.id ?? messageId,
    channelId: result.channel_id ?? channelId,
  };
}