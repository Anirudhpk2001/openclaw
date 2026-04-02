import { createLazyRuntimeNamedExport } from "openclaw/plugin-sdk/lazy-runtime";
import { resolveBlueBubblesAccount } from "./accounts.js";
import { getCachedBlueBubblesPrivateApiStatus, isMacOS26OrHigher } from "./probe.js";
import {
  BLUEBUBBLES_ACTION_NAMES,
  BLUEBUBBLES_ACTIONS,
  createActionGate,
  extractToolSend,
  jsonResult,
  readNumberParam,
  readBooleanParam,
  readReactionParams,
  readStringParam,
  type ChannelMessageActionAdapter,
  type ChannelMessageActionName,
} from "./runtime-api.js";
import { normalizeSecretInputString } from "./secret-input.js";
import {
  normalizeBlueBubblesHandle,
  normalizeBlueBubblesMessagingTarget,
  parseBlueBubblesTarget,
} from "./targets.js";
import type { BlueBubblesSendTarget } from "./types.js";

// NOTE (Policy: Authenticate MCP Client): Missing authentication is a policy violation.
// All MCP clients must be authenticated before being allowed to invoke actions.
// Please add authentication to comply with the policy.

const loadBlueBubblesActionsRuntime = createLazyRuntimeNamedExport(
  () => import("./actions.runtime.js"),
  "blueBubblesActionsRuntime",
);

const providerId = "bluebubbles";

// ── Input sanitization helpers ────────────────────────────────────────────────

/**
 * Suspicious-content patterns used to detect hidden/injected prompts,
 * shell commands, binaries, base64-encoded payloads, leetspeak, etc.
 */
const SUSPICIOUS_PATTERNS: RegExp[] = [
  // Shell / system commands (including the mandatory list)
  /\b(alias|ripgrep|curl|rm|echo|dd|git|tar|chmod|chown|fsck)\b/i,
  /\b(bash|sh|zsh|fish|ksh|csh|tcsh|pwsh|powershell|cmd\.exe|command\.com)\b/i,
  /\b(exec|eval|system|popen|subprocess|spawn|fork|execve|execvp)\b/i,
  /\b(wget|nc|netcat|ncat|socat|telnet|ssh|scp|sftp|ftp|rsync)\b/i,
  /\b(python|python3|ruby|perl|node|php|lua|java|javac|gcc|cc|make|cmake)\b/i,
  /\b(sudo|su|doas|runas|pkexec)\b/i,
  /\b(kill|killall|pkill|nohup|cron|crontab|at|atd|launchctl|systemctl|service)\b/i,
  /\b(mount|umount|fdisk|mkfs|dd|lsblk|blkid)\b/i,
  /\b(iptables|nftables|ufw|firewall-cmd)\b/i,
  // Binary / executable markers
  /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/,
  /^(MZ|ELF|\x7fELF|#!\/)/m,
  // Base64-encoded content (long runs of base64 chars)
  /(?:[A-Za-z0-9+/]{40,}={0,2})/,
  // Leetspeak indicators (common substitutions)
  /\b[3e][xX][3e][cC]\b/,
  /\b[5s][hH][3e][lL][lL]\b/,
  /\b[5s][yY][5s][tT][3e][mM]\b/,
  // Invisible / hidden prompt tricks (zero-width chars, tiny font markers)
  /[\u200b\u200c\u200d\u200e\u200f\ufeff\u00ad]/,
  // Prompt injection keywords
  /\b(ignore previous instructions?|disregard (all )?previous|system prompt|you are now|act as|jailbreak)\b/i,
];

const SUSPICIOUS_CONTENT_PLACEHOLDER = "<suspicious_content_removed>";

function containsSuspiciousContent(value: string): boolean {
  return SUSPICIOUS_PATTERNS.some((re) => re.test(value));
}

function sanitizeString(value: string): string {
  if (containsSuspiciousContent(value)) {
    return SUSPICIOUS_CONTENT_PLACEHOLDER;
  }
  return value;
}

// ── Singapore PII patterns ────────────────────────────────────────────────────

const SG_PII_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /\b[STFGM]\d{7}[A-Z]\b/g, label: "NRIC/FIN" },
  { pattern: /\b[A-Z]{1,2}\d{7}[A-Z]?\b/g, label: "Passport" },
  { pattern: /\b\d{8,12}\b/g, label: "WorkPermit/StudentPass" },
  { pattern: /\b\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}\b/g, label: "DateOfBirth" },
  { pattern: /\b[6|8|9]\d{7}\b/g, label: "SGPhoneNumber" },
  { pattern: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, label: "Email" },
  { pattern: /\b\d{6}\s[A-Za-z\s]{5,50}\b/g, label: "SGPostalAddress" },
  { pattern: /\b\d{3,4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b/g, label: "CreditCard" },
  { pattern: /\b\d{9,18}\b/g, label: "BankAccount" },
  { pattern: /\b\d{3}-\d{2}-\d{4}\b/g, label: "SSN" },
  { pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, label: "IPAddress" },
  { pattern: /\b([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b/g, label: "MACAddress" },
  { pattern: /\b\d{15,17}\b/g, label: "IMEI" },
  { pattern: /\b[0-9]{5,6}-[0-9A-Z]{5,10}-[0-9]{1,2}\b/g, label: "CPFAccount" },
  { pattern: /singpass[\s\S]{0,40}/gi, label: "SingPassIdentifier" },
  { pattern: /myinfo[\s\S]{0,40}/gi, label: "MyInfoIdentifier" },
];

// General PII patterns (non-Singapore-specific)
const GENERAL_PII_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /\b\d{3}-\d{2}-\d{4}\b/g, label: "SSN" },
  { pattern: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, label: "Email" },
  { pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, label: "IPAddress" },
  { pattern: /\b([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b/g, label: "MACAddress" },
  { pattern: /\b\d{3,4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b/g, label: "CreditCard" },
  { pattern: /\b\d{9,18}\b/g, label: "FinancialAccount" },
  { pattern: /\b\d{15,17}\b/g, label: "IMEI" },
  { pattern: /\b[A-Z]{1,2}\d{7}[A-Z]?\b/g, label: "Passport" },
  { pattern: /\b[A-Z]\d{7}\b/g, label: "DriversLicense" },
  { pattern: /\b\d{2,3}-\d{7,8}-\d\b/g, label: "TaxID" },
];

function redactPII(content: string): string {
  let result = content;
  for (const { pattern } of SG_PII_PATTERNS) {
    result = result.replace(pattern, "REDACTED");
  }
  for (const { pattern } of GENERAL_PII_PATTERNS) {
    result = result.replace(pattern, "REDACTED");
  }
  return result;
}

/**
 * Sanitize and validate a string parameter: trim, check for suspicious content,
 * and return the cleaned value (or undefined if empty).
 */
function sanitizeParam(value: string | undefined): string | undefined {
  if (value === undefined || value === null) return undefined;
  const trimmed = String(value).trim();
  if (!trimmed) return undefined;
  return sanitizeString(trimmed);
}

/**
 * Validate that a string does not exceed a reasonable maximum length.
 */
function validateLength(value: string, max: number, fieldName: string): string {
  if (value.length > max) {
    throw new Error(`Input validation failed: '${fieldName}' exceeds maximum allowed length of ${max}.`);
  }
  return value;
}

/**
 * Sanitize all string values in a params record.
 */
function sanitizeParams(params: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(params)) {
    if (typeof value === "string") {
      result[key] = sanitizeParam(value) ?? value;
    } else {
      result[key] = value;
    }
  }
  return result;
}

/**
 * Process uploaded file buffer: scan for suspicious content, redact PII,
 * and return the sanitized buffer.
 */
function processUploadedFileBuffer(buffer: Uint8Array, filename: string): Uint8Array {
  // Attempt to decode as UTF-8 text for scanning
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(buffer);
  } catch {
    // Binary file — scan for binary executable markers
    const header = Array.from(buffer.slice(0, 4)).map((b) => String.fromCharCode(b)).join("");
    if (header.startsWith("MZ") || header.startsWith("\x7fELF") || header.startsWith("#!")) {
      throw new Error(
        `BlueBubbles upload-file: '${filename}' appears to be a binary executable and cannot be uploaded.`,
      );
    }
    // Return binary as-is (cannot text-scan)
    return buffer;
  }

  // Check for suspicious content
  if (containsSuspiciousContent(text)) {
    // Replace suspicious segments
    let sanitized = text;
    for (const pattern of SUSPICIOUS_PATTERNS) {
      sanitized = sanitized.replace(pattern, SUSPICIOUS_CONTENT_PLACEHOLDER);
    }
    text = sanitized;
  }

  // Redact PII
  text = redactPII(text);

  return new TextEncoder().encode(text);
}

function mapTarget(raw: string): BlueBubblesSendTarget {
  const sanitized = sanitizeParam(raw);
  if (!sanitized) {
    throw new Error("Invalid target: empty or suspicious value.");
  }
  const parsed = parseBlueBubblesTarget(sanitized);
  if (parsed.kind === "chat_guid") {
    return { kind: "chat_guid", chatGuid: parsed.chatGuid };
  }
  if (parsed.kind === "chat_id") {
    return { kind: "chat_id", chatId: parsed.chatId };
  }
  if (parsed.kind === "chat_identifier") {
    return { kind: "chat_identifier", chatIdentifier: parsed.chatIdentifier };
  }
  return {
    kind: "handle",
    address: normalizeBlueBubblesHandle(parsed.to),
    service: parsed.service,
  };
}

function readMessageText(params: Record<string, unknown>): string | undefined {
  return readStringParam(params, "text") ?? readStringParam(params, "message");
}

/** Supported action names for BlueBubbles */
const SUPPORTED_ACTIONS = new Set<ChannelMessageActionName>([
  ...BLUEBUBBLES_ACTION_NAMES,
  "upload-file",
]);
const PRIVATE_API_ACTIONS = new Set<ChannelMessageActionName>([
  "react",
  "edit",
  "unsend",
  "reply",
  "sendWithEffect",
  "renameGroup",
  "setGroupIcon",
  "addParticipant",
  "removeParticipant",
  "leaveGroup",
]);

export const bluebubblesMessageActions: ChannelMessageActionAdapter = {
  describeMessageTool: ({ cfg, currentChannelId }) => {
    const account = resolveBlueBubblesAccount({ cfg: cfg });
    if (!account.enabled || !account.configured) {
      return null;
    }
    const gate = createActionGate(cfg.channels?.bluebubbles?.actions);
    const actions = new Set<ChannelMessageActionName>();
    const macOS26 = isMacOS26OrHigher(account.accountId);
    const privateApiStatus = getCachedBlueBubblesPrivateApiStatus(account.accountId);
    for (const action of BLUEBUBBLES_ACTION_NAMES) {
      const spec = BLUEBUBBLES_ACTIONS[action];
      if (!spec?.gate) {
        continue;
      }
      if (privateApiStatus === false && PRIVATE_API_ACTIONS.has(action)) {
        continue;
      }
      if ("unsupportedOnMacOS26" in spec && spec.unsupportedOnMacOS26 && macOS26) {
        continue;
      }
      if (gate(spec.gate)) {
        actions.add(action);
      }
    }
    const normalizedTarget = currentChannelId
      ? normalizeBlueBubblesMessagingTarget(currentChannelId)
      : undefined;
    const lowered = normalizedTarget?.trim().toLowerCase() ?? "";
    const isGroupTarget =
      lowered.startsWith("chat_guid:") ||
      lowered.startsWith("chat_id:") ||
      lowered.startsWith("chat_identifier:") ||
      lowered.startsWith("group:");
    if (!isGroupTarget) {
      for (const action of BLUEBUBBLES_ACTION_NAMES) {
        if ("groupOnly" in BLUEBUBBLES_ACTIONS[action] && BLUEBUBBLES_ACTIONS[action].groupOnly) {
          actions.delete(action);
        }
      }
    }
    if (actions.delete("sendAttachment")) {
      actions.add("upload-file");
    }
    return { actions: Array.from(actions) };
  },
  supportsAction: ({ action }) => SUPPORTED_ACTIONS.has(action),
  extractToolSend: ({ args }) => extractToolSend(args, "sendMessage"),
  handleAction: async ({ action, params, cfg, accountId, toolContext }) => {
    // Sanitize all incoming params
    const params = sanitizeParams(params);

    const runtime = await loadBlueBubblesActionsRuntime();
    const account = resolveBlueBubblesAccount({
      cfg: cfg,
      accountId: accountId ?? undefined,
    });
    const baseUrl = normalizeSecretInputString(account.config.serverUrl);
    const password = normalizeSecretInputString(account.config.password);
    const opts = { cfg: cfg, accountId: accountId ?? undefined };
    const assertPrivateApiEnabled = () => {
      if (getCachedBlueBubblesPrivateApiStatus(account.accountId) === false) {
        throw new Error(
          `BlueBubbles ${action} requires Private API, but it is disabled on the BlueBubbles server.`,
        );
      }
    };

    // Helper to resolve chatGuid from various params or session context
    const resolveChatGuid = async (): Promise<string> => {
      const chatGuid = readStringParam(params, "chatGuid");
      if (chatGuid?.trim()) {
        const sanitizedChatGuid = sanitizeParam(chatGuid);
        if (!sanitizedChatGuid) throw new Error("Invalid chatGuid value.");
        return sanitizedChatGuid;
      }

      const chatIdentifier = readStringParam(params, "chatIdentifier");
      const chatId = readNumberParam(params, "chatId", { integer: true });
      const to = readStringParam(params, "to");
      // Fall back to session context if no explicit target provided
      const contextTarget = toolContext?.currentChannelId?.trim();

      const sanitizedChatIdentifier = sanitizeParam(chatIdentifier);
      const sanitizedTo = sanitizeParam(to);
      const sanitizedContextTarget = sanitizeParam(contextTarget);

      const target = sanitizedChatIdentifier
        ? ({
            kind: "chat_identifier",
            chatIdentifier: sanitizedChatIdentifier,
          } as BlueBubblesSendTarget)
        : typeof chatId === "number"
          ? ({ kind: "chat_id", chatId } as BlueBubblesSendTarget)
          : sanitizedTo
            ? mapTarget(sanitizedTo)
            : sanitizedContextTarget
              ? mapTarget(sanitizedContextTarget)
              : null;

      if (!target) {
        throw new Error(`BlueBubbles ${action} requires chatGuid, chatIdentifier, chatId, or to.`);
      }
      if (!baseUrl || !password) {
        throw new Error(`BlueBubbles ${action} requires serverUrl and password.`);
      }

      const resolved = await runtime.resolveChatGuidForTarget({
        baseUrl,
        password,
        target,
        allowPrivateNetwork: account.config.allowPrivateNetwork === true,
      });
      if (!resolved) {
        throw new Error(`BlueBubbles ${action} failed: chatGuid not found for target.`);
      }
      return resolved;
    };

    // Handle react action
    if (action === "react") {
      assertPrivateApiEnabled();
      const { emoji, remove, isEmpty } = readReactionParams(params, {
        removeErrorMessage: "Emoji is required to remove a BlueBubbles reaction.",
      });
      if (isEmpty && !remove) {
        throw new Error(
          "BlueBubbles react requires emoji parameter. Use action=react with emoji=<emoji> and messageId=<message_id>.",
        );
      }
      const rawMessageId = readStringParam(params, "messageId");
      if (!rawMessageId) {
        throw new Error(
          "BlueBubbles react requires messageId parameter (the message ID to react to). " +
            "Use action=react with messageId=<message_id>, emoji=<emoji>, and to/chatGuid to identify the chat.",
        );
      }
      const sanitizedMessageId = sanitizeParam(rawMessageId);
      if (!sanitizedMessageId) throw new Error("Invalid messageId value.");
      // Resolve short ID (e.g., "1", "2") to full UUID
      const messageId = runtime.resolveBlueBubblesMessageId(sanitizedMessageId, {
        requireKnownShortId: true,
      });
      const partIndex = readNumberParam(params, "partIndex", { integer: true });
      const resolvedChatGuid = await resolveChatGuid();

      await runtime.sendBlueBubblesReaction({
        chatGuid: resolvedChatGuid,
        messageGuid: messageId,
        emoji,
        remove: remove || undefined,
        partIndex: typeof partIndex === "number" ? partIndex : undefined,
        opts,
      });

      return jsonResult({ ok: true, ...(remove ? { removed: true } : { added: emoji }) });
    }

    // Handle edit action
    if (action === "edit") {
      assertPrivateApiEnabled();
      // Edit is not supported on macOS 26+
      if (isMacOS26OrHigher(accountId ?? undefined)) {
        throw new Error(
          "BlueBubbles edit is not supported on macOS 26 or higher. " +
            "Apple removed the ability to edit iMessages in this version.",
        );
      }
      const rawMessageId = readStringParam(params, "messageId");
      const newText =
        readStringParam(params, "text") ??
        readStringParam(params, "newText") ??
        readStringParam(params, "message");
      if (!rawMessageId || !newText) {
        const missing: string[] = [];
        if (!rawMessageId) {
          missing.push("messageId (the message ID to edit)");
        }
        if (!newText) {
          missing.push("text (the new message content)");
        }
        throw new Error(
          `BlueBubbles edit requires: ${missing.join(", ")}. ` +
            `Use action=edit with messageId=<message_id>, text=<new_content>.`,
        );
      }
      const sanitizedMessageId = sanitizeParam(rawMessageId);
      if (!sanitizedMessageId) throw new Error("Invalid messageId value.");
      const sanitizedNewText = sanitizeParam(newText);
      if (!sanitizedNewText) throw new Error("Invalid text value.");
      validateLength(sanitizedNewText, 10000, "text");
      // Resolve short ID (e.g., "1", "2") to full UUID
      const messageId = runtime.resolveBlueBubblesMessageId(sanitizedMessageId, {
        requireKnownShortId: true,
      });
      const partIndex = readNumberParam(params, "partIndex", { integer: true });
      const backwardsCompatMessage = readStringParam(params, "backwardsCompatMessage");
      const sanitizedBackwardsCompatMessage = sanitizeParam(backwardsCompatMessage);

      await runtime.editBlueBubblesMessage(messageId, sanitizedNewText, {
        ...opts,
        partIndex: typeof partIndex === "number" ? partIndex : undefined,
        backwardsCompatMessage: sanitizedBackwardsCompatMessage ?? undefined,
      });

      return jsonResult({ ok: true, edited: rawMessageId });
    }

    // Handle unsend action
    if (action === "unsend") {
      assertPrivateApiEnabled();
      const rawMessageId = readStringParam(params, "messageId");
      if (!rawMessageId) {
        throw new Error(
          "BlueBubbles unsend requires messageId parameter (the message ID to unsend). " +
            "Use action=unsend with messageId=<message_id>.",
        );
      }
      const sanitizedMessageId = sanitizeParam(rawMessageId);
      if (!sanitizedMessageId) throw new Error("Invalid messageId value.");
      // Resolve short ID (e.g., "1", "2") to full UUID
      const messageId = runtime.resolveBlueBubblesMessageId(sanitizedMessageId, {
        requireKnownShortId: true,
      });
      const partIndex = readNumberParam(params, "partIndex", { integer: true });

      await runtime.unsendBlueBubblesMessage(messageId, {
        ...opts,
        partIndex: typeof partIndex === "number" ? partIndex : undefined,
      });

      return jsonResult({ ok: true, unsent: rawMessageId });
    }

    // Handle reply action
    if (action === "reply") {
      assertPrivateApiEnabled();
      const rawMessageId = readStringParam(params, "messageId");
      const text = readMessageText(params);
      const to = readStringParam(params, "to") ?? readStringParam(params, "target");
      if (!rawMessageId || !text || !to) {
        const missing: string[] = [];
        if (!rawMessageId) {
          missing.push("messageId (the message ID to reply to)");
        }
        if (!text) {
          missing.push("text or message (the reply message content)");
        }
        if (!to) {
          missing.push("to or target (the chat target)");
        }
        throw new Error(
          `BlueBubbles reply requires: ${missing.join(", ")}. ` +
            `Use action=reply with messageId=<message_id>, message=<your reply>, target=<chat_target>.`,
        );
      }
      const sanitizedMessageId = sanitizeParam(rawMessageId);
      if (!sanitizedMessageId) throw new Error("Invalid messageId value.");
      const sanitizedText = sanitizeParam(text);
      if (!sanitizedText) throw new Error("Invalid text value.");
      validateLength(sanitizedText, 10000, "text");
      const sanitizedTo = sanitizeParam(to);
      if (!sanitizedTo) throw new Error("Invalid to/target value.");
      // Resolve short ID (e.g., "1", "2") to full UUID
      const messageId = runtime.resolveBlueBubblesMessageId(sanitizedMessageId, {
        requireKnownShortId: true,
      });
      const partIndex = readNumberParam(params, "partIndex", { integer: true });

      const result = await runtime.sendMessageBlueBubbles(sanitizedTo, sanitizedText, {
        ...opts,
        replyToMessageGuid: messageId,
        replyToPartIndex: typeof partIndex === "number" ? partIndex : undefined,
      });

      return jsonResult({ ok: true, messageId: result.messageId, repliedTo: rawMessageId });
    }

    // Handle sendWithEffect action
    if (action === "sendWithEffect") {
      assertPrivateApiEnabled();
      const text = readMessageText(params);
      const to = readStringParam(params, "to") ?? readStringParam(params, "target");
      const effectId = readStringParam(params, "effectId") ?? readStringParam(params, "effect");
      if (!text || !to || !effectId) {
        const missing: string[] = [];
        if (!text) {
          missing.push("text or message (the message content)");
        }
        if (!to) {
          missing.push("to or target (the chat target)");
        }
        if (!effectId) {
          missing.push(
            "effectId or effect (e.g., slam, loud, gentle, invisible-ink, confetti, lasers, fireworks, balloons, heart)",
          );
        }
        throw new Error(
          `BlueBubbles sendWithEffect requires: ${missing.join(", ")}. ` +
            `Use action=sendWithEffect with message=<message>, target=<chat_target>, effectId=<effect_name>.`,
        );
      }
      const sanitizedText = sanitizeParam(text);
      if (!sanitizedText) throw new Error("Invalid text value.");
      validateLength(sanitizedText, 10000, "text");
      const sanitizedTo = sanitizeParam(to);
      if (!sanitizedTo) throw new Error("Invalid to/target value.");
      const sanitizedEffectId = sanitizeParam(effectId);
      if (!sanitizedEffectId) throw new Error("Invalid effectId value.");

      const result = await runtime.sendMessageBlueBubbles(sanitizedTo, sanitizedText, {
        ...opts,
        effectId: sanitizedEffectId,
      });

      return jsonResult({ ok: true, messageId: result.messageId, effect: sanitizedEffectId });
    }

    // Handle renameGroup action
    if (action === "renameGroup") {
      assertPrivateApiEnabled();
      const resolvedChatGuid = await resolveChatGuid();
      const displayName = readStringParam(params, "displayName") ?? readStringParam(params, "name");
      if (!displayName) {
        throw new Error("BlueBubbles renameGroup requires displayName or name parameter.");
      }
      const sanitizedDisplayName = sanitizeParam(displayName);
      if (!sanitizedDisplayName) throw new Error("Invalid displayName value.");
      validateLength(sanitizedDisplayName, 256, "displayName");

      await runtime.renameBlueBubblesChat(resolvedChatGuid, sanitizedDisplayName, opts);

      return jsonResult({ ok: true, renamed: resolvedChatGuid, displayName: sanitizedDisplayName });
    }

    // Handle setGroupIcon action
    if (action === "setGroupIcon") {
      assertPrivateApiEnabled();
      const resolvedChatGuid = await resolveChatGuid();
      const base64Buffer = readStringParam(params, "buffer");
      const filename =
        readStringParam(params, "filename") ?? readStringParam(params, "name") ?? "icon.png";
      const contentType =
        readStringParam(params, "contentType") ?? readStringParam(params, "mimeType");

      if (!base64Buffer) {
        throw new Error(
          "BlueBubbles setGroupIcon requires an image. " +
            "Use action=setGroupIcon with media=<image_url> or path=<local_file_path> to set the group icon.",
        );
      }

      // Validate base64 string length
      validateLength(base64Buffer, 10 * 1024 * 1024, "buffer");

      // Decode base64 to buffer
      let rawBuffer: Uint8Array;
      try {
        rawBuffer = Uint8Array.from(atob(base64Buffer), (c) => c.charCodeAt(0));
      } catch {
        throw new Error("BlueBubbles setGroupIcon: buffer is not valid base64.");
      }

      // Process uploaded file: scan for suspicious content and redact PII
      const sanitizedFilename = sanitizeParam(filename) ?? "icon.png";
      const buffer = processUploadedFileBuffer(rawBuffer, sanitizedFilename);
      const sanitizedContentType = sanitizeParam(contentType);

      await runtime.setGroupIconBlueBubbles(resolvedChatGuid, buffer, sanitizedFilename, {
        ...opts,
        contentType: sanitizedContentType ?? undefined,
      });

      return jsonResult({ ok: true, chatGuid: resolvedChatGuid, iconSet: true });
    }

    // Handle addParticipant action
    if (action === "addParticipant") {
      assertPrivateApiEnabled();
      const resolvedChatGuid = await resolveChatGuid();
      const address = readStringParam(params, "address") ?? readStringParam(params, "participant");
      if (!address) {
        throw new Error("BlueBubbles addParticipant requires address or participant parameter.");
      }
      const sanitizedAddress = sanitizeParam(address);
      if (!sanitizedAddress) throw new Error("Invalid address value.");

      await runtime.addBlueBubblesParticipant(resolvedChatGuid, sanitizedAddress, opts);

      return jsonResult({ ok: true, added: sanitizedAddress, chatGuid: resolvedChatGuid });
    }

    // Handle removeParticipant action
    if (action === "removeParticipant") {
      assertPrivateApiEnabled();
      const resolvedChatGuid = await resolveChatGuid();
      const address = readStringParam(params, "address") ?? readStringParam(params, "participant");
      if (!address) {
        throw new Error("BlueBubbles removeParticipant requires address or participant parameter.");
      }
      const sanitizedAddress = sanitizeParam(address);
      if (!sanitizedAddress) throw new Error("Invalid address value.");

      await runtime.removeBlueBubblesParticipant(resolvedChatGuid, sanitizedAddress, opts);

      return jsonResult({ ok: true, removed: sanitizedAddress, chatGuid: resolvedChatGuid });
    }

    // Handle leaveGroup action
    if (action === "leaveGroup") {
      assertPrivateApiEnabled();
      const resolvedChatGuid = await resolveChatGuid();

      await runtime.leaveBlueBubblesChat(resolvedChatGuid, opts);

      return jsonResult({ ok: true, left: resolvedChatGuid });
    }

    // Handle sendAttachment action (legacy) and upload-file (canonical)
    if (action === "sendAttachment" || action === "upload-file") {
      const to = readStringParam(params, "to", { required: true });
      const filename = readStringParam(params, "filename", { required: true });
      const caption = readStringParam(params, "caption") ?? readStringParam(params, "message");
      const contentType =
        readStringParam(params, "contentType") ?? readStringParam(params, "mimeType");
      const asVoice = readBooleanParam(params, "asVoice");

      const sanitizedTo = sanitizeParam(to);
      if (!sanitizedTo) throw new Error(`BlueBubbles ${action} requires a valid 'to' parameter.`);
      const sanitizedFilename = sanitizeParam(filename);
      if (!sanitizedFilename) throw new Error(`BlueBubbles ${action} requires a valid 'filename' parameter.`);
      validateLength(sanitizedFilename, 512, "filename");
      const sanitizedCaption = sanitizeParam(caption);
      if (sanitizedCaption) validateLength(sanitizedCaption, 10000, "caption");
      const sanitizedContentType = sanitizeParam(contentType);

      // Buffer can come from params.buffer (base64) or params.path (file path)
      const base64Buffer = readStringParam(params, "buffer");
      const filePath = readStringParam(params, "path") ?? readStringParam(params, "filePath");

      let buffer: Uint8Array;
      if (base64Buffer) {
        // Validate base64 string length (max ~75MB base64 → ~56MB binary)
        validateLength(base64Buffer, 75 * 1024 * 1024, "buffer");
        // Decode base64 to buffer
        let rawBuffer: Uint8Array;
        try {
          rawBuffer = Uint8Array.from(atob(base64Buffer), (c) => c.charCodeAt(0));
        } catch {
          throw new Error(`BlueBubbles ${action}: buffer is not valid base64.`);
        }
        // Process uploaded file: scan for suspicious content and redact PII
        buffer = processUploadedFileBuffer(rawBuffer, sanitizedFilename);
      } else if (filePath) {
        // Read file from path (will be handled by caller providing buffer)
        throw new Error(
          `BlueBubbles ${action}: filePath not supported in action, provide buffer as base64.`,
        );
      } else {
        throw new Error(`BlueBubbles ${action} requires buffer (base64) parameter.`);
      }

      const result = await runtime.sendBlueBubblesAttachment({
        to: sanitizedTo,
        buffer,
        filename: sanitizedFilename,
        contentType: sanitizedContentType ?? undefined,
        caption: sanitizedCaption ?? undefined,
        asVoice: asVoice ?? undefined,
        opts,
      });

      return jsonResult({ ok: true, messageId: result.messageId });
    }

    throw new Error(`Action ${action} is not supported for provider ${providerId}.`);
  },
};