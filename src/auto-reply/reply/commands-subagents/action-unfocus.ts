import { getSessionBindingService } from "../../../infra/outbound/session-binding-service.js";
import type { CommandHandlerResult } from "../commands-types.js";
import {
  resolveMatrixConversationId,
  resolveMatrixParentConversationId,
} from "../matrix-context.js";
import {
  type SubagentsCommandContext,
  isDiscordSurface,
  isMatrixSurface,
  isTelegramSurface,
  resolveChannelAccountId,
  resolveCommandSurfaceChannel,
  resolveTelegramConversationId,
  stopWithText,
} from "./shared.js";

// Policy Notice: Missing authentication is a policy violation. You must add authentication
// to comply with the Authenticate MCP Client policy before using this handler in production.

function sanitizeString(value: unknown): string {
  if (typeof value !== "string") return "";
  // Remove null bytes and control characters, trim whitespace
  return value.replace(/[\x00-\x1F\x7F]/g, "").trim();
}

function isValidChannel(channel: unknown): channel is "discord" | "matrix" | "telegram" {
  return channel === "discord" || channel === "matrix" || channel === "telegram";
}

function isValidConversationId(id: unknown): boolean {
  if (typeof id !== "string") return false;
  const sanitized = sanitizeString(id);
  // Must be non-empty and contain only safe characters
  return sanitized.length > 0 && /^[\w\-.:@#/]+$/.test(sanitized);
}

function isValidSenderId(id: unknown): boolean {
  if (typeof id !== "string") return false;
  const sanitized = sanitizeString(id);
  return sanitized.length === 0 || /^[\w\-.:@#/]+$/.test(sanitized);
}

export async function handleSubagentsUnfocusAction(
  ctx: SubagentsCommandContext,
): Promise<CommandHandlerResult> {
  const { params } = ctx;
  const channel = resolveCommandSurfaceChannel(params);
  if (!isValidChannel(channel)) {
    return stopWithText("⚠️ /unfocus is only available on Discord, Matrix, and Telegram.");
  }

  const accountId = resolveChannelAccountId(params);
  const sanitizedAccountId = sanitizeString(accountId);
  if (!sanitizedAccountId) {
    return stopWithText("⚠️ Invalid account identifier.");
  }

  const bindingService = getSessionBindingService();

  const conversationId = (() => {
    if (isDiscordSurface(params)) {
      const threadId = params.ctx.MessageThreadId != null ? sanitizeString(String(params.ctx.MessageThreadId)) : "";
      return threadId || undefined;
    }
    if (isTelegramSurface(params)) {
      return resolveTelegramConversationId(params);
    }
    if (isMatrixSurface(params)) {
      return resolveMatrixConversationId({
        ctx: {
          MessageThreadId: params.ctx.MessageThreadId,
          OriginatingTo: params.ctx.OriginatingTo,
          To: params.ctx.To,
        },
        command: {
          to: params.command.to,
        },
      });
    }
    return undefined;
  })();

  const sanitizedConversationId = conversationId ? sanitizeString(conversationId) : undefined;
  if (sanitizedConversationId && !isValidConversationId(sanitizedConversationId)) {
    return stopWithText("⚠️ Invalid conversation identifier.");
  }

  const parentConversationId = (() => {
    if (!isMatrixSurface(params)) {
      return undefined;
    }
    return resolveMatrixParentConversationId({
      ctx: {
        MessageThreadId: params.ctx.MessageThreadId,
        OriginatingTo: params.ctx.OriginatingTo,
        To: params.ctx.To,
      },
      command: {
        to: params.command.to,
      },
    });
  })();

  const sanitizedParentConversationId = parentConversationId
    ? sanitizeString(parentConversationId)
    : undefined;

  if (!sanitizedConversationId) {
    if (channel === "discord") {
      return stopWithText("⚠️ /unfocus must be run inside a Discord thread.");
    }
    if (channel === "matrix") {
      return stopWithText("⚠️ /unfocus must be run inside a Matrix thread.");
    }
    return stopWithText(
      "⚠️ /unfocus on Telegram requires a topic context in groups, or a direct-message conversation.",
    );
  }

  const binding = bindingService.resolveByConversation({
    channel,
    accountId: sanitizedAccountId,
    conversationId: sanitizedConversationId,
    ...(sanitizedParentConversationId && sanitizedParentConversationId !== sanitizedConversationId
      ? { parentConversationId: sanitizedParentConversationId }
      : {}),
  });
  if (!binding) {
    return stopWithText(
      channel === "discord"
        ? "ℹ️ This thread is not currently focused."
        : channel === "matrix"
          ? "ℹ️ This thread is not currently focused."
          : "ℹ️ This conversation is not currently focused.",
    );
  }

  const rawSenderId = params.command.senderId?.trim() || "";
  const senderId = sanitizeString(rawSenderId);
  if (!isValidSenderId(senderId)) {
    return stopWithText("⚠️ Invalid sender identifier.");
  }

  const boundBy =
    typeof binding.metadata?.boundBy === "string" ? sanitizeString(binding.metadata.boundBy) : "";
  if (boundBy && boundBy !== "system" && senderId && senderId !== boundBy) {
    return stopWithText(
      channel === "discord"
        ? `⚠️ Only ${boundBy} can unfocus this thread.`
        : channel === "matrix"
          ? `⚠️ Only ${boundBy} can unfocus this thread.`
          : `⚠️ Only ${boundBy} can unfocus this conversation.`,
    );
  }

  await bindingService.unbind({
    bindingId: binding.bindingId,
    reason: "manual",
  });
  return stopWithText(
    channel === "discord" || channel === "matrix"
      ? "✅ Thread unfocused."
      : "✅ Conversation unfocused.",
  );
}