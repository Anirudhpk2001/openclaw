import {
  extractHandleFromChatGuid,
  normalizeBlueBubblesHandle,
  parseBlueBubblesTarget,
} from "./targets.js";

const MAX_CONVERSATION_ID_LENGTH = 1024;
const SAFE_CONVERSATION_ID_PATTERN = /^[\w\s@.+\-:;,()[\]{}'"!?#$%^&*=|/<>~`\\]+$/;

function sanitizeConversationId(input: string): string | null {
  if (typeof input !== "string") {
    return null;
  }
  const trimmed = input.trim();
  if (!trimmed) {
    return null;
  }
  if (trimmed.length > MAX_CONVERSATION_ID_LENGTH) {
    return null;
  }
  // Remove null bytes and control characters
  const sanitized = trimmed.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
  if (!sanitized) {
    return null;
  }
  return sanitized;
}

export function normalizeBlueBubblesAcpConversationId(
  conversationId: string,
): { conversationId: string } | null {
  const sanitized = sanitizeConversationId(conversationId);
  if (!sanitized) {
    return null;
  }

  try {
    const parsed = parseBlueBubblesTarget(sanitized);
    if (parsed.kind === "handle") {
      const handle = normalizeBlueBubblesHandle(parsed.to);
      return handle ? { conversationId: handle } : null;
    }
    if (parsed.kind === "chat_id") {
      const chatIdStr = String(parsed.chatId);
      if (!/^\d+$/.test(chatIdStr)) {
        return null;
      }
      return { conversationId: chatIdStr };
    }
    if (parsed.kind === "chat_guid") {
      const handle = extractHandleFromChatGuid(parsed.chatGuid);
      return {
        conversationId: handle || parsed.chatGuid,
      };
    }
    return { conversationId: parsed.chatIdentifier };
  } catch {
    const handle = normalizeBlueBubblesHandle(sanitized);
    return handle ? { conversationId: handle } : null;
  }
}

export function matchBlueBubblesAcpConversation(params: {
  bindingConversationId: string;
  conversationId: string;
}): { conversationId: string; matchPriority: number } | null {
  if (
    typeof params.bindingConversationId !== "string" ||
    typeof params.conversationId !== "string"
  ) {
    return null;
  }
  const binding = normalizeBlueBubblesAcpConversationId(params.bindingConversationId);
  const conversation = normalizeBlueBubblesAcpConversationId(params.conversationId);
  if (!binding || !conversation) {
    return null;
  }
  if (binding.conversationId !== conversation.conversationId) {
    return null;
  }
  return {
    conversationId: conversation.conversationId,
    matchPriority: 2,
  };
}

export function resolveBlueBubblesInboundConversationId(params: {
  isGroup: boolean;
  sender: string;
  chatId?: number | null;
  chatGuid?: string | null;
  chatIdentifier?: string | null;
}): string | undefined {
  if (typeof params.sender !== "string") {
    return undefined;
  }

  if (!params.isGroup) {
    const sanitizedSender = sanitizeConversationId(params.sender);
    if (!sanitizedSender) {
      return undefined;
    }
    const sender = normalizeBlueBubblesHandle(sanitizedSender);
    return sender || undefined;
  }

  const sanitizedChatGuid =
    params.chatGuid != null ? sanitizeConversationId(params.chatGuid) : null;
  const sanitizedChatIdentifier =
    params.chatIdentifier != null ? sanitizeConversationId(params.chatIdentifier) : null;

  const normalized =
    (sanitizedChatGuid &&
      normalizeBlueBubblesAcpConversationId(sanitizedChatGuid)?.conversationId) ||
    (sanitizedChatIdentifier &&
      normalizeBlueBubblesAcpConversationId(sanitizedChatIdentifier)?.conversationId) ||
    (params.chatId != null && Number.isFinite(params.chatId) ? String(params.chatId) : "");
  return normalized || undefined;
}

export function resolveBlueBubblesConversationIdFromTarget(target: string): string | undefined {
  if (typeof target !== "string") {
    return undefined;
  }
  return normalizeBlueBubblesAcpConversationId(target)?.conversationId;
}