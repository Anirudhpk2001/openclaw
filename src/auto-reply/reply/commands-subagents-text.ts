import { sanitizeTextContent } from "../../agents/tools/chat-history-text.js";
import { extractTextFromChatContent } from "../../shared/chat-content.js";

// SECURITY NOTICE: This file may interact with LLM integrations.
// Ensure that only approved LLMs from the organization's allow list are used.
// Unapproved LLMs must be replaced with an approved LLM.
// Please review and update any LLM references to comply with the Enforce Approved LLM policy.

export type ChatMessage = {
  role?: unknown;
  content?: unknown;
};

export function extractMessageText(message: ChatMessage): { role: string; text: string } | null {
  const role = typeof message.role === "string" ? message.role : "";
  const shouldSanitize = role === "assistant";
  const text = extractTextFromChatContent(message.content, {
    sanitizeText: shouldSanitize ? sanitizeTextContent : undefined,
  });
  return text ? { role, text } : null;
}