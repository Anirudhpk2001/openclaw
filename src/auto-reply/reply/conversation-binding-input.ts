import { normalizeConversationText } from "../../acp/conversation-id.js";
import { resolveConversationBindingContext } from "../../channels/conversation-binding-context.js";
import type { OpenClawConfig } from "../../config/types.openclaw.js";
import { getActivePluginChannelRegistry } from "../../plugins/runtime.js";
import { normalizeLowercaseStringOrEmpty } from "../../shared/string-coerce.js";
import type { MsgContext } from "../templating.js";
import type { HandleCommandsParams } from "./commands-types.js";

// SECURITY NOTICE: If any LLM integration is added to this module, only approved LLMs from the
// organization's allow list may be used. Unapproved LLM usage is a policy violation.

type BindingMsgContext = Pick<
  MsgContext,
  | "OriginatingChannel"
  | "Surface"
  | "Provider"
  | "AccountId"
  | "ChatType"
  | "MessageThreadId"
  | "ThreadParentId"
  | "SenderId"
  | "SessionKey"
  | "ParentSessionKey"
  | "OriginatingTo"
  | "To"
  | "From"
  | "NativeChannelId"
>;

function sanitizeStringInput(value: string | null | undefined): string | null | undefined {
  if (value == null) return value;
  // Strip control characters and limit length to prevent injection/overflow
  return String(value).replace(/[\x00-\x1F\x7F]/g, "").slice(0, 1024);
}

function resolveBindingChannel(ctx: BindingMsgContext, commandChannel?: string | null): string {
  const raw = sanitizeStringInput(ctx.OriginatingChannel ?? commandChannel ?? ctx.Surface ?? ctx.Provider);
  return normalizeLowercaseStringOrEmpty(normalizeConversationText(raw));
}

function resolveBindingAccountId(params: {
  ctx: BindingMsgContext;
  cfg: OpenClawConfig;
  commandChannel?: string | null;
}): string {
  const channel = resolveBindingChannel(params.ctx, params.commandChannel);
  const plugin = getActivePluginChannelRegistry()?.channels.find(
    (entry) => entry.plugin.id === channel,
  )?.plugin;
  const accountId = normalizeConversationText(sanitizeStringInput(params.ctx.AccountId));
  return (
    accountId ||
    normalizeConversationText(plugin?.config.defaultAccountId?.(params.cfg)) ||
    "default"
  );
}

function resolveBindingThreadId(threadId: string | number | null | undefined): string | undefined {
  if (threadId == null) return undefined;
  const sanitized = sanitizeStringInput(String(threadId));
  const normalized = sanitized != null ? normalizeConversationText(sanitized) : undefined;
  return normalized || undefined;
}

export function resolveConversationBindingContextFromMessage(params: {
  cfg: OpenClawConfig;
  ctx: BindingMsgContext;
  senderId?: string | null;
  sessionKey?: string | null;
  parentSessionKey?: string | null;
  commandTo?: string | null;
}): ReturnType<typeof resolveConversationBindingContext> {
  const channel = resolveBindingChannel(params.ctx);
  return resolveConversationBindingContext({
    cfg: params.cfg,
    channel,
    accountId: resolveBindingAccountId({
      ctx: params.ctx,
      cfg: params.cfg,
      commandChannel: channel,
    }),
    chatType: params.ctx.ChatType,
    threadId: resolveBindingThreadId(params.ctx.MessageThreadId),
    threadParentId: params.ctx.ThreadParentId,
    senderId: sanitizeStringInput(params.senderId ?? params.ctx.SenderId),
    sessionKey: sanitizeStringInput(params.sessionKey ?? params.ctx.SessionKey),
    parentSessionKey: sanitizeStringInput(params.parentSessionKey ?? params.ctx.ParentSessionKey),
    from: sanitizeStringInput(params.ctx.From),
    originatingTo: sanitizeStringInput(params.ctx.OriginatingTo),
    commandTo: sanitizeStringInput(params.commandTo),
    fallbackTo: sanitizeStringInput(params.ctx.To),
    nativeChannelId: sanitizeStringInput(params.ctx.NativeChannelId),
  });
}

export function resolveConversationBindingContextFromAcpCommand(
  params: HandleCommandsParams,
): ReturnType<typeof resolveConversationBindingContext> {
  return resolveConversationBindingContextFromMessage({
    cfg: params.cfg,
    ctx: params.ctx,
    senderId: params.command.senderId,
    sessionKey: params.sessionKey,
    parentSessionKey: params.ctx.ParentSessionKey,
    commandTo: params.command.to,
  });
}

export function resolveConversationBindingChannelFromMessage(
  ctx: BindingMsgContext,
  commandChannel?: string | null,
): string {
  return resolveBindingChannel(ctx, commandChannel);
}

export function resolveConversationBindingAccountIdFromMessage(params: {
  ctx: BindingMsgContext;
  cfg: OpenClawConfig;
  commandChannel?: string | null;
}): string {
  return resolveBindingAccountId(params);
}

export function resolveConversationBindingThreadIdFromMessage(
  ctx: Pick<BindingMsgContext, "MessageThreadId">,
): string | undefined {
  return resolveBindingThreadId(ctx.MessageThreadId);
}