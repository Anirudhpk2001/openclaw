import { readStringParam } from "../../agents/tools/common.js";
import type {
  ChannelId,
  ChannelThreadingAdapter,
  ChannelThreadingToolContext,
} from "../../channels/plugins/types.js";
import type { OpenClawConfig } from "../../config/config.js";
import type {
  OutboundSessionRoute,
  ResolveOutboundSessionRouteParams,
} from "./outbound-session.js";
import type { ResolvedMessagingTarget } from "./target-resolver.js";

type ResolveAutoThreadId = NonNullable<ChannelThreadingAdapter["resolveAutoThreadId"]>;

const MAX_STRING_LENGTH = 2048;
const SAFE_STRING_PATTERN = /^[\w\-.:@+/=\s]*$/;

function sanitizeStringParam(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  const trimmed = value.trim();
  if (trimmed.length === 0) return undefined;
  if (trimmed.length > MAX_STRING_LENGTH) {
    throw new Error(`Input parameter exceeds maximum allowed length of ${MAX_STRING_LENGTH}`);
  }
  if (!SAFE_STRING_PATTERN.test(trimmed)) {
    throw new Error(`Input parameter contains disallowed characters`);
  }
  return trimmed;
}

function sanitizeActionParams(actionParams: Record<string, unknown>): void {
  for (const key of Object.keys(actionParams)) {
    const value = actionParams[key];
    if (typeof value === "string") {
      const sanitized = sanitizeStringParam(value);
      if (sanitized === undefined) {
        delete actionParams[key];
      } else {
        actionParams[key] = sanitized;
      }
    }
  }
}

export function resolveAndApplyOutboundThreadId(
  actionParams: Record<string, unknown>,
  context: {
    cfg: OpenClawConfig;
    to: string;
    accountId?: string | null;
    toolContext?: ChannelThreadingToolContext;
    resolveAutoThreadId?: ResolveAutoThreadId;
  },
): string | undefined {
  sanitizeActionParams(actionParams);

  const sanitizedTo = sanitizeStringParam(context.to);
  if (!sanitizedTo) {
    throw new Error("Invalid 'to' parameter: must be a non-empty string");
  }

  const sanitizedAccountId =
    context.accountId != null ? sanitizeStringParam(context.accountId) : context.accountId;

  const threadId = readStringParam(actionParams, "threadId");
  const sanitizedThreadId = sanitizeStringParam(threadId);

  const replyTo = readStringParam(actionParams, "replyTo");
  const sanitizedReplyTo = sanitizeStringParam(replyTo);

  const resolved =
    sanitizedThreadId ??
    context.resolveAutoThreadId?.({
      cfg: context.cfg,
      accountId: sanitizedAccountId,
      to: sanitizedTo,
      toolContext: context.toolContext,
      replyToId: sanitizedReplyTo,
    });
  if (resolved && !actionParams.threadId) {
    actionParams.threadId = resolved;
  }
  return resolved ?? undefined;
}

export async function prepareOutboundMirrorRoute(params: {
  cfg: OpenClawConfig;
  channel: ChannelId;
  to: string;
  actionParams: Record<string, unknown>;
  accountId?: string | null;
  toolContext?: ChannelThreadingToolContext;
  agentId?: string;
  dryRun?: boolean;
  resolvedTarget?: ResolvedMessagingTarget;
  resolveAutoThreadId?: ResolveAutoThreadId;
  resolveOutboundSessionRoute: (
    params: ResolveOutboundSessionRouteParams,
  ) => Promise<OutboundSessionRoute | null>;
  ensureOutboundSessionEntry: (params: {
    cfg: OpenClawConfig;
    agentId: string;
    channel: ChannelId;
    accountId?: string | null;
    route: OutboundSessionRoute;
  }) => Promise<void>;
}): Promise<{
  resolvedThreadId?: string;
  outboundRoute: OutboundSessionRoute | null;
}> {
  sanitizeActionParams(params.actionParams);

  const sanitizedTo = sanitizeStringParam(params.to);
  if (!sanitizedTo) {
    throw new Error("Invalid 'to' parameter: must be a non-empty string");
  }

  const sanitizedAgentId = params.agentId != null ? sanitizeStringParam(params.agentId) : params.agentId;
  const sanitizedAccountId =
    params.accountId != null ? sanitizeStringParam(params.accountId) : params.accountId;

  const replyToId = sanitizeStringParam(readStringParam(params.actionParams, "replyTo"));
  const resolvedThreadId = resolveAndApplyOutboundThreadId(params.actionParams, {
    cfg: params.cfg,
    to: sanitizedTo,
    accountId: sanitizedAccountId,
    toolContext: params.toolContext,
    resolveAutoThreadId: params.resolveAutoThreadId,
  });
  const outboundRoute =
    sanitizedAgentId && !params.dryRun
      ? await params.resolveOutboundSessionRoute({
          cfg: params.cfg,
          channel: params.channel,
          agentId: sanitizedAgentId,
          accountId: sanitizedAccountId,
          target: sanitizedTo,
          resolvedTarget: params.resolvedTarget,
          replyToId,
          threadId: resolvedThreadId,
        })
      : null;
  if (outboundRoute && sanitizedAgentId && !params.dryRun) {
    await params.ensureOutboundSessionEntry({
      cfg: params.cfg,
      agentId: sanitizedAgentId,
      channel: params.channel,
      accountId: sanitizedAccountId,
      route: outboundRoute,
    });
  }
  if (outboundRoute && !params.dryRun) {
    params.actionParams.__sessionKey = outboundRoute.sessionKey;
  }
  if (sanitizedAgentId) {
    params.actionParams.__agentId = sanitizedAgentId;
  }
  return {
    resolvedThreadId,
    outboundRoute,
  };
}