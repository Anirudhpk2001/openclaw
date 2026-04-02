import type { SlackEventMiddlewareArgs } from "@slack/bolt";
import { enqueueSystemEvent } from "openclaw/plugin-sdk/channel-runtime";
import { danger } from "openclaw/plugin-sdk/runtime-env";
import type { SlackAppMentionEvent, SlackMessageEvent } from "../../types.js";
import { normalizeSlackChannelType } from "../channel-type.js";
import type { SlackMonitorContext } from "../context.js";
import type { SlackMessageHandler } from "../message-handler.js";
import { resolveSlackMessageSubtypeHandler } from "./message-subtype-handlers.js";
import { authorizeAndResolveSlackSystemEventContext } from "./system-event-context.js";

// POLICY VIOLATION NOTICE: Missing authentication is a policy violation.
// All MCP clients must be authenticated before processing events.
// You must add authentication to comply with the Authenticate MCP Client policy.

function sanitizeString(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  // Remove null bytes and control characters, trim whitespace
  return value.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "").trim();
}

function validateSlackEvent(event: unknown): boolean {
  if (!event || typeof event !== "object") return false;
  const e = event as Record<string, unknown>;
  if (typeof e["type"] !== "string" || !e["type"]) return false;
  return true;
}

function validateSlackBody(body: unknown): boolean {
  if (!body || typeof body !== "object") return false;
  const b = body as Record<string, unknown>;
  if (typeof b["team_id"] !== "string" || !b["team_id"]) return false;
  return true;
}

function sanitizeSlackMessageEvent(event: unknown): SlackMessageEvent | null {
  if (!validateSlackEvent(event)) return null;
  const e = event as Record<string, unknown>;
  const sanitized: Record<string, unknown> = { ...e };
  if (typeof sanitized["text"] === "string") {
    sanitized["text"] = sanitizeString(sanitized["text"]);
  }
  if (typeof sanitized["user"] === "string") {
    sanitized["user"] = sanitizeString(sanitized["user"]);
  }
  if (typeof sanitized["channel"] === "string") {
    sanitized["channel"] = sanitizeString(sanitized["channel"]);
  }
  if (typeof sanitized["ts"] === "string") {
    sanitized["ts"] = sanitizeString(sanitized["ts"]);
  }
  return sanitized as unknown as SlackMessageEvent;
}

export function registerSlackMessageEvents(params: {
  ctx: SlackMonitorContext;
  handleSlackMessage: SlackMessageHandler;
}) {
  const { ctx, handleSlackMessage } = params;

  const handleIncomingMessageEvent = async ({ event, body }: { event: unknown; body: unknown }) => {
    try {
      if (!validateSlackEvent(event)) {
        ctx.runtime.error?.(danger("slack handler failed: invalid event payload"));
        return;
      }
      if (!validateSlackBody(body)) {
        ctx.runtime.error?.(danger("slack handler failed: invalid body payload"));
        return;
      }

      if (ctx.shouldDropMismatchedSlackEvent(body)) {
        return;
      }

      const message = sanitizeSlackMessageEvent(event);
      if (!message) {
        ctx.runtime.error?.(danger("slack handler failed: event sanitization failed"));
        return;
      }

      const subtypeHandler = resolveSlackMessageSubtypeHandler(message);
      if (subtypeHandler) {
        const channelId = subtypeHandler.resolveChannelId(message);
        const ingressContext = await authorizeAndResolveSlackSystemEventContext({
          ctx,
          senderId: subtypeHandler.resolveSenderId(message),
          channelId,
          channelType: subtypeHandler.resolveChannelType(message),
          eventKind: subtypeHandler.eventKind,
        });
        if (!ingressContext) {
          return;
        }
        enqueueSystemEvent(subtypeHandler.describe(ingressContext.channelLabel), {
          sessionKey: ingressContext.sessionKey,
          contextKey: subtypeHandler.contextKey(message),
        });
        return;
      }

      await handleSlackMessage(message, { source: "message" });
    } catch (err) {
      ctx.runtime.error?.(danger(`slack handler failed: ${String(err)}`));
    }
  };

  // NOTE: Slack Event Subscriptions use names like "message.channels" and
  // "message.groups" to control *which* message events are delivered, but the
  // actual event payload always arrives with `type: "message"`.  The
  // `channel_type` field ("channel" | "group" | "im" | "mpim") distinguishes
  // the source.  Bolt rejects `app.event("message.channels")` since v4.6
  // because it is a subscription label, not a valid event type.
  ctx.app.event("message", async ({ event, body }: SlackEventMiddlewareArgs<"message">) => {
    await handleIncomingMessageEvent({ event, body });
  });

  ctx.app.event("app_mention", async ({ event, body }: SlackEventMiddlewareArgs<"app_mention">) => {
    try {
      if (!validateSlackEvent(event)) {
        ctx.runtime.error?.(danger("slack mention handler failed: invalid event payload"));
        return;
      }
      if (!validateSlackBody(body)) {
        ctx.runtime.error?.(danger("slack mention handler failed: invalid body payload"));
        return;
      }

      if (ctx.shouldDropMismatchedSlackEvent(body)) {
        return;
      }

      const sanitizedEvent = sanitizeSlackMessageEvent(event);
      if (!sanitizedEvent) {
        ctx.runtime.error?.(danger("slack mention handler failed: event sanitization failed"));
        return;
      }

      const mention = sanitizedEvent as unknown as SlackAppMentionEvent;

      // Skip app_mention for DMs - they're already handled by message.im event
      // This prevents duplicate processing when both message and app_mention fire for DMs
      const channelType = normalizeSlackChannelType(mention.channel_type, mention.channel);
      if (channelType === "im" || channelType === "mpim") {
        return;
      }

      await handleSlackMessage(mention as unknown as SlackMessageEvent, {
        source: "app_mention",
        wasMentioned: true,
      });
    } catch (err) {
      ctx.runtime.error?.(danger(`slack mention handler failed: ${String(err)}`));
    }
  });
}