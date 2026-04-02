import type { SlackEventMiddlewareArgs } from "@slack/bolt";
import { resolveChannelConfigWrites } from "openclaw/plugin-sdk/channel-config-writes";
import { enqueueSystemEvent } from "openclaw/plugin-sdk/channel-runtime";
import { loadConfig, writeConfigFile } from "openclaw/plugin-sdk/config-runtime";
import { danger, warn } from "openclaw/plugin-sdk/runtime-env";
import { migrateSlackChannelConfig } from "../../channel-migration.js";
import { resolveSlackChannelLabel } from "../channel-config.js";
import type { SlackMonitorContext } from "../context.js";
import type {
  SlackChannelCreatedEvent,
  SlackChannelIdChangedEvent,
  SlackChannelRenamedEvent,
} from "../types.js";

const CHANNEL_ID_PATTERN = /^[A-Z0-9]{1,32}$/i;
const CHANNEL_NAME_PATTERN = /^[a-z0-9_\-]{1,80}$/;

function sanitizeChannelId(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  if (!CHANNEL_ID_PATTERN.test(trimmed)) return undefined;
  return trimmed;
}

function sanitizeChannelName(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim().toLowerCase();
  if (!CHANNEL_NAME_PATTERN.test(trimmed)) return undefined;
  return trimmed;
}

function sanitizeString(value: unknown): string {
  if (typeof value !== "string") return "unknown";
  return value.replace(/[^\w\s\-.:@#]/g, "").slice(0, 256);
}

export function registerSlackChannelEvents(params: {
  ctx: SlackMonitorContext;
  trackEvent?: () => void;
}) {
  const { ctx, trackEvent } = params;

  const enqueueChannelSystemEvent = (params: {
    kind: "created" | "renamed";
    channelId: string | undefined;
    channelName: string | undefined;
  }) => {
    if (
      !ctx.isChannelAllowed({
        channelId: params.channelId,
        channelName: params.channelName,
        channelType: "channel",
      })
    ) {
      return;
    }

    const label = resolveSlackChannelLabel({
      channelId: params.channelId,
      channelName: params.channelName,
    });
    const sessionKey = ctx.resolveSlackSystemEventSessionKey({
      channelId: params.channelId,
      channelType: "channel",
    });
    enqueueSystemEvent(`Slack channel ${params.kind}: ${label}.`, {
      sessionKey,
      contextKey: `slack:channel:${params.kind}:${params.channelId ?? params.channelName ?? "unknown"}`,
    });
  };

  ctx.app.event(
    "channel_created",
    async ({ event, body }: SlackEventMiddlewareArgs<"channel_created">) => {
      try {
        if (ctx.shouldDropMismatchedSlackEvent(body)) {
          return;
        }
        trackEvent?.();

        const payload = event as SlackChannelCreatedEvent;
        const channelId = sanitizeChannelId(payload.channel?.id);
        const channelName = sanitizeChannelName(payload.channel?.name);
        if (!channelId && !channelName) {
          ctx.runtime.error?.(danger(`slack channel created handler: invalid or missing channel id/name`));
          return;
        }
        enqueueChannelSystemEvent({ kind: "created", channelId, channelName });
      } catch (err) {
        ctx.runtime.error?.(danger(`slack channel created handler failed: ${sanitizeString(String(err))}`));
      }
    },
  );

  ctx.app.event(
    "channel_rename",
    async ({ event, body }: SlackEventMiddlewareArgs<"channel_rename">) => {
      try {
        if (ctx.shouldDropMismatchedSlackEvent(body)) {
          return;
        }
        trackEvent?.();

        const payload = event as SlackChannelRenamedEvent;
        const channelId = sanitizeChannelId(payload.channel?.id);
        const channelName = sanitizeChannelName(payload.channel?.name_normalized ?? payload.channel?.name);
        if (!channelId && !channelName) {
          ctx.runtime.error?.(danger(`slack channel rename handler: invalid or missing channel id/name`));
          return;
        }
        enqueueChannelSystemEvent({ kind: "renamed", channelId, channelName });
      } catch (err) {
        ctx.runtime.error?.(danger(`slack channel rename handler failed: ${sanitizeString(String(err))}`));
      }
    },
  );

  ctx.app.event(
    "channel_id_changed",
    async ({ event, body }: SlackEventMiddlewareArgs<"channel_id_changed">) => {
      try {
        if (ctx.shouldDropMismatchedSlackEvent(body)) {
          return;
        }
        trackEvent?.();

        const payload = event as SlackChannelIdChangedEvent;
        const oldChannelId = sanitizeChannelId(payload.old_channel_id);
        const newChannelId = sanitizeChannelId(payload.new_channel_id);
        if (!oldChannelId || !newChannelId) {
          ctx.runtime.error?.(danger(`slack channel_id_changed handler: invalid or missing channel ids`));
          return;
        }

        const channelInfo = await ctx.resolveChannelName(newChannelId);
        const label = resolveSlackChannelLabel({
          channelId: newChannelId,
          channelName: sanitizeChannelName(channelInfo?.name),
        });

        ctx.runtime.log?.(
          warn(`[slack] Channel ID changed: ${oldChannelId} → ${newChannelId} (${label})`),
        );

        if (
          !resolveChannelConfigWrites({
            cfg: ctx.cfg,
            channelId: "slack",
            accountId: ctx.accountId,
          })
        ) {
          ctx.runtime.log?.(
            warn("[slack] Config writes disabled; skipping channel config migration."),
          );
          return;
        }

        const currentConfig = loadConfig();
        const migration = migrateSlackChannelConfig({
          cfg: currentConfig,
          accountId: ctx.accountId,
          oldChannelId,
          newChannelId,
        });

        if (migration.migrated) {
          migrateSlackChannelConfig({
            cfg: ctx.cfg,
            accountId: ctx.accountId,
            oldChannelId,
            newChannelId,
          });
          await writeConfigFile(currentConfig);
          ctx.runtime.log?.(warn("[slack] Channel config migrated and saved successfully."));
        } else if (migration.skippedExisting) {
          ctx.runtime.log?.(
            warn(
              `[slack] Channel config already exists for ${newChannelId}; leaving ${oldChannelId} unchanged`,
            ),
          );
        } else {
          ctx.runtime.log?.(
            warn(
              `[slack] No config found for old channel ID ${oldChannelId}; migration logged only`,
            ),
          );
        }
      } catch (err) {
        ctx.runtime.error?.(danger(`slack channel_id_changed handler failed: ${sanitizeString(String(err))}`));
      }
    },
  );
}