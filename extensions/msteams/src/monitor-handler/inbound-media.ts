import {
  buildMSTeamsGraphMessageUrls,
  downloadMSTeamsAttachments,
  downloadMSTeamsBotFrameworkAttachments,
  downloadMSTeamsGraphMedia,
  extractMSTeamsHtmlAttachmentIds,
  isBotFrameworkPersonalChatId,
  type MSTeamsAccessTokenProvider,
  type MSTeamsAttachmentLike,
  type MSTeamsHtmlAttachmentSummary,
  type MSTeamsInboundMedia,
} from "../attachments.js";
import type { MSTeamsTurnContext } from "../sdk-types.js";

type MSTeamsLogger = {
  debug?: (message: string, meta?: Record<string, unknown>) => void;
  warn?: (message: string, meta?: Record<string, unknown>) => void;
  error?: (message: string, meta?: Record<string, unknown>) => void;
};

const ALLOWED_CONVERSATION_TYPES = new Set([
  "personal",
  "groupChat",
  "channel",
  "meeting",
]);

function sanitizeConversationType(conversationType: string): string {
  if (ALLOWED_CONVERSATION_TYPES.has(conversationType)) {
    return conversationType;
  }
  return "unknown";
}

function sanitizeConversationId(conversationId: string): string {
  // Restrict to characters expected in Teams conversation IDs
  return conversationId.replace(/[^a-zA-Z0-9\-_:.@]/g, "");
}

function sanitizeMessageId(messageId: string | undefined): string | undefined {
  if (messageId === undefined) return undefined;
  return messageId.replace(/[^a-zA-Z0-9\-_:.@]/g, "");
}

export async function resolveMSTeamsInboundMedia(params: {
  attachments: MSTeamsAttachmentLike[];
  htmlSummary?: MSTeamsHtmlAttachmentSummary;
  maxBytes: number;
  allowHosts?: string[];
  authAllowHosts?: string[];
  tokenProvider: MSTeamsAccessTokenProvider;
  conversationType: string;
  conversationId: string;
  conversationMessageId?: string;
  serviceUrl?: string;
  activity: Pick<MSTeamsTurnContext["activity"], "id" | "replyToId" | "channelData">;
  log: MSTeamsLogger;
  /** When true, embeds original filename in stored path for later extraction. */
  preserveFilenames?: boolean;
}): Promise<MSTeamsInboundMedia[]> {
  const {
    attachments,
    htmlSummary,
    maxBytes,
    tokenProvider,
    allowHosts,
    conversationType: rawConversationType,
    conversationId: rawConversationId,
    conversationMessageId: rawConversationMessageId,
    serviceUrl,
    activity,
    log,
    preserveFilenames,
  } = params;

  const conversationType = sanitizeConversationType(rawConversationType);
  const conversationId = sanitizeConversationId(rawConversationId);
  const conversationMessageId = sanitizeMessageId(rawConversationMessageId);
  const sanitizedActivityId = sanitizeMessageId(activity.id ?? undefined);
  const sanitizedReplyToId = sanitizeMessageId(activity.replyToId ?? undefined);

  let mediaList = await downloadMSTeamsAttachments({
    attachments,
    maxBytes,
    tokenProvider,
    allowHosts,
    authAllowHosts: params.authAllowHosts,
    preserveFilenames,
    logger: log,
  });

  if (mediaList.length === 0) {
    // Gate the Graph/Bot Framework media fallback on the presence of real
    // `<attachment id="...">` tags inside any `text/html` attachment. Teams
    // delivers @mention cards and other chrome as `text/html` attachments
    // too, so keying off contentType alone produces spurious 404 diagnostics
    // for every mention-only message and masks real file attachments (#58617).
    const attachmentIds = extractMSTeamsHtmlAttachmentIds(attachments);
    const hasHtmlFileAttachment = attachmentIds.length > 0;

    // Personal DMs with the bot use Bot Framework conversation IDs (`a:...`
    // or `8:orgid:...`) which Graph's `/chats/{id}` endpoint rejects with
    // "Invalid ThreadId". Fetch media via the Bot Framework v3 attachments
    // endpoint instead, which speaks the same identifier space.
    if (hasHtmlFileAttachment && isBotFrameworkPersonalChatId(conversationId)) {
      if (!serviceUrl) {
        log.debug?.("bot framework attachment skipped (missing serviceUrl)", {
          conversationType,
          conversationId,
        });
      } else {
        const bfMedia = await downloadMSTeamsBotFrameworkAttachments({
          serviceUrl,
          attachmentIds,
          tokenProvider,
          maxBytes,
          allowHosts,
          authAllowHosts: params.authAllowHosts,
          preserveFilenames,
        });
        if (bfMedia.media.length > 0) {
          mediaList = bfMedia.media;
        } else {
          log.debug?.("bot framework attachments fetch empty", {
            conversationType,
            attachmentCount: bfMedia.attachmentCount ?? attachmentIds.length,
          });
        }
      }
    }

    if (
      hasHtmlFileAttachment &&
      mediaList.length === 0 &&
      !isBotFrameworkPersonalChatId(conversationId)
    ) {
      const messageUrls = buildMSTeamsGraphMessageUrls({
        conversationType,
        conversationId,
        messageId: sanitizedActivityId,
        replyToId: sanitizedReplyToId,
        conversationMessageId,
        channelData: activity.channelData,
      });
      if (messageUrls.length === 0) {
        log.debug?.("graph message url unavailable", {
          conversationType,
          hasChannelData: Boolean(activity.channelData),
          messageId: sanitizedActivityId,
          replyToId: sanitizedReplyToId,
        });
      } else {
        const attempts: Array<{
          url: string;
          hostedStatus?: number;
          attachmentStatus?: number;
          hostedCount?: number;
          attachmentCount?: number;
          tokenError?: boolean;
        }> = [];
        for (const messageUrl of messageUrls) {
          const graphMedia = await downloadMSTeamsGraphMedia({
            messageUrl,
            tokenProvider,
            maxBytes,
            allowHosts,
            authAllowHosts: params.authAllowHosts,
            preserveFilenames,
            log,
            logger: log,
          });
          attempts.push({
            url: messageUrl,
            hostedStatus: graphMedia.hostedStatus,
            attachmentStatus: graphMedia.attachmentStatus,
            hostedCount: graphMedia.hostedCount,
            attachmentCount: graphMedia.attachmentCount,
            tokenError: graphMedia.tokenError,
          });
          if (graphMedia.media.length > 0) {
            mediaList = graphMedia.media;
            break;
          }
          if (graphMedia.tokenError) {
            break;
          }
        }
        if (mediaList.length === 0) {
          log.debug?.("graph media fetch empty", {
            attempts,
            attachmentIdCount: attachmentIds.length,
          });
        }
      }
    }
  }

  if (mediaList.length > 0) {
    log.debug?.("downloaded attachments", { count: mediaList.length });
  } else if (htmlSummary?.imgTags) {
    log.debug?.("inline images detected but none downloaded", {
      imgTags: htmlSummary.imgTags,
      srcHosts: htmlSummary.srcHosts,
      dataImages: htmlSummary.dataImages,
      cidImages: htmlSummary.cidImages,
    });
  }

  return mediaList;
}