import type { ChannelOutboundAdapter } from "../channels/plugins/types.js";

export type { MediaPayload, MediaPayloadInput } from "../channels/plugins/media-payload.js";
export { buildMediaPayload } from "../channels/plugins/media-payload.js";

export type OutboundReplyPayload = {
  text?: string;
  mediaUrls?: string[];
  mediaUrl?: string;
  replyToId?: string;
};

export type SendableOutboundReplyParts = {
  text: string;
  trimmedText: string;
  mediaUrls: string[];
  mediaCount: number;
  hasText: boolean;
  hasMedia: boolean;
  hasContent: boolean;
};

type SendPayloadContext = Parameters<NonNullable<ChannelOutboundAdapter["sendPayload"]>>[0];
type SendPayloadResult = Awaited<ReturnType<NonNullable<ChannelOutboundAdapter["sendPayload"]>>>;
type SendPayloadAdapter = Pick<
  ChannelOutboundAdapter,
  "sendMedia" | "sendText" | "chunker" | "textChunkLimit"
>;

const MAX_TEXT_LENGTH = 100_000;
const MAX_URL_LENGTH = 2_048;
const MAX_ID_LENGTH = 512;
const MAX_MEDIA_URLS = 50;

function sanitizeString(value: unknown, maxLength: number): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }
  const trimmed = value.slice(0, maxLength);
  return trimmed;
}

function isValidUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return parsed.protocol === "https:" || parsed.protocol === "http:";
  } catch {
    return false;
  }
}

function sanitizeMediaUrl(url: unknown): string | undefined {
  if (typeof url !== "string") {
    return undefined;
  }
  const trimmed = url.trim().slice(0, MAX_URL_LENGTH);
  if (!trimmed || !isValidUrl(trimmed)) {
    return undefined;
  }
  return trimmed;
}

/** Extract the supported outbound reply fields from loose tool or agent payload objects. */
export function normalizeOutboundReplyPayload(
  payload: Record<string, unknown>,
): OutboundReplyPayload {
  const text = sanitizeString(payload.text, MAX_TEXT_LENGTH);
  const mediaUrls = Array.isArray(payload.mediaUrls)
    ? payload.mediaUrls
        .slice(0, MAX_MEDIA_URLS)
        .map((entry) => sanitizeMediaUrl(entry))
        .filter((entry): entry is string => entry !== undefined && entry.length > 0)
    : undefined;
  const rawMediaUrl = sanitizeMediaUrl(payload.mediaUrl);
  const mediaUrl = rawMediaUrl !== undefined && rawMediaUrl.length > 0 ? rawMediaUrl : undefined;
  const rawReplyToId = sanitizeString(payload.replyToId, MAX_ID_LENGTH);
  const replyToId =
    rawReplyToId !== undefined && /^[\w\-.:@#/]+$/.test(rawReplyToId) ? rawReplyToId : undefined;
  return {
    text,
    mediaUrls,
    mediaUrl,
    replyToId,
  };
}

/** Wrap a deliverer so callers can hand it arbitrary payloads while channels receive normalized data. */
export function createNormalizedOutboundDeliverer(
  handler: (payload: OutboundReplyPayload) => Promise<void>,
): (payload: unknown) => Promise<void> {
  return async (payload: unknown) => {
    const normalized =
      payload && typeof payload === "object"
        ? normalizeOutboundReplyPayload(payload as Record<string, unknown>)
        : {};
    await handler(normalized);
  };
}

/** Prefer multi-attachment payloads, then fall back to the legacy single-media field. */
export function resolveOutboundMediaUrls(payload: {
  mediaUrls?: string[];
  mediaUrl?: string;
}): string[] {
  if (payload.mediaUrls?.length) {
    return payload.mediaUrls
      .map((u) => sanitizeMediaUrl(u))
      .filter((u): u is string => u !== undefined && u.length > 0);
  }
  if (payload.mediaUrl) {
    const sanitized = sanitizeMediaUrl(payload.mediaUrl);
    if (sanitized) {
      return [sanitized];
    }
  }
  return [];
}

/** Resolve media URLs from a channel sendPayload context after legacy fallback normalization. */
export function resolvePayloadMediaUrls(payload: SendPayloadContext["payload"]): string[] {
  return resolveOutboundMediaUrls(payload);
}

/** Count outbound media items after legacy single-media fallback normalization. */
export function countOutboundMedia(payload: { mediaUrls?: string[]; mediaUrl?: string }): number {
  return resolveOutboundMediaUrls(payload).length;
}

/** Check whether an outbound payload includes any media after normalization. */
export function hasOutboundMedia(payload: { mediaUrls?: string[]; mediaUrl?: string }): boolean {
  return countOutboundMedia(payload) > 0;
}

/** Check whether an outbound payload includes text, optionally trimming whitespace first. */
export function hasOutboundText(payload: { text?: string }, options?: { trim?: boolean }): boolean {
  const text = options?.trim ? payload.text?.trim() : payload.text;
  return Boolean(text);
}

/** Check whether an outbound payload includes any sendable text or media. */
export function hasOutboundReplyContent(
  payload: { text?: string; mediaUrls?: string[]; mediaUrl?: string },
  options?: { trimText?: boolean },
): boolean {
  return hasOutboundText(payload, { trim: options?.trimText }) || hasOutboundMedia(payload);
}

/** Normalize reply payload text/media into a trimmed, sendable shape for delivery paths. */
export function resolveSendableOutboundReplyParts(
  payload: { text?: string; mediaUrls?: string[]; mediaUrl?: string },
  options?: { text?: string },
): SendableOutboundReplyParts {
  const rawText = options?.text ?? payload.text ?? "";
  const text = rawText.slice(0, MAX_TEXT_LENGTH);
  const trimmedText = text.trim();
  const mediaUrls = resolveOutboundMediaUrls(payload)
    .map((entry) => entry.trim())
    .filter(Boolean);
  const mediaCount = mediaUrls.length;
  const hasText = Boolean(trimmedText);
  const hasMedia = mediaCount > 0;
  return {
    text,
    trimmedText,
    mediaUrls,
    mediaCount,
    hasText,
    hasMedia,
    hasContent: hasText || hasMedia,
  };
}

/** Preserve caller-provided chunking, but fall back to the full text when chunkers return nothing. */
export function resolveTextChunksWithFallback(text: string, chunks: readonly string[]): string[] {
  if (chunks.length > 0) {
    return [...chunks];
  }
  if (!text) {
    return [];
  }
  return [text];
}

/** Send media-first payloads intact, or chunk text-only payloads through the caller's transport hooks. */
export async function sendPayloadWithChunkedTextAndMedia<
  TContext extends { payload: object },
  TResult,
>(params: {
  ctx: TContext;
  textChunkLimit?: number;
  chunker?: ((text: string, limit: number) => string[]) | null;
  sendText: (ctx: TContext & { text: string }) => Promise<TResult>;
  sendMedia: (ctx: TContext & { text: string; mediaUrl: string }) => Promise<TResult>;
  emptyResult: TResult;
}): Promise<TResult> {
  const payload = params.ctx.payload as { text?: string; mediaUrls?: string[]; mediaUrl?: string };
  const rawText = payload.text ?? "";
  const text = rawText.slice(0, MAX_TEXT_LENGTH);
  const urls = resolveOutboundMediaUrls(payload);
  if (!text && urls.length === 0) {
    return params.emptyResult;
  }
  if (urls.length > 0) {
    let lastResult = await params.sendMedia({
      ...params.ctx,
      text,
      mediaUrl: urls[0],
    });
    for (let i = 1; i < urls.length; i++) {
      lastResult = await params.sendMedia({
        ...params.ctx,
        text: "",
        mediaUrl: urls[i],
      });
    }
    return lastResult;
  }
  const limit = params.textChunkLimit;
  const chunks = limit && params.chunker ? params.chunker(text, limit) : [text];
  let lastResult: TResult;
  for (const chunk of chunks) {
    lastResult = await params.sendText({ ...params.ctx, text: chunk });
  }
  return lastResult!;
}

export async function sendPayloadMediaSequence<TResult>(params: {
  text: string;
  mediaUrls: readonly string[];
  send: (input: {
    text: string;
    mediaUrl: string;
    index: number;
    isFirst: boolean;
  }) => Promise<TResult>;
}): Promise<TResult | undefined> {
  let lastResult: TResult | undefined;
  for (let i = 0; i < params.mediaUrls.length; i += 1) {
    const rawMediaUrl = params.mediaUrls[i];
    if (!rawMediaUrl) {
      continue;
    }
    const mediaUrl = sanitizeMediaUrl(rawMediaUrl);
    if (!mediaUrl) {
      continue;
    }
    lastResult = await params.send({
      text: i === 0 ? params.text : "",
      mediaUrl,
      index: i,
      isFirst: i === 0,
    });
  }
  return lastResult;
}

export async function sendPayloadMediaSequenceOrFallback<TResult>(params: {
  text: string;
  mediaUrls: readonly string[];
  send: (input: {
    text: string;
    mediaUrl: string;
    index: number;
    isFirst: boolean;
  }) => Promise<TResult>;
  fallbackResult: TResult;
  sendNoMedia?: () => Promise<TResult>;
}): Promise<TResult> {
  if (params.mediaUrls.length === 0) {
    return params.sendNoMedia ? await params.sendNoMedia() : params.fallbackResult;
  }
  return (await sendPayloadMediaSequence(params)) ?? params.fallbackResult;
}

export async function sendPayloadMediaSequenceAndFinalize<TMediaResult, TResult>(params: {
  text: string;
  mediaUrls: readonly string[];
  send: (input: {
    text: string;
    mediaUrl: string;
    index: number;
    isFirst: boolean;
  }) => Promise<TMediaResult>;
  finalize: () => Promise<TResult>;
}): Promise<TResult> {
  if (params.mediaUrls.length > 0) {
    await sendPayloadMediaSequence(params);
  }
  return await params.finalize();
}

export async function sendTextMediaPayload(params: {
  channel: string;
  ctx: SendPayloadContext;
  adapter: SendPayloadAdapter;
}): Promise<SendPayloadResult> {
  const rawText = params.ctx.payload.text ?? "";
  const text = rawText.slice(0, MAX_TEXT_LENGTH);
  const urls = resolvePayloadMediaUrls(params.ctx.payload);
  if (!text && urls.length === 0) {
    return { channel: params.channel, messageId: "" };
  }
  if (urls.length > 0) {
    const lastResult = await sendPayloadMediaSequence({
      text,
      mediaUrls: urls,
      send: async ({ text, mediaUrl }) =>
        await params.adapter.sendMedia!({
          ...params.ctx,
          text,
          mediaUrl,
        }),
    });
    return lastResult ?? { channel: params.channel, messageId: "" };
  }
  const limit = params.adapter.textChunkLimit;
  const chunks = limit && params.adapter.chunker ? params.adapter.chunker(text, limit) : [text];
  let lastResult: Awaited<ReturnType<NonNullable<typeof params.adapter.sendText>>>;
  for (const chunk of chunks) {
    lastResult = await params.adapter.sendText!({ ...params.ctx, text: chunk });
  }
  return lastResult!;
}

/** Detect numeric-looking target ids for channels that distinguish ids from handles. */
export function isNumericTargetId(raw: string): boolean {
  const trimmed = raw.trim();
  if (!trimmed) {
    return false;
  }
  return /^\d{3,}$/.test(trimmed);
}

/** Append attachment links to plain text when the channel cannot send media inline. */
export function formatTextWithAttachmentLinks(
  text: string | undefined,
  mediaUrls: string[],
): string {
  const trimmedText = text?.trim() ?? "";
  const sanitizedText = trimmedText.slice(0, MAX_TEXT_LENGTH);
  const sanitizedUrls = mediaUrls
    .slice(0, MAX_MEDIA_URLS)
    .map((url) => sanitizeMediaUrl(url))
    .filter((url): url is string => url !== undefined && url.length > 0);
  if (!sanitizedText && sanitizedUrls.length === 0) {
    return "";
  }
  const mediaBlock = sanitizedUrls.length
    ? sanitizedUrls.map((url) => `Attachment: ${url}`).join("\n")
    : "";
  if (!sanitizedText) {
    return mediaBlock;
  }
  if (!mediaBlock) {
    return sanitizedText;
  }
  return `${sanitizedText}\n\n${mediaBlock}`;
}

/** Send a caption with only the first media item, mirroring caption-limited channel transports. */
export async function sendMediaWithLeadingCaption(params: {
  mediaUrls: string[];
  caption: string;
  send: (payload: { mediaUrl: string; caption?: string }) => Promise<void>;
  onError?: (params: {
    error: unknown;
    mediaUrl: string;
    caption?: string;
    index: number;
    isFirst: boolean;
  }) => Promise<void> | void;
}): Promise<boolean> {
  if (params.mediaUrls.length === 0) {
    return false;
  }

  const sanitizedCaption = params.caption.slice(0, MAX_TEXT_LENGTH);
  const sanitizedUrls = params.mediaUrls
    .slice(0, MAX_MEDIA_URLS)
    .map((url) => sanitizeMediaUrl(url))
    .filter((url): url is string => url !== undefined && url.length > 0);

  if (sanitizedUrls.length === 0) {
    return false;
  }

  for (const [index, mediaUrl] of sanitizedUrls.entries()) {
    const isFirst = index === 0;
    const caption = isFirst ? sanitizedCaption : undefined;
    try {
      await params.send({ mediaUrl, caption });
    } catch (error) {
      if (params.onError) {
        await params.onError({
          error,
          mediaUrl,
          caption,
          index,
          isFirst,
        });
        continue;
      }
      throw error;
    }
  }
  return true;
}

export async function deliverTextOrMediaReply(params: {
  payload: OutboundReplyPayload;
  text: string;
  chunkText?: (text: string) => readonly string[];
  sendText: (text: string) => Promise<void>;
  sendMedia: (payload: { mediaUrl: string; caption?: string }) => Promise<void>;
  onMediaError?: (params: {
    error: unknown;
    mediaUrl: string;
    caption?: string;
    index: number;
    isFirst: boolean;
  }) => Promise<void> | void;
}): Promise<"empty" | "text" | "media"> {
  const sanitizedText = params.text.slice(0, MAX_TEXT_LENGTH);
  const { mediaUrls } = resolveSendableOutboundReplyParts(params.payload, {
    text: sanitizedText,
  });
  const sentMedia = await sendMediaWithLeadingCaption({
    mediaUrls,
    caption: sanitizedText,
    send: params.sendMedia,
    onError: params.onMediaError,
  });
  if (sentMedia) {
    return "media";
  }
  if (!sanitizedText) {
    return "empty";
  }
  const chunks = params.chunkText ? params.chunkText(sanitizedText) : [sanitizedText];
  let sentText = false;
  for (const chunk of chunks) {
    if (!chunk) {
      continue;
    }
    await params.sendText(chunk);
    sentText = true;
  }
  return sentText ? "text" : "empty";
}

export async function deliverFormattedTextWithAttachments(params: {
  payload: OutboundReplyPayload;
  send: (params: { text: string; replyToId?: string }) => Promise<void>;
}): Promise<boolean> {
  const text = formatTextWithAttachmentLinks(
    params.payload.text,
    resolveOutboundMediaUrls(params.payload),
  );
  if (!text) {
    return false;
  }
  await params.send({
    text,
    replyToId: params.payload.replyToId,
  });
  return true;
}