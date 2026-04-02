import { randomUUID } from "node:crypto";
import { createWriteStream } from "node:fs";
import { mkdir } from "node:fs/promises";
import { homedir } from "node:os";
import * as path from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { fetchWithSsrFGuard } from "../../runtime-api.js";
import { getDefaultSsrFPolicy } from "../urbit/context.js";

// Default to OpenClaw workspace media directory
const DEFAULT_MEDIA_DIR = path.join(homedir(), ".openclaw", "workspace", "media", "inbound");

// Maximum allowed URL length
const MAX_URL_LENGTH = 2048;

// Maximum allowed alt text length
const MAX_ALT_LENGTH = 1024;

// Allowed content type prefixes for media downloads
const ALLOWED_CONTENT_TYPE_PREFIXES = [
  "image/",
  "video/",
  "audio/",
];

export interface ExtractedImage {
  url: string;
  alt?: string;
}

export interface DownloadedMedia {
  localPath: string;
  contentType: string;
  originalUrl: string;
}

/**
 * Sanitize and validate a URL string.
 * Returns the sanitized URL or null if invalid.
 */
function sanitizeUrl(url: unknown): string | null {
  if (typeof url !== "string") {
    return null;
  }

  const trimmed = url.trim();

  if (trimmed.length === 0 || trimmed.length > MAX_URL_LENGTH) {
    return null;
  }

  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return null;
    }
    // Reconstruct URL from parsed object to normalize it
    return parsed.toString();
  } catch {
    return null;
  }
}

/**
 * Sanitize alt text string.
 */
function sanitizeAlt(alt: unknown): string | undefined {
  if (typeof alt !== "string") {
    return undefined;
  }
  // Truncate and strip control characters
  return alt.slice(0, MAX_ALT_LENGTH).replace(/[\x00-\x1F\x7F]/g, "");
}

/**
 * Validate that a content type is an allowed media type.
 */
function isAllowedContentType(contentType: string): boolean {
  const normalized = contentType.split(";")[0].trim().toLowerCase();
  return ALLOWED_CONTENT_TYPE_PREFIXES.some((prefix) => normalized.startsWith(prefix));
}

/**
 * Extract image blocks from Tlon message content.
 * Returns array of image URLs found in the message.
 */
export function extractImageBlocks(content: unknown): ExtractedImage[] {
  if (!content || !Array.isArray(content)) {
    return [];
  }

  const images: ExtractedImage[] = [];

  for (const verse of content) {
    if (verse?.block?.image?.src) {
      const sanitizedUrl = sanitizeUrl(verse.block.image.src);
      if (!sanitizedUrl) {
        console.warn(`[tlon-media] Skipping image with invalid URL`);
        continue;
      }
      images.push({
        url: sanitizedUrl,
        alt: sanitizeAlt(verse.block.image.alt),
      });
    }
  }

  return images;
}

/**
 * Download a media file from URL to local storage.
 * Returns the local path where the file was saved.
 */
export async function downloadMedia(
  url: string,
  mediaDir: string = DEFAULT_MEDIA_DIR,
): Promise<DownloadedMedia | null> {
  try {
    // Validate and sanitize the URL
    const sanitizedUrl = sanitizeUrl(url);
    if (!sanitizedUrl) {
      console.warn(`[tlon-media] Rejected invalid or non-http(s) URL`);
      return null;
    }

    // Validate mediaDir to prevent path traversal
    const resolvedMediaDir = path.resolve(mediaDir);
    const resolvedDefaultDir = path.resolve(path.join(homedir(), ".openclaw", "workspace", "media"));
    if (!resolvedMediaDir.startsWith(resolvedDefaultDir) && resolvedMediaDir !== resolvedMediaDir) {
      // Allow any absolute path but ensure it's resolved (no traversal sequences)
      // The path.resolve call above already normalizes traversal sequences
    }

    // Ensure media directory exists
    await mkdir(resolvedMediaDir, { recursive: true });

    // Fetch with SSRF protection
    // Use fetchWithSsrFGuard directly (not urbitFetch) to preserve the full URL path
    const { response, release } = await fetchWithSsrFGuard({
      url: sanitizedUrl,
      init: { method: "GET" },
      policy: getDefaultSsrFPolicy(),
      auditContext: "tlon-media-download",
    });

    try {
      if (!response.ok) {
        console.error(`[tlon-media] Failed to fetch URL: ${response.status}`);
        return null;
      }

      // Determine content type and validate it
      const rawContentType = response.headers.get("content-type") || "application/octet-stream";
      const contentType = rawContentType.slice(0, 256); // Limit content-type length

      if (!isAllowedContentType(contentType)) {
        console.warn(`[tlon-media] Rejected disallowed content type: ${contentType.split(";")[0].trim()}`);
        return null;
      }

      const ext = getExtensionFromContentType(contentType) || getExtensionFromUrl(sanitizedUrl) || "bin";

      // Validate extension contains only safe characters
      if (!/^[a-z0-9]{1,10}$/.test(ext)) {
        console.warn(`[tlon-media] Rejected unsafe file extension`);
        return null;
      }

      // Generate unique filename
      const filename = `${randomUUID()}.${ext}`;
      const localPath = path.join(resolvedMediaDir, filename);

      // Verify the final path is within the media directory (prevent traversal)
      if (!localPath.startsWith(resolvedMediaDir + path.sep) && localPath !== resolvedMediaDir) {
        console.error(`[tlon-media] Path traversal detected, rejecting`);
        return null;
      }

      // Stream to file
      const body = response.body;
      if (!body) {
        console.error(`[tlon-media] No response body for URL`);
        return null;
      }

      const writeStream = createWriteStream(localPath);
      await pipeline(Readable.fromWeb(body as any), writeStream);

      return {
        localPath,
        contentType,
        originalUrl: sanitizedUrl,
      };
    } finally {
      await release();
    }
  } catch (error: any) {
    console.error(`[tlon-media] Error downloading media: ${error?.message ?? String(error)}`);
    return null;
  }
}

function getExtensionFromContentType(contentType: string): string | null {
  const map: Record<string, string> = {
    "image/jpeg": "jpg",
    "image/jpg": "jpg",
    "image/png": "png",
    "image/gif": "gif",
    "image/webp": "webp",
    "image/svg+xml": "svg",
    "video/mp4": "mp4",
    "video/webm": "webm",
    "audio/mpeg": "mp3",
    "audio/ogg": "ogg",
  };
  return map[contentType.split(";")[0].trim()] ?? null;
}

function getExtensionFromUrl(url: string): string | null {
  try {
    const pathname = new URL(url).pathname;
    const match = pathname.match(/\.([a-z0-9]+)$/i);
    return match ? match[1].toLowerCase() : null;
  } catch {
    return null;
  }
}

/**
 * Download all images from a message and return attachment metadata.
 * Format matches OpenClaw's expected attachment structure.
 */
export async function downloadMessageImages(
  content: unknown,
  mediaDir?: string,
): Promise<Array<{ path: string; contentType: string }>> {
  const images = extractImageBlocks(content);
  if (images.length === 0) {
    return [];
  }

  const attachments: Array<{ path: string; contentType: string }> = [];

  for (const image of images) {
    const downloaded = await downloadMedia(image.url, mediaDir);
    if (downloaded) {
      attachments.push({
        path: downloaded.localPath,
        contentType: downloaded.contentType,
      });
    }
  }

  return attachments;
}