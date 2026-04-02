import crypto from "node:crypto";
import type { AgentToolResult } from "@mariozechner/pi-agent-core";
import {
  type CameraFacing,
  cameraTempPath,
  parseCameraClipPayload,
  parseCameraSnapPayload,
  writeCameraClipPayloadToFile,
  writeCameraPayloadToFile,
} from "../../cli/nodes-camera.js";
import {
  parseScreenRecordPayload,
  screenRecordTempPath,
  writeScreenRecordToFile,
} from "../../cli/nodes-screen.js";
import { parseDurationMs } from "../../cli/parse-duration.js";
import { imageMimeFromFormat } from "../../media/mime.js";
import type { ImageSanitizationLimits } from "../image-sanitization.js";
import { sanitizeToolResultImages } from "../tool-images.js";
import type { GatewayCallOptions } from "./gateway.js";
import { callGatewayTool } from "./gateway.js";
import { resolveNode, resolveNodeId } from "./nodes-utils.js";

export const MEDIA_INVOKE_ACTIONS = {
  "camera.snap": "camera_snap",
  "camera.clip": "camera_clip",
  "photos.latest": "photos_latest",
  "screen.record": "screen_record",
} as const;

export type NodeMediaAction = "camera_snap" | "photos_latest" | "camera_clip" | "screen_record";

type ExecuteNodeMediaActionParams = {
  action: NodeMediaAction;
  params: Record<string, unknown>;
  gatewayOpts: GatewayCallOptions;
  modelHasVision?: boolean;
  imageSanitization: ImageSanitizationLimits;
};

const ALLOWED_NODE_MEDIA_ACTIONS: NodeMediaAction[] = [
  "camera_snap",
  "photos_latest",
  "camera_clip",
  "screen_record",
];

const MAX_STRING_LENGTH = 1024;
const MAX_DEVICE_ID_LENGTH = 256;
const MAX_OUT_PATH_LENGTH = 4096;
const MAX_WIDTH_MIN = 1;
const MAX_WIDTH_MAX = 8000;
const QUALITY_MIN = 0.0;
const QUALITY_MAX = 1.0;
const DELAY_MS_MIN = 0;
const DELAY_MS_MAX = 30_000;
const DURATION_MS_MIN = 100;
const DURATION_MS_MAX = 300_000;
const FPS_MIN = 1;
const FPS_MAX = 120;
const SCREEN_INDEX_MIN = 0;
const SCREEN_INDEX_MAX = 16;

function sanitizeString(value: unknown, maxLength: number = MAX_STRING_LENGTH): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  if (trimmed.length === 0) return undefined;
  if (trimmed.length > maxLength) {
    throw new Error(`string value exceeds maximum allowed length of ${maxLength}`);
  }
  return trimmed;
}

function sanitizeNumber(
  value: unknown,
  min: number,
  max: number,
  defaultValue?: number,
): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) {
    const clamped = Math.max(min, Math.min(max, value));
    return clamped;
  }
  return defaultValue;
}

function sanitizeBoolean(value: unknown, defaultValue: boolean): boolean {
  if (typeof value === "boolean") return value;
  return defaultValue;
}

function sanitizeOutPath(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  if (trimmed.length === 0) return undefined;
  if (trimmed.length > MAX_OUT_PATH_LENGTH) {
    throw new Error(`outPath exceeds maximum allowed length of ${MAX_OUT_PATH_LENGTH}`);
  }
  // Prevent path traversal
  if (trimmed.includes("\0")) {
    throw new Error("outPath contains invalid characters");
  }
  const normalized = trimmed.replace(/\\/g, "/");
  const parts = normalized.split("/");
  for (const part of parts) {
    if (part === "..") {
      throw new Error("outPath must not contain path traversal sequences");
    }
  }
  return trimmed;
}

function sanitizeParams(params: Record<string, unknown>): Record<string, unknown> {
  if (params === null || typeof params !== "object" || Array.isArray(params)) {
    throw new Error("params must be a plain object");
  }
  return params;
}

export async function executeNodeMediaAction(
  input: ExecuteNodeMediaActionParams,
): Promise<AgentToolResult<unknown>> {
  if (!ALLOWED_NODE_MEDIA_ACTIONS.includes(input.action)) {
    throw new Error(`invalid action: ${String(input.action)}`);
  }
  sanitizeParams(input.params);

  switch (input.action) {
    case "camera_snap":
      return await executeCameraSnap(input);
    case "photos_latest":
      return await executePhotosLatest(input);
    case "camera_clip":
      return await executeCameraClip(input);
    case "screen_record":
      return await executeScreenRecord(input);
  }
}

async function executeCameraSnap({
  params,
  gatewayOpts,
  modelHasVision,
  imageSanitization,
}: ExecuteNodeMediaActionParams): Promise<AgentToolResult<unknown>> {
  const node = requireString(params, "node");
  const resolvedNode = await resolveNode(gatewayOpts, node);
  const nodeId = resolvedNode.nodeId;
  const facingRaw =
    sanitizeString(params.facing, 16) ?? "front";
  const facings: CameraFacing[] =
    facingRaw === "both"
      ? ["front", "back"]
      : facingRaw === "front" || facingRaw === "back"
        ? [facingRaw]
        : (() => {
            throw new Error("invalid facing (front|back|both)");
          })();
  const maxWidth = sanitizeNumber(params.maxWidth, MAX_WIDTH_MIN, MAX_WIDTH_MAX, 1600)!;
  const quality = sanitizeNumber(params.quality, QUALITY_MIN, QUALITY_MAX, 0.95)!;
  const delayMs =
    typeof params.delayMs === "number" && Number.isFinite(params.delayMs)
      ? sanitizeNumber(params.delayMs, DELAY_MS_MIN, DELAY_MS_MAX)
      : undefined;
  const deviceIdRaw = sanitizeString(params.deviceId, MAX_DEVICE_ID_LENGTH);
  const deviceId = deviceIdRaw ?? undefined;
  if (deviceId && facings.length > 1) {
    throw new Error("facing=both is not allowed when deviceId is set");
  }

  const content: AgentToolResult<unknown>["content"] = [];
  const details: Array<Record<string, unknown>> = [];

  for (const facing of facings) {
    const raw = await callGatewayTool<{ payload: unknown }>("node.invoke", gatewayOpts, {
      nodeId,
      command: "camera.snap",
      params: {
        facing,
        maxWidth,
        quality,
        format: "jpg",
        delayMs,
        deviceId,
      },
      idempotencyKey: crypto.randomUUID(),
    });
    const payload = parseCameraSnapPayload(raw?.payload);
    const normalizedFormat = payload.format.toLowerCase();
    if (normalizedFormat !== "jpg" && normalizedFormat !== "jpeg" && normalizedFormat !== "png") {
      throw new Error(`unsupported camera.snap format: ${payload.format}`);
    }

    const isJpeg = normalizedFormat === "jpg" || normalizedFormat === "jpeg";
    const filePath = cameraTempPath({
      kind: "snap",
      facing,
      ext: isJpeg ? "jpg" : "png",
    });
    await writeCameraPayloadToFile({
      filePath,
      payload,
      expectedHost: resolvedNode.remoteIp,
      invalidPayloadMessage: "invalid camera.snap payload",
    });
    if (modelHasVision && payload.base64) {
      content.push({
        type: "image",
        data: payload.base64,
        mimeType: imageMimeFromFormat(payload.format) ?? (isJpeg ? "image/jpeg" : "image/png"),
      });
    }
    details.push({
      facing,
      path: filePath,
      width: payload.width,
      height: payload.height,
    });
  }

  return await sanitizeToolResultImages(
    {
      content,
      details: {
        snaps: details,
        media: {
          mediaUrls: details
            .map((entry) => entry.path)
            .filter((path): path is string => typeof path === "string"),
        },
      },
    },
    "nodes:camera_snap",
    imageSanitization,
  );
}

async function executePhotosLatest({
  params,
  gatewayOpts,
  modelHasVision,
  imageSanitization,
}: ExecuteNodeMediaActionParams): Promise<AgentToolResult<unknown>> {
  const node = requireString(params, "node");
  const resolvedNode = await resolveNode(gatewayOpts, node);
  const nodeId = resolvedNode.nodeId;
  const limitRaw =
    typeof params.limit === "number" && Number.isFinite(params.limit)
      ? Math.floor(params.limit)
      : DEFAULT_PHOTOS_LIMIT;
  const limit = Math.max(1, Math.min(limitRaw, MAX_PHOTOS_LIMIT));
  const maxWidth = sanitizeNumber(params.maxWidth, MAX_WIDTH_MIN, MAX_WIDTH_MAX, DEFAULT_PHOTOS_MAX_WIDTH)!;
  const quality = sanitizeNumber(params.quality, QUALITY_MIN, QUALITY_MAX, DEFAULT_PHOTOS_QUALITY)!;
  const raw = await callGatewayTool<{ payload: unknown }>("node.invoke", gatewayOpts, {
    nodeId,
    command: "photos.latest",
    params: {
      limit,
      maxWidth,
      quality,
    },
    idempotencyKey: crypto.randomUUID(),
  });
  const payload =
    raw?.payload && typeof raw.payload === "object" && !Array.isArray(raw.payload)
      ? (raw.payload as Record<string, unknown>)
      : {};
  const photos = Array.isArray(payload.photos) ? payload.photos : [];

  if (photos.length === 0) {
    return await sanitizeToolResultImages(
      {
        content: [],
        details: [],
      },
      "nodes:photos_latest",
      imageSanitization,
    );
  }

  const content: AgentToolResult<unknown>["content"] = [];
  const details: Array<Record<string, unknown>> = [];

  for (const [index, photoRaw] of photos.entries()) {
    const photo = parseCameraSnapPayload(photoRaw);
    const normalizedFormat = photo.format.toLowerCase();
    if (normalizedFormat !== "jpg" && normalizedFormat !== "jpeg" && normalizedFormat !== "png") {
      throw new Error(`unsupported photos.latest format: ${photo.format}`);
    }
    const isJpeg = normalizedFormat === "jpg" || normalizedFormat === "jpeg";
    const filePath = cameraTempPath({
      kind: "snap",
      ext: isJpeg ? "jpg" : "png",
      id: crypto.randomUUID(),
    });
    await writeCameraPayloadToFile({
      filePath,
      payload: photo,
      expectedHost: resolvedNode.remoteIp,
      invalidPayloadMessage: "invalid photos.latest payload",
    });

    if (modelHasVision && photo.base64) {
      content.push({
        type: "image",
        data: photo.base64,
        mimeType: imageMimeFromFormat(photo.format) ?? (isJpeg ? "image/jpeg" : "image/png"),
      });
    }

    const createdAt =
      photoRaw && typeof photoRaw === "object" && !Array.isArray(photoRaw)
        ? (photoRaw as Record<string, unknown>).createdAt
        : undefined;
    const sanitizedCreatedAt =
      typeof createdAt === "string" && createdAt.length <= 64 ? createdAt : undefined;
    details.push({
      index,
      path: filePath,
      width: photo.width,
      height: photo.height,
      ...(sanitizedCreatedAt !== undefined ? { createdAt: sanitizedCreatedAt } : {}),
    });
  }

  return await sanitizeToolResultImages(
    {
      content,
      details: {
        photos: details,
        media: {
          mediaUrls: details
            .map((entry) => entry.path)
            .filter((path): path is string => typeof path === "string"),
        },
      },
    },
    "nodes:photos_latest",
    imageSanitization,
  );
}

async function executeCameraClip({
  params,
  gatewayOpts,
}: ExecuteNodeMediaActionParams): Promise<AgentToolResult<unknown>> {
  const node = requireString(params, "node");
  const resolvedNode = await resolveNode(gatewayOpts, node);
  const nodeId = resolvedNode.nodeId;
  const facingRaw = sanitizeString(params.facing, 16) ?? "front";
  if (facingRaw !== "front" && facingRaw !== "back") {
    throw new Error("invalid facing (front|back)");
  }
  const facing = facingRaw;
  const durationMsRaw =
    typeof params.durationMs === "number" && Number.isFinite(params.durationMs)
      ? params.durationMs
      : typeof params.duration === "string"
        ? parseDurationMs(sanitizeString(params.duration, 32) ?? "")
        : 3000;
  const durationMs = Math.max(
    DURATION_MS_MIN,
    Math.min(typeof durationMsRaw === "number" ? durationMsRaw : 3000, DURATION_MS_MAX),
  );
  const includeAudio = sanitizeBoolean(params.includeAudio, true);
  const deviceId = sanitizeString(params.deviceId, MAX_DEVICE_ID_LENGTH) ?? undefined;
  const raw = await callGatewayTool<{ payload: unknown }>("node.invoke", gatewayOpts, {
    nodeId,
    command: "camera.clip",
    params: {
      facing,
      durationMs,
      includeAudio,
      format: "mp4",
      deviceId,
    },
    idempotencyKey: crypto.randomUUID(),
  });
  const payload = parseCameraClipPayload(raw?.payload);
  const filePath = await writeCameraClipPayloadToFile({
    payload,
    facing,
    expectedHost: resolvedNode.remoteIp,
  });
  return {
    content: [{ type: "text", text: `FILE:${filePath}` }],
    details: {
      facing,
      path: filePath,
      durationMs: payload.durationMs,
      hasAudio: payload.hasAudio,
    },
  };
}

async function executeScreenRecord({
  params,
  gatewayOpts,
}: ExecuteNodeMediaActionParams): Promise<AgentToolResult<unknown>> {
  const node = requireString(params, "node");
  const nodeId = await resolveNodeId(gatewayOpts, node);
  const durationMsRaw =
    typeof params.durationMs === "number" && Number.isFinite(params.durationMs)
      ? params.durationMs
      : typeof params.duration === "string"
        ? parseDurationMs(sanitizeString(params.duration, 32) ?? "")
        : 10_000;
  const durationMs = Math.max(
    DURATION_MS_MIN,
    Math.min(typeof durationMsRaw === "number" ? durationMsRaw : 10_000, DURATION_MS_MAX),
  );
  const fps = sanitizeNumber(params.fps, FPS_MIN, FPS_MAX, 10)!;
  const screenIndex = sanitizeNumber(params.screenIndex, SCREEN_INDEX_MIN, SCREEN_INDEX_MAX, 0)!;
  const includeAudio = sanitizeBoolean(params.includeAudio, true);
  const raw = await callGatewayTool<{ payload: unknown }>("node.invoke", gatewayOpts, {
    nodeId,
    command: "screen.record",
    params: {
      durationMs,
      screenIndex,
      fps,
      format: "mp4",
      includeAudio,
    },
    idempotencyKey: crypto.randomUUID(),
  });
  const payload = parseScreenRecordPayload(raw?.payload);
  const outPathRaw = sanitizeOutPath(params.outPath);
  const filePath =
    outPathRaw !== undefined
      ? outPathRaw
      : screenRecordTempPath({ ext: payload.format || "mp4" });
  const written = await writeScreenRecordToFile(filePath, payload.base64);
  return {
    content: [{ type: "text", text: `FILE:${written.path}` }],
    details: {
      path: written.path,
      durationMs: payload.durationMs,
      fps: payload.fps,
      screenIndex: payload.screenIndex,
      hasAudio: payload.hasAudio,
    },
  };
}

function requireString(params: Record<string, unknown>, key: string): string {
  const raw = params[key];
  if (typeof raw !== "string" || raw.trim().length === 0) {
    throw new Error(`${key} required`);
  }
  const trimmed = raw.trim();
  if (trimmed.length > MAX_STRING_LENGTH) {
    throw new Error(`${key} exceeds maximum allowed length of ${MAX_STRING_LENGTH}`);
  }
  return trimmed;
}

const DEFAULT_PHOTOS_LIMIT = 1;
const MAX_PHOTOS_LIMIT = 20;
const DEFAULT_PHOTOS_MAX_WIDTH = 1600;
const DEFAULT_PHOTOS_QUALITY = 0.85;