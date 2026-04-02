import { inspectMatrixDirectRooms } from "../direct-management.js";
import { isStrictDirectRoom } from "../direct-room.js";
import type { MatrixClient } from "../sdk.js";
import { resolveMatrixMonitorAccessState } from "./access-state.js";
import type { MatrixRawEvent } from "./types.js";
import { EventType } from "./types.js";
import {
  isMatrixVerificationEventType,
  isMatrixVerificationRequestMsgType,
  matrixVerificationConstants,
} from "./verification-utils.js";

const MAX_TRACKED_VERIFICATION_EVENTS = 1024;
const SAS_NOTICE_RETRY_DELAY_MS = 750;
const VERIFICATION_EVENT_STARTUP_GRACE_MS = 30_000;
const MAX_STRING_LENGTH = 2048;
const MAX_NOTICE_BODY_LENGTH = 4096;
const MAX_SENDER_ID_LENGTH = 255;
const MAX_ROOM_ID_LENGTH = 255;
const MAX_FLOW_ID_LENGTH = 255;
const MAX_SAS_EMOJI_COUNT = 8;
const MAX_SAS_EMOJI_STRING_LENGTH = 64;
const MAX_CANCEL_CODE_LENGTH = 128;
const MAX_CANCEL_REASON_LENGTH = 512;

type MatrixVerificationStage = "request" | "ready" | "start" | "cancel" | "done" | "other";

type MatrixVerificationSummaryLike = {
  id: string;
  transactionId?: string;
  roomId?: string;
  otherUserId: string;
  updatedAt?: string;
  completed?: boolean;
  pending?: boolean;
  phase?: number;
  phaseName?: string;
  sas?: {
    decimal?: [number, number, number];
    emoji?: Array<[string, string]>;
  };
};

function trimMaybeString(input: unknown): string | null {
  if (typeof input !== "string") {
    return null;
  }
  const trimmed = input.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function sanitizeString(input: unknown, maxLength: number = MAX_STRING_LENGTH): string | null {
  const trimmed = trimMaybeString(input);
  if (trimmed === null) {
    return null;
  }
  // Remove control characters except for newline (used in multi-line notices)
  const sanitized = trimmed.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
  if (sanitized.length === 0) {
    return null;
  }
  return sanitized.length > maxLength ? sanitized.slice(0, maxLength) : sanitized;
}

function sanitizeSenderId(input: unknown): string | null {
  const value = sanitizeString(input, MAX_SENDER_ID_LENGTH);
  if (value === null) {
    return null;
  }
  // Matrix user IDs must start with @ and contain a colon
  if (!value.startsWith("@") || !value.includes(":")) {
    return null;
  }
  // Only allow printable ASCII characters in user IDs
  if (!/^[@a-zA-Z0-9._=\-/+:]+$/.test(value)) {
    return null;
  }
  return value;
}

function sanitizeRoomId(input: unknown): string | null {
  const value = sanitizeString(input, MAX_ROOM_ID_LENGTH);
  if (value === null) {
    return null;
  }
  // Matrix room IDs must start with ! and contain a colon
  if (!value.startsWith("!") || !value.includes(":")) {
    return null;
  }
  // Only allow printable ASCII characters in room IDs
  if (!/^[!a-zA-Z0-9._=\-/+:]+$/.test(value)) {
    return null;
  }
  return value;
}

function sanitizeFlowId(input: unknown): string | null {
  return sanitizeString(input, MAX_FLOW_ID_LENGTH);
}

function sanitizeEventId(input: unknown): string | null {
  const value = sanitizeString(input, MAX_FLOW_ID_LENGTH);
  if (value === null) {
    return null;
  }
  // Matrix event IDs start with $ or are opaque strings
  return value;
}

function sanitizeNoticeBody(body: string): string {
  // Remove control characters except newline
  const sanitized = body.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
  return sanitized.length > MAX_NOTICE_BODY_LENGTH
    ? sanitized.slice(0, MAX_NOTICE_BODY_LENGTH)
    : sanitized;
}

function readVerificationSignal(event: MatrixRawEvent): {
  stage: MatrixVerificationStage;
  flowId: string | null;
} | null {
  const type = sanitizeString(event?.type) ?? "";
  const content = event?.content ?? {};
  const msgtype = sanitizeString((content as { msgtype?: unknown }).msgtype) ?? "";
  const relatedEventId = sanitizeFlowId(
    (content as { "m.relates_to"?: { event_id?: unknown } })["m.relates_to"]?.event_id,
  );
  const transactionId = sanitizeFlowId((content as { transaction_id?: unknown }).transaction_id);
  if (type === EventType.RoomMessage && isMatrixVerificationRequestMsgType(msgtype)) {
    return {
      stage: "request",
      flowId: sanitizeEventId(event.event_id) ?? transactionId ?? relatedEventId,
    };
  }
  if (!isMatrixVerificationEventType(type)) {
    return null;
  }
  const flowId = transactionId ?? relatedEventId ?? sanitizeEventId(event.event_id);
  if (type === `${matrixVerificationConstants.eventPrefix}request`) {
    return { stage: "request", flowId };
  }
  if (type === `${matrixVerificationConstants.eventPrefix}ready`) {
    return { stage: "ready", flowId };
  }
  if (type === "m.key.verification.start") {
    return { stage: "start", flowId };
  }
  if (type === "m.key.verification.cancel") {
    return { stage: "cancel", flowId };
  }
  if (type === "m.key.verification.done") {
    return { stage: "done", flowId };
  }
  return { stage: "other", flowId };
}

function formatVerificationStageNotice(params: {
  stage: MatrixVerificationStage;
  senderId: string;
  event: MatrixRawEvent;
}): string | null {
  const { stage, senderId, event } = params;
  const sanitizedSenderId = sanitizeSenderId(senderId) ?? sanitizeString(senderId) ?? "unknown";
  const content = event.content as { code?: unknown; reason?: unknown };
  switch (stage) {
    case "request":
      return sanitizeNoticeBody(
        `Matrix verification request received from ${sanitizedSenderId}. Open "Verify by emoji" in your Matrix client to continue.`,
      );
    case "ready":
      return sanitizeNoticeBody(
        `Matrix verification is ready with ${sanitizedSenderId}. Choose "Verify by emoji" to reveal the emoji sequence.`,
      );
    case "start":
      return sanitizeNoticeBody(`Matrix verification started with ${sanitizedSenderId}.`);
    case "done":
      return sanitizeNoticeBody(`Matrix verification completed with ${sanitizedSenderId}.`);
    case "cancel": {
      const code = sanitizeString(content.code, MAX_CANCEL_CODE_LENGTH);
      const reason = sanitizeString(content.reason, MAX_CANCEL_REASON_LENGTH);
      if (code && reason) {
        return sanitizeNoticeBody(
          `Matrix verification cancelled by ${sanitizedSenderId} (${code}: ${reason}).`,
        );
      }
      if (reason) {
        return sanitizeNoticeBody(
          `Matrix verification cancelled by ${sanitizedSenderId} (${reason}).`,
        );
      }
      return sanitizeNoticeBody(`Matrix verification cancelled by ${sanitizedSenderId}.`);
    }
    default:
      return null;
  }
}

function formatVerificationSasNotice(summary: MatrixVerificationSummaryLike): string | null {
  const sas = summary.sas;
  if (!sas) {
    return null;
  }
  const sanitizedOtherUserId =
    sanitizeSenderId(summary.otherUserId) ??
    sanitizeString(summary.otherUserId) ??
    "unknown";
  const emojiLine =
    Array.isArray(sas.emoji) && sas.emoji.length > 0
      ? (() => {
          const limitedEmoji = sas.emoji.slice(0, MAX_SAS_EMOJI_COUNT);
          const validEmoji = limitedEmoji.filter(
            (entry) => Array.isArray(entry) && entry.length === 2,
          );
          if (validEmoji.length === 0) {
            return null;
          }
          return `SAS emoji: ${validEmoji
            .map(([emoji, name]) => {
              const sanitizedEmoji = sanitizeString(emoji, MAX_SAS_EMOJI_STRING_LENGTH) ?? "?";
              const sanitizedName = sanitizeString(name, MAX_SAS_EMOJI_STRING_LENGTH) ?? "?";
              return `${sanitizedEmoji} ${sanitizedName}`;
            })
            .join(" | ")}`;
        })()
      : null;
  const decimalLine =
    Array.isArray(sas.decimal) && sas.decimal.length === 3
      ? (() => {
          const [a, b, c] = sas.decimal;
          if (
            typeof a !== "number" ||
            typeof b !== "number" ||
            typeof c !== "number" ||
            !Number.isFinite(a) ||
            !Number.isFinite(b) ||
            !Number.isFinite(c)
          ) {
            return null;
          }
          return `SAS decimal: ${Math.floor(a)} ${Math.floor(b)} ${Math.floor(c)}`;
        })()
      : null;
  if (!emojiLine && !decimalLine) {
    return null;
  }
  const lines = [`Matrix verification SAS with ${sanitizedOtherUserId}:`];
  if (emojiLine) {
    lines.push(emojiLine);
  }
  if (decimalLine) {
    lines.push(decimalLine);
  }
  lines.push("If both sides match, choose 'They match' in your Matrix app.");
  return sanitizeNoticeBody(lines.join("\n"));
}

function resolveVerificationFlowCandidates(params: {
  event: MatrixRawEvent;
  flowId: string | null;
}): string[] {
  const { event, flowId } = params;
  const content = event.content as {
    transaction_id?: unknown;
    "m.relates_to"?: { event_id?: unknown };
  };
  const candidates = new Set<string>();
  const add = (value: unknown) => {
    const normalized = sanitizeFlowId(value);
    if (normalized) {
      candidates.add(normalized);
    }
  };
  add(flowId);
  add(event.event_id);
  add(content.transaction_id);
  add(content["m.relates_to"]?.event_id);
  return Array.from(candidates);
}

function resolveSummaryRecency(summary: MatrixVerificationSummaryLike): number {
  const ts = Date.parse(summary.updatedAt ?? "");
  return Number.isFinite(ts) ? ts : 0;
}

function isActiveVerificationSummary(summary: MatrixVerificationSummaryLike): boolean {
  if (summary.completed === true) {
    return false;
  }
  if (summary.phaseName === "cancelled" || summary.phaseName === "done") {
    return false;
  }
  if (typeof summary.phase === "number" && summary.phase >= 4) {
    return false;
  }
  return true;
}

async function resolveVerificationSummaryForSignal(
  client: MatrixClient,
  params: {
    roomId: string;
    event: MatrixRawEvent;
    senderId: string;
    flowId: string | null;
  },
): Promise<MatrixVerificationSummaryLike | null> {
  if (!client.crypto) {
    return null;
  }
  const sanitizedRoomId = sanitizeRoomId(params.roomId);
  const sanitizedSenderId = sanitizeSenderId(params.senderId);
  if (!sanitizedRoomId || !sanitizedSenderId) {
    return null;
  }
  await client.crypto
    .ensureVerificationDmTracked({
      roomId: sanitizedRoomId,
      userId: sanitizedSenderId,
    })
    .catch(() => null);
  const list = await client.crypto.listVerifications();
  if (list.length === 0) {
    return null;
  }
  const candidates = resolveVerificationFlowCandidates({
    event: params.event,
    flowId: params.flowId,
  });
  const byTransactionId = list.find((entry) =>
    candidates.some((candidate) => entry.transactionId === candidate),
  );
  if (byTransactionId) {
    return byTransactionId;
  }

  // Only fall back by user inside the active DM with that user. Otherwise a
  // spoofed verification event in an unrelated room can leak the current SAS
  // prompt into that room.
  const inspection = await inspectMatrixDirectRooms({
    client,
    remoteUserId: sanitizedSenderId,
  }).catch(() => null);
  const activeRoomId = sanitizeRoomId(inspection?.activeRoomId);
  if (activeRoomId) {
    if (activeRoomId !== sanitizedRoomId) {
      return null;
    }
  } else if (
    !(await isStrictDirectRoom({
      client,
      roomId: sanitizedRoomId,
      remoteUserId: sanitizedSenderId,
    }))
  ) {
    // If we cannot determine a canonical active DM, preserve the older
    // strict-room fallback so transient m.direct or joined-room read failures
    // do not suppress SAS notices for the current DM.
    return null;
  }

  // Fallback for DM flows where transaction IDs do not match room event IDs consistently.
  const activeByUser = list
    .filter(
      (entry) => entry.otherUserId === sanitizedSenderId && isActiveVerificationSummary(entry),
    )
    .sort((a, b) => resolveSummaryRecency(b) - resolveSummaryRecency(a));
  const activeInRoom = activeByUser.filter((entry) => {
    const roomId = sanitizeRoomId(entry.roomId);
    return roomId === sanitizedRoomId;
  });
  if (activeInRoom.length > 0) {
    return activeInRoom[0] ?? null;
  }
  return activeByUser[0] ?? null;
}

async function resolveVerificationSasNoticeForSignal(
  client: MatrixClient,
  params: {
    roomId: string;
    event: MatrixRawEvent;
    senderId: string;
    flowId: string | null;
    stage: MatrixVerificationStage;
  },
): Promise<{ summary: MatrixVerificationSummaryLike | null; sasNotice: string | null }> {
  const summary = await resolveVerificationSummaryForSignal(client, params);
  const immediateNotice =
    summary && isActiveVerificationSummary(summary) ? formatVerificationSasNotice(summary) : null;
  if (immediateNotice || (params.stage !== "ready" && params.stage !== "start")) {
    return {
      summary,
      sasNotice: immediateNotice,
    };
  }

  await new Promise((resolve) => setTimeout(resolve, SAS_NOTICE_RETRY_DELAY_MS));
  const retriedSummary = await resolveVerificationSummaryForSignal(client, params);
  return {
    summary: retriedSummary,
    sasNotice:
      retriedSummary && isActiveVerificationSummary(retriedSummary)
        ? formatVerificationSasNotice(retriedSummary)
        : null,
  };
}

function trackBounded(set: Set<string>, value: string): boolean {
  if (!value || set.has(value)) {
    return false;
  }
  set.add(value);
  if (set.size > MAX_TRACKED_VERIFICATION_EVENTS) {
    const oldest = set.values().next().value;
    if (typeof oldest === "string") {
      set.delete(oldest);
    }
  }
  return true;
}

async function sendVerificationNotice(params: {
  client: MatrixClient;
  roomId: string;
  body: string;
  logVerboseMessage: (message: string) => void;
}): Promise<void> {
  const roomId = sanitizeRoomId(params.roomId);
  if (!roomId) {
    return;
  }
  const sanitizedBody = sanitizeNoticeBody(params.body);
  if (!sanitizedBody) {
    return;
  }
  try {
    await params.client.sendMessage(roomId, {
      msgtype: "m.notice",
      body: sanitizedBody,
    });
  } catch (err) {
    params.logVerboseMessage(
      `matrix: failed sending verification notice room=${roomId}: ${String(err)}`,
    );
  }
}

async function isVerificationNoticeAuthorized(params: {
  senderId: string;
  allowFrom: string[];
  dmEnabled: boolean;
  dmPolicy: "open" | "pairing" | "allowlist" | "disabled";
  readStoreAllowFrom: () => Promise<string[]>;
  logVerboseMessage: (message: string) => void;
}): Promise<boolean> {
  // Verification notices are DM-only. If DM ingress is disabled, there is no
  // policy-compatible path for posting these notices back into the room.
  if (!params.dmEnabled || params.dmPolicy === "disabled") {
    params.logVerboseMessage(
      `matrix: blocked verification sender ${params.senderId} (dmPolicy=${params.dmPolicy}, dmEnabled=${String(params.dmEnabled)})`,
    );
    return false;
  }
  if (params.dmPolicy === "open") {
    return true;
  }
  const storeAllowFrom = await params.readStoreAllowFrom();
  const accessState = resolveMatrixMonitorAccessState({
    allowFrom: params.allowFrom,
    storeAllowFrom,
    // Verification flows only exist in strict DMs, so room/group allowlists do
    // not participate in the authorization decision here.
    groupAllowFrom: [],
    roomUsers: [],
    senderId: params.senderId,
    isRoom: false,
  });
  if (accessState.directAllowMatch.allowed) {
    return true;
  }
  params.logVerboseMessage(
    `matrix: blocked verification sender ${params.senderId} (dmPolicy=${params.dmPolicy})`,
  );
  return false;
}

export function createMatrixVerificationEventRouter(params: {
  client: MatrixClient;
  allowFrom: string[];
  dmEnabled: boolean;
  dmPolicy: "open" | "pairing" | "allowlist" | "disabled";
  readStoreAllowFrom: () => Promise<string[]>;
  logVerboseMessage: (message: string) => void;
}) {
  const routerStartedAtMs = Date.now();
  const routedVerificationEvents = new Set<string>();
  const routedVerificationSasFingerprints = new Set<string>();
  const routedVerificationStageNotices = new Set<string>();
  const verificationFlowRooms = new Map<string, string>();
  const verificationUserRooms = new Map<string, string>();

  async function resolveActiveDirectRoomId(remoteUserId: string): Promise<string | null> {
    const sanitizedUserId = sanitizeSenderId(remoteUserId);
    if (!sanitizedUserId) {
      return null;
    }
    const inspection = await inspectMatrixDirectRooms({
      client: params.client,
      remoteUserId: sanitizedUserId,
    }).catch(() => null);
    return sanitizeRoomId(inspection?.activeRoomId);
  }

  function shouldEmitVerificationEventNotice(event: MatrixRawEvent): boolean {
    const eventTs =
      typeof event.origin_server_ts === "number" && Number.isFinite(event.origin_server_ts)
        ? event.origin_server_ts
        : null;
    if (eventTs === null) {
      return true;
    }
    return eventTs >= routerStartedAtMs - VERIFICATION_EVENT_STARTUP_GRACE_MS;
  }

  function rememberVerificationRoom(roomId: string, event: MatrixRawEvent, flowId: string | null) {
    const sanitizedRoomId = sanitizeRoomId(roomId);
    if (!sanitizedRoomId) {
      return;
    }
    for (const candidate of resolveVerificationFlowCandidates({ event, flowId })) {
      verificationFlowRooms.set(candidate, sanitizedRoomId);
      if (verificationFlowRooms.size > MAX_TRACKED_VERIFICATION_EVENTS) {
        const oldest = verificationFlowRooms.keys().next().value;
        if (typeof oldest === "string") {
          verificationFlowRooms.delete(oldest);
        }
      }
    }
  }

  function rememberVerificationUserRoom(remoteUserId: string, roomId: string): void {
    const normalizedUserId = sanitizeSenderId(remoteUserId);
    const normalizedRoomId = sanitizeRoomId(roomId);
    if (!normalizedUserId || !normalizedRoomId) {
      return;
    }
    verificationUserRooms.delete(normalizedUserId);
    verificationUserRooms.set(normalizedUserId, normalizedRoomId);
    if (verificationUserRooms.size > MAX_TRACKED_VERIFICATION_EVENTS) {
      const oldest = verificationUserRooms.keys().next().value;
      if (typeof oldest === "string") {
        verificationUserRooms.delete(oldest);
      }
    }
  }

  async function resolveSummaryRoomId(
    summary: MatrixVerificationSummaryLike,
  ): Promise<string | null> {
    const mappedRoomId =
      sanitizeRoomId(summary.roomId) ??
      sanitizeRoomId(
        summary.transactionId ? verificationFlowRooms.get(summary.transactionId) : null,
      ) ??
      sanitizeRoomId(verificationFlowRooms.get(summary.id));
    if (mappedRoomId) {
      return mappedRoomId;
    }

    const remoteUserId = sanitizeSenderId(summary.otherUserId);
    if (!remoteUserId) {
      return null;
    }
    const recentRoomId = sanitizeRoomId(verificationUserRooms.get(remoteUserId));
    const activeRoomId = await resolveActiveDirectRoomId(remoteUserId);
    if (recentRoomId && activeRoomId && recentRoomId === activeRoomId) {
      return recentRoomId;
    }
    if (activeRoomId) {
      return activeRoomId;
    }
    if (
      recentRoomId &&
      (await isStrictDirectRoom({
        client: params.client,
        roomId: recentRoomId,
        remoteUserId,
      }))
    ) {
      return recentRoomId;
    }
    return null;
  }

  async function routeVerificationSummary(summary: MatrixVerificationSummaryLike): Promise<void> {
    const roomId = await resolveSummaryRoomId(summary);
    if (!roomId || !isActiveVerificationSummary(summary)) {
      return;
    }
    const sanitizedOtherUserId = sanitizeSenderId(summary.otherUserId);
    if (!sanitizedOtherUserId) {
      params.logVerboseMessage(
        `matrix: ignoring verification summary with invalid otherUserId room=${roomId}`,
      );
      return;
    }
    if (
      !(await isStrictDirectRoom({
        client: params.client,
        roomId,
        remoteUserId: sanitizedOtherUserId,
      }))
    ) {
      params.logVerboseMessage(
        `matrix: ignoring verification summary outside strict DM room=${roomId} sender=${sanitizedOtherUserId}`,
      );
      return;
    }
    if (
      !(await isVerificationNoticeAuthorized({
        senderId: sanitizedOtherUserId,
        allowFrom: params.allowFrom,
        dmEnabled: params.dmEnabled,
        dmPolicy: params.dmPolicy,
        readStoreAllowFrom: params.readStoreAllowFrom,
        logVerboseMessage: params.logVerboseMessage,
      }))
    ) {
      return;
    }
    const sasNotice = formatVerificationSasNotice(summary);
    if (!sasNotice) {
      return;
    }
    const sasFingerprint = `${sanitizeString(summary.id) ?? ""}:${JSON.stringify(summary.sas)}`;
    if (!trackBounded(routedVerificationSasFingerprints, sasFingerprint)) {
      return;
    }
    await sendVerificationNotice({
      client: params.client,
      roomId,
      body: sasNotice,
      logVerboseMessage: params.logVerboseMessage,
    });
  }

  function routeVerificationEvent(roomId: string, event: MatrixRawEvent): boolean {
    const sanitizedRoomId = sanitizeRoomId(roomId);
    if (!sanitizedRoomId) {
      return false;
    }
    const senderId = sanitizeSenderId(event?.sender);
    if (!senderId) {
      return false;
    }
    const signal = readVerificationSignal(event);
    if (!signal) {
      return false;
    }
    rememberVerificationRoom(sanitizedRoomId, event, signal.flowId);

    void (async () => {
      if (!shouldEmitVerificationEventNotice(event)) {
        params.logVerboseMessage(
          `matrix: ignoring historical verification event room=${sanitizedRoomId} id=${event.event_id ?? "unknown"} type=${event.type ?? "unknown"}`,
        );
        return;
      }
      const flowId = signal.flowId;
      const sourceEventId = sanitizeEventId(event?.event_id);
      const sourceFingerprint =
        sourceEventId ?? `${senderId}:${event.type}:${flowId ?? "none"}`;
      const shouldRouteInRoom = await isStrictDirectRoom({
        client: params.client,
        roomId: sanitizedRoomId,
        remoteUserId: senderId,
      });
      if (!shouldRouteInRoom) {
        params.logVerboseMessage(
          `matrix: ignoring verification event outside strict DM room=${sanitizedRoomId} sender=${senderId}`,
        );
        return;
      }
      if (
        !(await isVerificationNoticeAuthorized({
          senderId,
          allowFrom: params.allowFrom,
          dmEnabled: params.dmEnabled,
          dmPolicy: params.dmPolicy,
          readStoreAllowFrom: params.readStoreAllowFrom,
          logVerboseMessage: params.logVerboseMessage,
        }))
      ) {
        return;
      }
      rememberVerificationUserRoom(senderId, sanitizedRoomId);
      if (!trackBounded(routedVerificationEvents, sourceFingerprint)) {
        return;
      }

      const stageNotice = formatVerificationStageNotice({
        stage: signal.stage,
        senderId,
        event,
      });
      const { summary, sasNotice } = await resolveVerificationSasNoticeForSignal(params.client, {
        roomId: sanitizedRoomId,
        event,
        senderId,
        flowId,
        stage: signal.stage,
      }).catch(() => ({ summary: null, sasNotice: null }));

      const notices: string[] = [];
      if (stageNotice) {
        const stageKey = `${sanitizedRoomId}:${senderId}:${flowId ?? sourceFingerprint}:${signal.stage}`;
        if (trackBounded(routedVerificationStageNotices, stageKey)) {
          notices.push(stageNotice);
        }
      }
      if (summary && sasNotice) {
        const sasFingerprint = `${sanitizeString(summary.id) ?? ""}:${JSON.stringify(summary.sas)}`;
        if (trackBounded(routedVerificationSasFingerprints, sasFingerprint)) {
          notices.push(sasNotice);
        }
      }
      if (notices.length === 0) {
        return;
      }

      for (const body of notices) {
        await sendVerificationNotice({
          client: params.client,
          roomId: sanitizedRoomId,
          body,
          logVerboseMessage: params.logVerboseMessage,
        });
      }
    })().catch((err) => {
      params.logVerboseMessage(`matrix: failed routing verification event: ${String(err)}`);
    });

    return true;
  }

  return {
    routeVerificationEvent,
    routeVerificationSummary,
  };
}